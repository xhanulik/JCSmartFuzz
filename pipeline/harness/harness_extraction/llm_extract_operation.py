#!/usr/bin/env python3
"""
Stage 3b (LLM + gate): the only part of harness extraction that requires
judgment. It picks one of two harness modes and produces the code for it:

  - "inline-core": copy the target method body verbatim-minus-removals into the
    fuzzing applet as coreXxx() and write a wrapper that unpacks the APDU and
    calls it. For applet-level entry methods with removable APDU/secure-channel/
    lifecycle setup. The removals are the fixed categories (lifecycle guard,
    cache, state mutation, secure channel, key selection, logging) and are
    fidelity-checked against the original body.
  - "invoke-instance": copy NOTHING. The wrapper constructs a real receiver (and
    argument objects) via the class's real public constructors (from
    context.json's construction_api), calls the real method on it, and
    serializes the result. For instance methods of normal (non-applet) classes
    whose body relies on this/private state and so cannot be lifted into the
    applet (JCMathLib's BigNat/Integer/ECPoint operations). core_method is null
    and the fidelity check does not apply.

Takes context.json from extract_context.py (the target method's exact
source, its helper-method closure, fields/constants/error codes -- all
gathered deterministically) and makes ONE focused API call asking for a
strict-JSON operation spec.

The LLM backend (endpoint, model, timeout, token) is resolved through the
shared pipeline.llm_config loader -- environment variable > llm_config.ini >
built-in default -- the same as every other LLM-calling stage. Plain urllib,
no extra HTTP dependency.

Gate (two layers, both must pass or the call is re-queried with the
specific error appended, up to --retries times; on exhaustion the run
fails with the error printed rather than emitting a fabricated result):
  1. JSON-schema validation (types, required fields, the fixed
     ALLOWED REMOVALS category enum).
  2. Fidelity diff: reconstructs the target method's original body
     (context.json already has it verbatim from ast_symtab) with the
     LLM's OWN declared removed_lines stripped out, and diffs it against
     core_method.code. Any undeclared difference fails the gate -- this
     automates the manual verification step the original prompt calls
     for ("diff each core method body against the original source...
     Only ALLOWED REMOVALS may differ") instead of leaving it to a human.

Each/each model: one operation per method. context.json matches whatever
extract_context.py wrote to it:
  - a single context object (from --method) -> operation.json is a single object.
  - a JSON list of per-method contexts (from --verdicts, several methods) ->
    operation.json is a JSON list, one operation per element, each tagged with
    its {class, method} target so the assemble step can pair them back up.
A method that fails the gate is recorded in operation_errors.json and does not
abort the rest of the list.

Usage:
    export LLM_API_TOKEN=...
    py llm_extract_operation.py context.json -o operation.json

    # exercise the schema/fidelity gate without network access or a token:
    py llm_extract_operation.py context.json -o operation.json --mock
"""
import argparse
import difflib
import json
import logging
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# LLM backend settings (endpoint/model/timeout/token) are resolved through the
# shared pipeline config loader -- env var > llm_config.ini > default -- so no
# provider specifics are hardcoded here.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import llm_config

# ---------------------------------------------------------------------------
# Prompt templates live in prompts/ as editable text files (with {{marker}}
# placeholders) so the wording can be tuned without touching this code.
# ---------------------------------------------------------------------------
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt(name):
    """Read a prompt template from prompts/<name>."""
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def render_prompt(template, **values):
    """Substitute every {{name}} marker in *template* from *values* in a single
    pass (inserted values are never re-scanned for further markers). Raises
    KeyError if the template references a marker that was not supplied."""
    return re.sub(r"{{\s*(\w+)\s*}}", lambda m: str(values[m.group(1)]), template)

log = logging.getLogger(__name__)

REMOVAL_CATEGORIES = [
    "lifecycle guard",
    "cache",
    "state mutation",
    "secure channel",
    "key selection",
    "logging",
]

REMOVED_LINE_FIELDS = {
    "start_line": int,
    "end_line": int,
    "category": str,
    "description": str,
}
CORE_METHOD_FIELDS = {
    "name": str,
    "code": str,
    "removed_lines": list,
    "field_mapping": list,
    "precondition": str,
}
WRAPPER_METHOD_FIELDS = {
    "name": str,
    "code": str,
    "data_layout_comment": str,
}
# The wrapper's signature is fixed: the skeleton's process() calls
# `wrapOperation(apdu, buffer)`, so the declaration must take (APDU, byte[]) in
# that order (parameter names are free). Anything else fails to compile.
WRAPPER_SIG_RE = re.compile(r"wrapOperation\s*\(\s*APDU\s+\w+\s*,\s*byte\s*\[\s*\]\s+\w+\s*\)")

TOP_STR_FIELDS = ("operation_name", "ins_name", "timing_risk")
TOP_FIELDS = {"mode", "operation_name", "ins_name", "timing_risk", "core_method", "wrapper_method"}
MODES = ("inline-core", "invoke-instance")


def _check_fields(obj, spec, label):
    if not isinstance(obj, dict):
        return f"{label} is not a JSON object"
    extra = set(obj) - set(spec)
    if extra:
        return f"{label} has unexpected extra field(s): {sorted(extra)}"
    missing = set(spec) - set(obj)
    if missing:
        return f"{label} is missing required field(s): {sorted(missing)}"
    for field, expected_type in spec.items():
        if not isinstance(obj[field], expected_type) or isinstance(obj[field], bool):
            return f"{label}.{field} has wrong type (expected {expected_type.__name__})"
    return None


def validate_operation(obj):
    """Return None if obj matches the strict schema for its mode, else an error string.

    Both modes share the top-level fields and the wrapper (named `wrapOperation`).
    They differ in core_method: inline-core carries the verbatim-minus-removals
    core object (fidelity-checked later); invoke-instance sets it to null (the
    wrapper calls the real method on a constructed object, so nothing is copied)."""
    if not isinstance(obj, dict):
        return "response is not a JSON object"
    extra = set(obj) - TOP_FIELDS
    if extra:
        return f"response has unexpected extra field(s): {sorted(extra)}"
    missing = TOP_FIELDS - set(obj)
    if missing:
        return f"response is missing required field(s): {sorted(missing)}"
    if obj["mode"] not in MODES:
        return f"mode must be one of {list(MODES)}, got {obj['mode']!r}"
    for f in TOP_STR_FIELDS:
        if not isinstance(obj[f], str):
            return f"{f} must be a string"
    if not obj["ins_name"].startswith("INS_") or not obj["ins_name"].isupper():
        return f"ins_name must look like INS_XXX (all-caps), got {obj['ins_name']!r}"

    wrapper = obj["wrapper_method"]
    err = _check_fields(wrapper, WRAPPER_METHOD_FIELDS, "wrapper_method")
    if err:
        return err
    if wrapper["name"] != "wrapOperation":
        return (f"wrapper_method.name must be exactly 'wrapOperation' (the fixed name the "
                f"harness process() calls; there is no INS dispatch), got {wrapper['name']!r}")
    if not wrapper["code"].strip():
        return "wrapper_method.code must be non-empty"
    if not WRAPPER_SIG_RE.search(wrapper["code"]):
        return ("wrapper_method.code must declare exactly "
                "`private short wrapOperation(APDU apdu, byte[] buffer)` -- that is the signature "
                "the harness process() calls (parameter names may vary, types/order may not); "
                "read P1/P2/CDATA from the `byte[]` buffer inside, do not change the parameters")

    core = obj["core_method"]
    if obj["mode"] == "invoke-instance":
        if core is not None:
            return "core_method must be null in invoke-instance mode (the real method is called, not copied)"
        return None

    # inline-core: core_method is a verbatim-minus-removals copy.
    err = _check_fields(core, CORE_METHOD_FIELDS, "core_method")
    if err:
        return err
    if not core["name"].startswith("core"):
        return f"core_method.name must start with 'core', got {core['name']!r}"
    if not core["code"].strip():
        return "core_method.code must be non-empty"
    for i, r in enumerate(core["removed_lines"]):
        err = _check_fields(r, REMOVED_LINE_FIELDS, f"core_method.removed_lines[{i}]")
        if err:
            return err
        if r["category"] not in REMOVAL_CATEGORIES:
            return f"core_method.removed_lines[{i}].category must be one of {REMOVAL_CATEGORIES}, got {r['category']!r}"
        if r["start_line"] > r["end_line"] or r["start_line"] < 1:
            return f"core_method.removed_lines[{i}] has an invalid line range {r['start_line']}-{r['end_line']}"
    if not all(isinstance(f, str) for f in core["field_mapping"]):
        return "core_method.field_mapping must be a list of strings"

    return None


def fidelity_diff(original_source, removed_lines, core_code):
    """Reconstruct the original method's body (minus the LLM's own declared
    removals) and diff it against core_method.code's body. Both are reduced to
    "interior lines" (excluding the signature line and the final closing
    brace, since the core legitimately gets a new name/signature) and
    whitespace-stripped before comparison. Returns None if they match, else a
    unified-diff string to feed back to the model."""
    orig_lines = original_source.splitlines()
    n = len(orig_lines)
    removed_idx = set()
    for r in removed_lines:
        removed_idx.update(range(r["start_line"], r["end_line"] + 1))

    expected = [
        orig_lines[i - 1].strip()
        for i in range(2, n)  # interior lines only: exclude signature (1) and closing brace (n)
        if i not in removed_idx and orig_lines[i - 1].strip()
    ]

    core_lines = core_code.splitlines()
    actual = [l.strip() for l in core_lines[1:-1] if l.strip()] if len(core_lines) > 2 else []

    if expected == actual:
        return None
    diff = list(difflib.unified_diff(
        expected, actual, lineterm="",
        fromfile="expected(original method body minus your declared removed_lines)",
        tofile="actual(your core_method.code body)"))
    return "\n".join(diff[:60])


def extract_json(text):
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("no JSON object found in response")
    return json.loads(text[start:end + 1])


def op_summary(obj):
    """One-line 'what was produced' for logs, tolerant of a null core_method."""
    core = obj.get("core_method")
    produced = f"{core['name']} / wrapOperation" if core else "wrapOperation (invoke-instance, real method)"
    return f"[{obj['mode']}] {obj['operation_name']} -> {produced}"


def render_construction_api(api):
    """Render context.json's construction_api (public ctor + method signatures per
    class) into the prompt block the invoke-instance wrapper builds against."""
    if not api:
        return "  (none -- inline-core targets don't need this)"
    blocks = []
    for cls, info in api.items():
        lines = [f"class {cls} (package {info.get('package') or '(default)'}):"]
        for c in info.get("constructors", []):
            lines.append(f"    ctor:   {c}")
        for m in info.get("methods", []):
            lines.append(f"    method: {m}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def build_prompt(context):
    target = context["target"]
    helpers_block = "\n\n".join(
        f"--- {h['class']}.{h['method']}({', '.join(p['type'] for p in h['params'])}) ---\n{h['source']}"
        for h in context["helpers"]
    ) or "(no internal helper methods)"

    numbered_source = "\n".join(
        f"{i + 1:4d}: {line}" for i, line in enumerate(target["source"].splitlines())
    )

    fields_block = "\n".join(
        f"  - {f['name']} ({f['declaration'].strip()}) -- init: {f['init_line'] or '(not found; document if the wrapper must set it up)'}"
        for f in context["fields"]
    ) or "  (none)"
    constants_block = "\n".join(f"  - {c['declaration'].strip()}" for c in context["constants"]) or "  (none)"
    error_codes_block = "\n".join(f"  - {e['declaration'].strip()}" for e in context["error_codes"]) or "  (none)"
    construction_api_block = render_construction_api(context.get("construction_api", {}))

    hint = ""
    if context.get("verdict_hint"):
        v = context["verdict_hint"]
        hint = (f"\nA prior static/LLM triage pass already flagged this method: "
                f"leak_mechanism={v.get('leak_mechanism')!r}, rationale={v.get('rationale')!r}. "
                f"Use this as a starting hypothesis, not a constraint -- verify against the actual code.\n")

    return render_prompt(
        load_prompt("extract_operation.md"),
        hint=hint,
        target_class=target["class"],
        target_method=target["method"],
        numbered_source=numbered_source,
        helpers_block=helpers_block,
        fields_block=fields_block,
        constants_block=constants_block,
        error_codes_block=error_codes_block,
        construction_api_block=construction_api_block,
        suggested_mode=context.get("suggested_mode", "inline-core"),
        removal_categories=REMOVAL_CATEGORIES,
    )


def mock_llm(prompt, attempt, context):
    """Deterministic canned response for exercising the gate without network
    access or an API token. Attempt 0 always returns a version that silently
    drops the lifecycle-guard lines WITHOUT declaring them in removed_lines,
    so --mock demonstrates the fidelity-diff gate rejecting it; attempt 1+
    returns the properly-declared version so the retry recovers."""
    target = context["target"]
    lines = target["source"].splitlines()
    op_name = target["method"][0].upper() + target["method"][1:]
    core_name = f"core{op_name}"
    wrapper_name = "wrapOperation"  # fixed name; the harness process() calls it (no INS dispatch)
    ins_name = f"INS_{target['method'].upper()}"

    # fixture's target method has the lifecycle guard on (1-indexed) lines 2-4:
    #   1: signature   2: if (!initialized) {   3: throwIt(...)   4: }
    # the new signature line is free to differ from the original -- the
    # fidelity check only compares interior lines (see fidelity_diff()).
    new_signature = f"    private boolean {core_name}(byte[] buffer, short offset, byte len) {{"
    body_minus_guard = [new_signature] + lines[4:]

    if attempt == 0:
        # drop the guard but don't declare it -- must fail the fidelity gate
        core_code = "\n".join(body_minus_guard)
        removed_lines = []
    else:
        # same code, properly declared this time -- must pass
        core_code = "\n".join(body_minus_guard)
        removed_lines = [{"start_line": 2, "end_line": 4, "category": "lifecycle guard",
                           "description": "initialization guard, not timing-relevant"}]

    # The mock only exercises the inline-core path (the fixture is an applet
    # method). invoke-instance wrappers are class-specific and not mocked.
    return json.dumps({
        "mode": "inline-core",
        "operation_name": op_name,
        "ins_name": ins_name,
        "timing_risk": "[mock] early-exit comparison on secret data",
        "core_method": {
            "name": core_name,
            "code": core_code,
            "removed_lines": removed_lines,
            "field_mapping": [f["name"] for f in context["fields"]],
            "precondition": "[mock] fields loaded by wrapper before calling",
        },
        "wrapper_method": {
            "name": wrapper_name,
            "code": f"private short {wrapper_name}(APDU apdu, byte[] buffer) {{\n"
                    f"    byte pinLen = buffer[ISO7816.OFFSET_P1];\n"
                    f"    boolean ok = {core_name}(buffer, ISO7816.OFFSET_CDATA, pinLen);\n"
                    f"    buffer[0] = ok ? (byte) 1 : (byte) 0;\n"
                    f"    return (short) 1;\n}}",
            "data_layout_comment": "p1=pin_length | p2=0x00 | guess_pin(pin_length)",
        },
    })


def call_llm(prompt, model, api_token, timeout):
    if not api_token:
        raise RuntimeError("LLM_API_TOKEN is not set. Export the env var or pass --api-token.")

    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        llm_config.endpoint(),
        data=body,
        headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"LLM API HTTP {e.code} {e.reason}: {e.read().decode('utf-8', errors='replace')}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"LLM API network error: {e.reason}") from e
    except TimeoutError as e:
        raise RuntimeError(f"LLM API timed out after {timeout}s") from e

    choices = payload.get("choices") or []
    if not choices:
        raise RuntimeError(f"LLM API returned no choices: {payload!r}")
    return choices[0]["message"]["content"]


def get_operation(context, model, api_token, timeout, retries, mock):
    prompt = build_prompt(context)
    target_source = context["target"]["source"]

    last_error = None
    for attempt in range(retries + 1):
        query = prompt if last_error is None else (
            prompt + f"\n\n=== Your previous response was INVALID ===\n"
            f"Error:\n{last_error}\n\nRespond again with STRICT JSON ONLY, "
            f"fixing this specific issue. No prose, no markdown fences."
        )
        try:
            reply = mock_llm(query, attempt, context) if mock else call_llm(query, model, api_token, timeout)
        except RuntimeError as e:
            last_error = str(e)
            log.warning("LLM call failed (attempt %d): %s", attempt + 1, e)
            continue

        try:
            obj = extract_json(reply)
        except (ValueError, json.JSONDecodeError) as e:
            last_error = f"could not parse JSON: {e}"
            log.warning("malformed response (attempt %d): %s", attempt + 1, last_error)
            continue

        err = validate_operation(obj)
        if err is not None:
            last_error = f"schema validation failed: {err}"
            log.warning("attempt %d: %s", attempt + 1, last_error)
            continue

        # Fidelity diff applies only to inline-core (a verbatim body copy).
        # invoke-instance copies nothing -- it calls the real method -- so there
        # is no body to diff.
        if obj["mode"] == "inline-core":
            diff = fidelity_diff(target_source, obj["core_method"]["removed_lines"], obj["core_method"]["code"])
            if diff is not None:
                last_error = f"fidelity check failed -- core_method.code differs from the original beyond declared removed_lines:\n{diff}"
                log.warning("attempt %d: fidelity check failed", attempt + 1)
                continue

        return obj, attempt + 1, None

    return None, retries + 1, last_error


def compact_target(context):
    """{'class', 'method'} identity of a context object -- enough for the
    assemble step to pair an operation back to its context list element, without
    duplicating the full target source into operation.json."""
    t = context.get("target", {})
    return {"class": t.get("class"), "method": t.get("method")}


def target_label(context):
    """'Class.method' identifier for a context object (for logs)."""
    t = compact_target(context)
    return f"{t['class']}.{t['method']}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("context_json", type=Path,
                    help="context.json from extract_context.py: a single context object "
                         "(--method) or a JSON list of per-method contexts (--verdicts)")
    ap.add_argument("-o", "--output", type=Path, default=Path("operation.json"),
                    help="operation.json; a single object for a single context, or a JSON list "
                         "(one tagged operation per method) for a list context")
    ap.add_argument("--errors-output", type=Path, default=Path("operation_errors.json"))
    ap.add_argument("--model", default=None, help="overrides the model from env/llm_config.ini")
    ap.add_argument("--api-token", default=None, help="falls back to LLM_API_TOKEN env var / llm_config.ini")
    ap.add_argument("--timeout", type=float, default=None, help="overrides the timeout from env/llm_config.ini")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                         format="%(levelname)s %(message)s")

    api_token = args.api_token or llm_config.api_token()
    if not args.mock and not api_token:
        print("error: no API token (set LLM_API_TOKEN, pass --api-token, or set it in llm_config.ini; use --mock to test without the API)",
              file=sys.stderr)
        sys.exit(1)

    # Resolve the backend once (env var > llm_config.ini > default); model/timeout
    # are unused in --mock mode so we don't require config there.
    if args.mock:
        model, timeout = args.model, args.timeout
    else:
        model = args.model or llm_config.model()
        timeout = args.timeout if args.timeout is not None else llm_config.timeout()

    data = json.loads(args.context_json.read_text(encoding="utf-8"))

    # A single context object (from --method) -> a single operation object, as
    # before. A list of contexts (from --verdicts, several methods) -> a list of
    # operations, each tagged with its target so the assemble step can pair them.
    if isinstance(data, dict):
        obj, attempts, err = get_operation(data, model, api_token, timeout, args.retries, args.mock)
        if obj is None:
            print(f"FAIL: gave up after {attempts} attempt(s): {err}", file=sys.stderr)
            args.errors_output.write_text(json.dumps({"attempts": attempts, "error": err}, indent=2), encoding="utf-8")
            sys.exit(1)
        print(f"OK ({attempts} attempt(s)): {op_summary(obj)}", file=sys.stderr)
        args.output.write_text(json.dumps(obj, indent=2), encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
        return

    print(f"{len(data)} method context(s) in {args.context_json}", file=sys.stderr)
    operations, errors = [], []
    for context in data:
        label = target_label(context)
        obj, attempts, err = get_operation(context, model, api_token, timeout, args.retries, args.mock)
        if obj is None:
            print(f"FAIL {label}: gave up after {attempts} attempt(s): {err}", file=sys.stderr)
            errors.append({"target": compact_target(context), "attempts": attempts, "error": err})
            continue
        print(f"OK {label} ({attempts} attempt(s)): {op_summary(obj)}", file=sys.stderr)
        # Tag each operation with its target {class, method} so assemble_harness
        # can match it to the right context list element.
        operations.append({"target": compact_target(context), **obj})

    args.output.write_text(json.dumps(operations, indent=2), encoding="utf-8")
    if errors:
        args.errors_output.write_text(json.dumps(errors, indent=2), encoding="utf-8")
    print(f"\n{len(operations)}/{len(data)} operation(s) -> {args.output}"
          + (f"; {len(errors)} failed -> {args.errors_output}" if errors else ""),
          file=sys.stderr)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
