#!/usr/bin/env python3
"""
Stage 3b (LLM + gate): the only part of harness extraction that requires
judgment -- deciding what to strip from the core method (lifecycle guards,
cache, state mutation, secure channel, key selection, logging -- the fixed
categories from skeletons/llm_extraction_prompt.md) and writing the wrapper
that unpacks APDU data into the shape the core expects.

Takes context.json from extract_context.py (the target method's exact
source, its helper-method closure, fields/constants/error codes -- all
gathered deterministically) and makes ONE focused API call asking for a
strict-JSON operation spec.

LLM call settings are copied from tools/candidate_narrowing/llm_final_verdict.py
(itself copied from jcseedgen/generator.py): e-INFRA CZ
/v1/chat/completions endpoint, gpt-oss-120b default model, LLM_API_TOKEN
bearer auth, plain urllib.

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
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

E_INFRA_ENDPOINT = "https://llm.ai.e-infra.cz/v1/chat/completions"
E_INFRA_DEFAULT_MODEL = "gpt-oss-120b"
E_INFRA_TIMEOUT_SECONDS = 120

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
TOP_FIELDS = {
    "operation_name": str,
    "ins_name": str,
    "timing_risk": str,
    "core_method": dict,
    "wrapper_method": dict,
}


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
    """Return None if obj matches the strict schema, else an error string."""
    err = _check_fields(obj, TOP_FIELDS, "response")
    if err:
        return err

    if not obj["ins_name"].startswith("INS_") or not obj["ins_name"].isupper():
        return f"ins_name must look like INS_XXX (all-caps), got {obj['ins_name']!r}"

    core = obj["core_method"]
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

    wrapper = obj["wrapper_method"]
    err = _check_fields(wrapper, WRAPPER_METHOD_FIELDS, "wrapper_method")
    if err:
        return err
    if not wrapper["name"].startswith("wrap"):
        return f"wrapper_method.name must start with 'wrap', got {wrapper['name']!r}"
    if not wrapper["code"].strip():
        return "wrapper_method.code must be non-empty"

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

    hint = ""
    if context.get("verdict_hint"):
        v = context["verdict_hint"]
        hint = (f"\nA prior static/LLM triage pass already flagged this method: "
                f"leak_mechanism={v.get('leak_mechanism')!r}, rationale={v.get('rationale')!r}. "
                f"Use this as a starting hypothesis, not a constraint -- verify against the actual code.\n")

    return f"""\
You are extracting ONE timing-sensitive operation from a Java Card applet
into a wrapper + core method pair for a differential-fuzzing harness. The
operation to extract has already been chosen (this is not your job) --
you only need to do the core/wrapper split for the method below.
{hint}
=== Target method (line-numbered; line numbers are relative to THIS listing) ===
Class: {target['class']}
Method: {target['method']}
{numbered_source}

=== Internal helper methods this method calls (context only -- do not extract these, they are copied into the harness package verbatim) ===
{helpers_block}

=== Non-local instance fields this method (or its helpers) touch, with how the original constructor initializes them ===
{fields_block}

=== Constants available (paste verbatim if the core references them) ===
{constants_block}

=== Error codes available ===
{error_codes_block}

=== Task ===
Produce a core method (verbatim-minus-removals copy of the target method's
BODY) and a brand-new wrapper method, following these rules:

CORE METHOD:
- Keep ALL timing-sensitive logic verbatim: crypto API calls, comparisons/
  validations on secret data, branches/loops depending on secret data,
  array accesses indexed by secret data, error throws that are part of the
  secret-dependent logic.
- You MAY remove lines only in these categories, and EVERY removal must be
  declared in removed_lines: {REMOVAL_CATEGORIES}
  ("lifecycle guard" = init/setup checks; "cache" = persistent lookup/
  store; "state mutation" = persistent counters/flags unrelated to timing;
  "secure channel" = APDU encryption/decryption wrapping; "key selection"
  = choosing among multiple stored keys by id, replaced by the wrapper
  loading the one correct key; "logging" = audit/log writes.)
- Do NOT reformat, rename variables, or "clean up" anything else. Every
  line you don't declare as removed must appear in core_method.code
  EXACTLY as in the target method listing above (this is mechanically
  verified -- an undeclared change will be rejected).
- Name it coreXxx (CamelCase Xxx derived from the operation).
- field_mapping: list the exact original field names the core references.
- precondition: what the wrapper must set up before calling this core (or
  "" if nothing beyond normal parameters).

WRAPPER METHOD:
- Entirely new code (nothing copied from the original). Reads P1/P2/CDATA
  from `buffer` (a `byte[]`), validates sizes, loads any secret/public data
  the core needs into the fields/buffers listed above (or into local
  variables/parameters passed to the core), calls the core, formats the
  result into `buffer[0..]`, returns the output size as `short`.
- Signature: `private short wrapXxx(APDU apdu, byte[] buffer)`.
- Name it wrapXxx to match the core's Xxx.
- data_layout_comment: one line describing the per-input-set data layout,
  e.g. "p1=pin_length | p2=0x00 | reference_pin(8) | guess_pin(8)". Every
  piece of data the original method read from persistent/instance state
  (keys, PINs, seeds, config) must appear here as explicit input -- nothing
  implicit, since the fuzzer must control it.

Respond with STRICT JSON ONLY (no prose, no markdown fences), matching
exactly this shape:
{{
  "operation_name": "VerifyPin",
  "ins_name": "INS_VERIFY_PIN",
  "timing_risk": "one-sentence description of the specific timing-vulnerable construct",
  "core_method": {{
    "name": "coreVerifyPin",
    "code": "full java method source, verbatim-minus-declared-removals",
    "removed_lines": [{{"start_line": 1, "end_line": 2, "category": "lifecycle guard", "description": "..."}}],
    "field_mapping": ["referencePin"],
    "precondition": "referencePin loaded by wrapper before calling"
  }},
  "wrapper_method": {{
    "name": "wrapVerifyPin",
    "code": "full java method source",
    "data_layout_comment": "p1=... | p2=... | field(size) | ..."
  }}
}}"""


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
    wrapper_name = f"wrap{op_name}"
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

    return json.dumps({
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
        E_INFRA_ENDPOINT,
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

        diff = fidelity_diff(target_source, obj["core_method"]["removed_lines"], obj["core_method"]["code"])
        if diff is not None:
            last_error = f"fidelity check failed -- core_method.code differs from the original beyond declared removed_lines:\n{diff}"
            log.warning("attempt %d: fidelity check failed", attempt + 1)
            continue

        return obj, attempt + 1, None

    return None, retries + 1, last_error


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("context_json", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=Path("operation.json"))
    ap.add_argument("--errors-output", type=Path, default=Path("operation_errors.json"))
    ap.add_argument("--model", default=E_INFRA_DEFAULT_MODEL)
    ap.add_argument("--api-token", default=None, help="falls back to LLM_API_TOKEN env var")
    ap.add_argument("--timeout", type=float, default=E_INFRA_TIMEOUT_SECONDS)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--mock", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                         format="%(levelname)s %(message)s")

    api_token = args.api_token or os.environ.get("LLM_API_TOKEN")
    if not args.mock and not api_token:
        print("error: LLM_API_TOKEN not set and --api-token not passed (use --mock to test without the API)",
              file=sys.stderr)
        sys.exit(1)

    context = json.loads(args.context_json.read_text(encoding="utf-8"))

    obj, attempts, err = get_operation(context, args.model, api_token, args.timeout, args.retries, args.mock)

    if obj is None:
        print(f"FAIL: gave up after {attempts} attempt(s): {err}", file=sys.stderr)
        args.errors_output.write_text(json.dumps({"attempts": attempts, "error": err}, indent=2), encoding="utf-8")
        sys.exit(1)

    print(f"OK ({attempts} attempt(s)): {obj['operation_name']} -> "
          f"{obj['core_method']['name']} / {obj['wrapper_method']['name']}", file=sys.stderr)
    args.output.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
