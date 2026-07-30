#!/usr/bin/env python3
"""
For every candidate, makes one focused API call: method source +
immediate context (its direct, internally-resolved callees) + the rule(s)
that fired (if any), and asks for a strict-JSON structured verdict:

    {
      "is_custom_crypto": bool,
      "is_security_relevant": bool,
      "leak_mechanism": one of LEAK_MECHANISMS,
      "severity": float in [0, 1],
      "confidence": float in [0, 1],
      "rationale": string
    }

Gate: the response is parsed and validated against this schema. A
malformed response is re-queried (with the validation error fed back to
the model) up to --retries times; if it still doesn't validate, the
candidate is dropped from verdicts.jsonl and recorded in errors.jsonl
instead (never silently discarded -- see the final summary line).

The LLM backend (endpoint, model, timeout, token) is resolved through the
shared pipeline.llm_config loader -- environment variable > llm_config.ini >
built-in default -- the same as every other LLM-calling stage. Calls go to an
OpenAI-compatible /v1/chat/completions endpoint using stdlib urllib only (no
extra HTTP dependency).

Usage:
    export LLM_API_TOKEN=...
    py llm_final_verdict.py methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl

    # skip stage 1 entirely -- verdict every extracted method directly:
    py llm_final_verdict.py methods.jsonl -o verdicts.jsonl

    # exercise the schema/retry gate without any network access or token:
    py llm_final_verdict.py methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl --mock
"""
import argparse
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

log = logging.getLogger(__name__)

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

LEAK_MECHANISMS = [
    "timing-early-return-compare",
    "timing-secret-length-loop",
    "timing-branch-on-secret",
    "custom-crypto-primitive",
    "none",
    "other",
]

SCHEMA_FIELDS = {
    "is_custom_crypto": bool,
    "is_security_relevant": bool,
    "leak_mechanism": str,
    "severity": (int, float),
    "confidence": (int, float),
    "rationale": str,
}
REQUIRED_FIELDS = set(SCHEMA_FIELDS)


def validate_verdict(obj):
    """Return None if obj matches the strict schema, else an error string."""
    if not isinstance(obj, dict):
        return "response is not a JSON object"
    extra = set(obj) - REQUIRED_FIELDS
    if extra:
        return f"unexpected extra field(s): {sorted(extra)}"
    missing = REQUIRED_FIELDS - set(obj)
    if missing:
        return f"missing required field(s): {sorted(missing)}"
    for field, expected_type in SCHEMA_FIELDS.items():
        if not isinstance(obj[field], expected_type) or isinstance(obj[field], bool) != (expected_type is bool):
            return f"field '{field}' has wrong type (expected {expected_type})"
    if obj["leak_mechanism"] not in LEAK_MECHANISMS:
        return f"leak_mechanism must be one of {LEAK_MECHANISMS}, got {obj['leak_mechanism']!r}"
    if not (0.0 <= float(obj["severity"]) <= 1.0):
        return "severity must be in [0, 1]"
    if not (0.0 <= float(obj["confidence"]) <= 1.0):
        return "confidence must be in [0, 1]"
    if not obj["rationale"].strip():
        return "rationale must be non-empty"
    return None


def extract_json(text):
    """Best-effort extraction of a JSON object from a possibly-fenced/prose reply."""
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


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build_all_candidates(methods):
    """Treat every extracted method as a candidate directly, bypassing stage 1
    (prefilter_rank_candidates.py). Used when --candidates is omitted."""
    return [
        {
            "file": rec["file"],
            "class": rec["class"],
            "method": rec["method"],
            "score": None,
            "fired_rules": [],
            "rank": i,
        }
        for i, rec in enumerate(methods, 1)
    ]


def build_method_index(methods):
    index = {}
    for rec in methods:
        index.setdefault((rec["class"], rec["method"]), rec)
    return index


def build_immediate_context(rec, method_index, max_callees=5):
    """Direct, internally-resolved callees' signatures (+ short source if short
    enough) -- the 'immediate context' the prompt asks the model to consider
    alongside the candidate method itself."""
    seen = []
    for c in rec["calls"]:
        if c["external"] or c["resolved_owner"] is None:
            continue
        key = (c["resolved_owner"], c["method"])
        if key in seen:
            continue
        seen.append(key)
        if len(seen) >= max_callees:
            break

    blocks = []
    for cls, name in seen:
        callee = method_index.get((cls, name))
        if callee is None:
            continue
        blocks.append(f"--- {cls}.{name} ---\n{callee['source']}")
    return "\n\n".join(blocks) if blocks else "(no internal callees)"


def build_prompt(candidate, rec, context):
    fired_rules = candidate.get("fired_rules") or []
    fired = "\n".join(
        f"  - {r['rule_id']} (source={r['source']}, weight={r['weight']}, lines={r['lines']})"
        for r in fired_rules
    ) or "  (none -- reviewing directly from extraction; no static pre-filter was run)"
    field_dataflow = "\n".join(
        f"  - {f['field']} ({f['type']}, owner={f['owner_class']}): "
        f"{f['classification']} (reads={f['reads']}, writes={f['writes']})"
        for f in rec.get("field_dataflow", [])
    ) or "  (none)"

    schema_block = json.dumps({
        "is_custom_crypto": "boolean",
        "is_security_relevant": "boolean",
        "leak_mechanism": f"one of {LEAK_MECHANISMS}",
        "severity": "number in [0, 1]",
        "confidence": "number in [0, 1]",
        "rationale": "short string explaining the verdict",
    }, indent=2)

    prefilter_phrase = (
        " flagged by a deterministic static pre-filter" if fired_rules else
        " (reviewed directly, no static pre-filter stage was run)"
    )

    return render_prompt(
        load_prompt("verdict.md"),
        prefilter_phrase=prefilter_phrase,
        **{"class": rec["class"]},
        method=rec["method"],
        file=rec["file"],
        source=rec["source"],
        field_dataflow=field_dataflow,
        context=context,
        fired=fired,
        leak_mechanisms=LEAK_MECHANISMS,
        schema_block=schema_block,
    )


def mock_llm(prompt, attempt, candidate):
    """Deterministic canned response for exercising the gate without network
    access or an API token. Every 3rd call across the whole run returns a
    deliberately malformed payload so --mock also demonstrates the
    retry-then-drop path end to end."""
    mock_llm.counter = getattr(mock_llm, "counter", 0) + 1
    if mock_llm.counter % 3 == 0 and attempt == 0:
        return "sure, here you go: {\"is_custom_crypto\": true, \"confidence\": \"high\"}"
    fired_ids = {r["rule_id"] for r in (candidate.get("fired_rules") or [])}
    is_dataflow = any(r.startswith("dataflow-") for r in fired_ids)
    return json.dumps({
        "is_custom_crypto": "custom-xor-loop" in fired_ids or "custom-bit-rotate" in fired_ids,
        "is_security_relevant": is_dataflow or "early-return-array-compare" in fired_ids,
        "leak_mechanism": (
            "timing-early-return-compare" if "early-return-array-compare" in fired_ids else
            "timing-secret-length-loop" if "dataflow-secret-length-loop" in fired_ids or "secret-length-loop-bound" in fired_ids else
            "timing-branch-on-secret" if is_dataflow or "branch-on-secret-value" in fired_ids else
            "custom-crypto-primitive" if "custom-xor-loop" in fired_ids or "custom-bit-rotate" in fired_ids else
            "none"
        ),
        "severity": 0.5,
        "confidence": 0.7,
        "rationale": "[mock] verdict derived from fired rule ids for pipeline smoke-testing.",
    })


def call_llm(prompt, model, api_token, timeout):
    if not api_token:
        raise RuntimeError(
            "LLM_API_TOKEN is not set. Export the env var or pass --api-token.")

    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        llm_config.endpoint(),
        data=body,
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"LLM API HTTP {e.code} {e.reason}: {err_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"LLM API network error: {e.reason}") from e
    except TimeoutError as e:
        raise RuntimeError(f"LLM API timed out after {timeout}s") from e

    choices = payload.get("choices") or []
    if not choices:
        raise RuntimeError(f"LLM API returned no choices: {payload!r}")
    return choices[0]["message"]["content"]


def list_models(api_token, timeout):
    """Print the model ids the API endpoint offers (same endpoint used for
    verdicts, so the list reflects what --model may be set to)."""
    models_url = llm_config.endpoint().replace("/chat/completions", "/models")
    req = urllib.request.Request(models_url, headers={"Authorization": f"Bearer {api_token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"error: could not fetch models from {models_url}: {exc}", file=sys.stderr)
        sys.exit(1)
    for m in sorted(entry["id"] for entry in data.get("data", [])):
        print(m)


def get_verdict(candidate, rec, method_index, model, api_token, timeout, retries, mock):
    context = build_immediate_context(rec, method_index)
    prompt = build_prompt(candidate, rec, context)

    last_error = None
    for attempt in range(retries + 1):
        query = prompt if last_error is None else (
            prompt + f"\n\n=== Your previous response was INVALID ===\n"
            f"Error: {last_error}\nRespond again with STRICT JSON ONLY, "
            f"matching the schema exactly. No prose, no markdown fences."
        )
        try:
            reply = mock_llm(query, attempt, candidate) if mock else call_llm(query, model, api_token, timeout)
        except RuntimeError as e:
            last_error = str(e)
            log.warning("%s.%s: LLM call failed (attempt %d): %s",
                        rec["class"], rec["method"], attempt + 1, e)
            continue

        try:
            obj = extract_json(reply)
        except (ValueError, json.JSONDecodeError) as e:
            last_error = f"could not parse JSON: {e}"
            log.warning("%s.%s: malformed response (attempt %d): %s",
                        rec["class"], rec["method"], attempt + 1, last_error)
            continue

        err = validate_verdict(obj)
        if err is None:
            return obj, attempt + 1, None
        last_error = err
        log.warning("%s.%s: schema validation failed (attempt %d): %s",
                    rec["class"], rec["method"], attempt + 1, last_error)

    return None, retries + 1, last_error


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("methods_jsonl", type=Path, help="ast_symtab/extract.py's methods.jsonl (always required)")
    ap.add_argument("-c", "--candidates", type=Path, default=None,
                    help="candidates.jsonl from prefilter_rank_candidates.py (stage 1 output). "
                         "If omitted, every method in methods_jsonl is verdicted directly, "
                         "with no static pre-filtering.")
    ap.add_argument("-o", "--output", type=Path, default=Path("verdicts.jsonl"))
    ap.add_argument("--errors-output", type=Path, default=Path("errors.jsonl"))
    ap.add_argument("--model", default=None, help="overrides the model from env/llm_config.ini")
    ap.add_argument("--api-token", default=None, help="falls back to LLM_API_TOKEN env var / llm_config.ini")
    ap.add_argument("--timeout", type=float, default=None, help="overrides the timeout from env/llm_config.ini")
    ap.add_argument("--retries", type=int, default=2, help="re-queries on malformed/invalid JSON before dropping")
    ap.add_argument("--top", type=int, default=None,
                    help="only process the first N candidates (by rank when --candidates is given, "
                         "by extraction order otherwise)")
    ap.add_argument("--mock", action="store_true", help="use a canned local responder instead of calling the real API")
    ap.add_argument("--list-models", action="store_true",
                    help="print the models the API endpoint offers and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                         format="%(levelname)s %(message)s")

    api_token = args.api_token or llm_config.api_token()

    if args.list_models:
        if not api_token:
            print("error: --list-models needs a token (LLM_API_TOKEN, --api-token, or llm_config.ini)", file=sys.stderr)
            sys.exit(1)
        list_models(api_token, args.timeout if args.timeout is not None else llm_config.timeout())
        return

    if not args.mock and not api_token:
        print("error: no API token (set LLM_API_TOKEN, pass --api-token, or set it in llm_config.ini; use --mock to test without the API)",
              file=sys.stderr)
        sys.exit(1)

    # Resolve the backend once (env var > llm_config.ini > default) and announce
    # it, so the log makes the LLM in use explicit.
    if args.mock:
        model = args.model
        timeout = args.timeout
        print("LLM: --mock (canned local responder; no API calls)", file=sys.stderr)
    else:
        model = args.model or llm_config.model()
        timeout = args.timeout if args.timeout is not None else llm_config.timeout()
        print(f"LLM: model={model} endpoint={llm_config.endpoint()} "
              f"(token via {'--api-token' if args.api_token else 'LLM_API_TOKEN/llm_config.ini'})",
              file=sys.stderr)

    methods = load_jsonl(args.methods_jsonl)
    method_index = build_method_index(methods)

    if args.candidates:
        candidates = load_jsonl(args.candidates)
    else:
        candidates = build_all_candidates(methods)
        print(f"no --candidates given: verdicting all {len(candidates)} extracted methods directly "
              f"(stage 1 pre-filter skipped)", file=sys.stderr)
    if args.top:
        candidates = candidates[:args.top]

    verdicts, errors = [], []
    for candidate in candidates:
        key = (candidate["class"], candidate["method"])
        rec = method_index.get(key)
        if rec is None:
            errors.append({**candidate, "error": "method record not found in methods.jsonl"})
            continue

        obj, attempts, err = get_verdict(
            candidate, rec, method_index, model, api_token, timeout, args.retries, args.mock)

        if obj is None:
            print(f"DROP  {rec['class']}.{rec['method']}: gave up after {attempts} attempt(s): {err}",
                  file=sys.stderr)
            errors.append({**candidate, "attempts": attempts, "error": err})
            continue

        print(f"OK    {rec['class']}.{rec['method']}: "
              f"security_relevant={obj['is_security_relevant']} "
              f"custom_crypto={obj['is_custom_crypto']} "
              f"leak={obj['leak_mechanism']} severity={obj['severity']} confidence={obj['confidence']} "
              f"(attempt {attempts})", file=sys.stderr)
        verdicts.append({**candidate, "verdict": obj, "attempts": attempts})

    with args.output.open("w", encoding="utf-8") as f:
        for v in verdicts:
            f.write(json.dumps(v) + "\n")
    with args.errors_output.open("w", encoding="utf-8") as f:
        for e in errors:
            f.write(json.dumps(e) + "\n")

    print(f"\n{len(verdicts)} verdicts -> {args.output}; "
          f"{len(errors)} dropped/errored -> {args.errors_output}", file=sys.stderr)


if __name__ == "__main__":
    main()
