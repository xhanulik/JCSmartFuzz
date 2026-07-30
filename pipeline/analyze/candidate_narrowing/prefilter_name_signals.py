#!/usr/bin/env python3
"""
Cheapest tier of candidate narrowing: flag methods whose own name, class
name, parameters, locals, or non-local fields look like they handle secret
material, by name alone. No parsing beyond what ast_symtab already did.
"""
import argparse
import json
import sys
from pathlib import Path

from secret_keywords import CRYPTO_METHOD_RE, name_matches


def analyze_method(rec):
    hits = {}

    if CRYPTO_METHOD_RE.search(rec["method"]):
        hits.setdefault("name:crypto-method-name", []).append(rec["method"])

    for p in rec["params"]:
        if name_matches(p["name"]):
            hits.setdefault("name:secret-param", []).append(p["name"])
    for l in rec["locals"]:
        if name_matches(l["name"]):
            hits.setdefault("name:secret-local", []).append(l["name"])
    for f in rec["field_dataflow"]:
        if name_matches(f["field"]):
            hits.setdefault("name:secret-field", []).append(f["field"])

    return hits


def run(methods_jsonl_path):
    results = []
    with open(methods_jsonl_path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            hits = analyze_method(rec)
            for rule_id, names in hits.items():
                results.append({
                    "file": rec["file"],
                    "class": rec["class"],
                    "method": rec["method"],
                    "start_line": rec["start_line"],
                    "rule_id": rule_id,
                    "matched_names": sorted(set(names)),
                })
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("methods_jsonl", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=None)
    args = ap.parse_args()

    results = run(args.methods_jsonl)
    out = json.dumps(results, indent=2)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print(f"wrote {len(results)} name-heuristic findings to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
