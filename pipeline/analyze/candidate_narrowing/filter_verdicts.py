#!/usr/bin/env python3
"""
Post-verdict shortlisting (deterministic).

Takes llm_final_verdict.py's verdicts.jsonl (one JSON verdict per line) and
produces the ranked, trimmed shortlist that the harness stage consumes: keep
only the entries the LLM marked security-relevant, order them by
(severity, confidence) descending, and cut to the top N.

The output preserves the same one-verdict-per-line JSONL shape as the input,
so extract_context.py --verdicts can read it directly (it takes the first
is_security_relevant entry, i.e. this file's top-ranked one).

Usage:
    py filter_verdicts.py <verdicts.jsonl> [-n 5] [-o filtered_verdicts.jsonl]
"""
import argparse
import json
import sys
from pathlib import Path


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def filter_entries(entries):
    """Keep only entries the LLM verdict marked security-relevant."""
    return [
        e for e in entries
        if e.get("verdict", {}).get("is_security_relevant") is True
    ]


def rank(entries):
    """Order by verdict severity, then confidence (both descending)."""
    return sorted(
        entries,
        key=lambda e: (
            e.get("verdict", {}).get("severity", float("-inf")),
            e.get("verdict", {}).get("confidence", float("-inf")),
        ),
        reverse=True,
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("verdicts_jsonl", type=Path, help="llm_final_verdict.py's verdicts.jsonl")
    ap.add_argument("-n", "--num", type=int, default=5,
                    help="number of top-ranked entries to keep (default: 5)")
    ap.add_argument("-o", "--output", type=Path, default=Path("filtered_verdicts.jsonl"))
    args = ap.parse_args()

    entries = load_jsonl(args.verdicts_jsonl)
    relevant = filter_entries(entries)
    selected = rank(relevant)[:args.num]

    with args.output.open("w", encoding="utf-8") as f:
        for e in selected:
            f.write(json.dumps(e) + "\n")

    print(f"read {len(entries)} verdicts; {len(relevant)} security-relevant; "
          f"kept top {len(selected)} -> {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
