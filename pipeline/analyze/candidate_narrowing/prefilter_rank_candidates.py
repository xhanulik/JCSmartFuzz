#!/usr/bin/env python3
"""
Deterministic pre-filter / candidate narrowing.

Combines three independent, cheap-to-run signal sources into one ranked
shortlist of methods, each tagged with which rule(s) fired -- this is the
step that keeps the LLM off the whole repo, and its output doubles as a
heuristic-only baseline for ablation (LLM-review-with-narrowing vs.
LLM-review-of-the-full-shortlist vs. no narrowing at all).

Sources (see README for the rationale on each; all are pure Python over
the javalang AST ast_symtab already built -- no external tool/subprocess):
  1. idiom     -- AST-shape idiom checks (prefilter_idiom_signals.py), the
                  same set originally scoped as "Semgrep/Opengrep rules":
                  early-return array compare, secret-length loop bound
                  (literal name match), branch-on-secret (literal name
                  match), custom XOR/rotate loops.
  2. dataflow  -- single-method, one-hop taint propagation over the AST
                  (prefilter_dataflow_signals.py). Stronger than idiom's
                  literal-name rules because it survives `byte[] p = pin;`
                  -style renaming; weaker than real interprocedural CPG
                  taint (Joern) -- see README for that tradeoff.
  3. name      -- crude name-only heuristic (prefilter_name_signals.py) as
                  a cheap baseline signal and an ablation floor.

This is stage 1 (deterministic) of the two-stage narrowing pipeline; its
output (candidates.jsonl) feeds stage 2, llm_final_verdict.py, which
produces the pipeline's ultimate per-method output.

Usage:
    py prefilter_rank_candidates.py <ast_symtab_methods.jsonl> [-o candidates.jsonl]

Requires ast_symtab/extract.py to have already been run over the source
tree being narrowed.
"""
import argparse
import json
import sys
from pathlib import Path

import prefilter_dataflow_signals
import prefilter_idiom_signals
import prefilter_name_signals

RULE_WEIGHTS = {
    "early-return-array-compare": 3,
    "secret-length-loop-bound": 2,
    "branch-on-secret-value": 1,
    "branch-on-secret-in-loop": 3,
    "custom-xor-loop": 2,
    "custom-bit-rotate": 2,
    "dataflow-secret-length-loop": 4,
    "dataflow-branch-on-secret": 4,
    "name:crypto-method-name": 1,
    "name:secret-param": 1,
    "name:secret-local": 1,
    "name:secret-field": 1,
}


def normalize(results, source):
    findings = []
    for r in results:
        findings.append({
            "method_key": (r["file"], r["class"], r["method"]),
            "rule_id": r["rule_id"],
            "source": source,
            "line": r.get("line", r.get("start_line")),
        })
    return findings


def rank(all_findings):
    by_method = {}
    for f in all_findings:
        by_method.setdefault(f["method_key"], []).append(f)

    candidates = []
    for method_key, findings in by_method.items():
        by_rule = {}
        for f in findings:
            by_rule.setdefault(f["rule_id"], []).append(f)
        fired_rules = []
        score = 0
        for rule_id, items in by_rule.items():
            weight = RULE_WEIGHTS.get(rule_id, 1)
            score += weight
            fired_rules.append({
                "rule_id": rule_id,
                "source": items[0]["source"],
                "weight": weight,
                "hit_count": len(items),
                "lines": sorted(set(i["line"] for i in items if i["line"] is not None)),
            })
        fired_rules.sort(key=lambda r: -r["weight"])
        file_, class_, method_ = method_key
        candidates.append({
            "file": file_,
            "class": class_,
            "method": method_,
            "score": score,
            "fired_rules": fired_rules,
        })
    candidates.sort(key=lambda c: (-c["score"], c["file"], c["class"], c["method"]))
    for i, c in enumerate(candidates, 1):
        c["rank"] = i
    return candidates


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("methods_jsonl", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=Path("candidates.jsonl"))
    args = ap.parse_args()

    idiom_raw = prefilter_idiom_signals.run(args.methods_jsonl)
    idiom_findings = normalize(idiom_raw, "idiom")
    print(f"idiom checks: {len(idiom_findings)} findings", file=sys.stderr)

    dataflow_raw = prefilter_dataflow_signals.run(args.methods_jsonl)
    dataflow_findings = normalize(dataflow_raw, "dataflow")
    print(f"dataflow: {len(dataflow_findings)} findings", file=sys.stderr)

    name_raw = prefilter_name_signals.run(args.methods_jsonl)
    name_findings = normalize(name_raw, "name")
    print(f"name heuristics: {len(name_findings)} findings", file=sys.stderr)

    all_findings = idiom_findings + dataflow_findings + name_findings
    candidates = rank(all_findings)

    with args.output.open("w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps(c) + "\n")
    print(f"wrote {len(candidates)} ranked candidates to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
