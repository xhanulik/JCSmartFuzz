#!/usr/bin/env python3
"""
This module gets most of the same signal for the single-method case using
the AST/symbol data ast_symtab already extracts:

  - seeds a "tainted" name set from parameters/fields/locals whose name
    looks like secret material (pin/secret/key/password/...)
  - does a bounded (3-pass) one-hop propagation: `byte[] p = pin;` taints
    `p` too, so renaming the secret before using it doesn't defeat the
    check the way a pure name-regex (semgrep) rule would
  - flags loop bounds and if/while conditions that reference a tainted
    name -- i.e. control flow or iteration count that depends on secret
    data, the actual timing-leak precondition

This is intentionally narrower than real dataflow: propagation is
single-assignment/single-hop per pass, bounded to one method body (no
interprocedural taint through calls), and is not control-flow sensitive
(see ast_symtab/extract.py docstring for the same caveat applied there).
"""
import argparse
import json
import sys
from pathlib import Path

import javalang

from secret_keywords import name_matches

PROPAGATION_PASSES = 3


def parse_method_snippet(source):
    wrapped = f"class __Wrapper__ {{\n{source}\n}}"
    tree = javalang.parse.parse(wrapped)
    for _, m in tree.filter(javalang.tree.MethodDeclaration):
        return m
    for _, m in tree.filter(javalang.tree.ConstructorDeclaration):
        return m
    return None


def collect_member_names(node):
    names = set()

    def visit(n):
        if n is None:
            return
        if isinstance(n, (list, tuple)):
            for x in n:
                visit(x)
            return
        if isinstance(n, javalang.tree.MemberReference):
            names.add(n.member)
        if not isinstance(n, javalang.ast.Node):
            return
        for attr in n.attrs:
            visit(getattr(n, attr, None))

    visit(node)
    return names


def bare_reference_name(expr):
    """If expr is just `name` (a plain MemberReference, no selectors/call), return the name."""
    if isinstance(expr, javalang.tree.MemberReference) and not expr.selectors and expr.qualifier in ("", "this", None):
        return expr.member
    return None


def propagate_taint(method_node, tainted):
    tainted = set(tainted)
    for _ in range(PROPAGATION_PASSES):
        changed = False
        for _, lv in method_node.filter(javalang.tree.LocalVariableDeclaration):
            for decl in lv.declarators:
                src_name = bare_reference_name(decl.initializer) if decl.initializer is not None else None
                if src_name and src_name in tainted and decl.name not in tainted:
                    tainted.add(decl.name)
                    changed = True
        for _, asn in method_node.filter(javalang.tree.Assignment):
            target_name = bare_reference_name(asn.expressionl)
            src_name = bare_reference_name(asn.value)
            if target_name and src_name and src_name in tainted and target_name not in tainted:
                tainted.add(target_name)
                changed = True
        if not changed:
            break
    return tainted


def analyze_method(rec):
    """Return a list of finding dicts for this ast_symtab method record."""
    source = rec.get("source")
    if not source:
        return []
    try:
        method_node = parse_method_snippet(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
        return []
    if method_node is None or method_node.body is None:
        return []

    seed = set()
    for p in rec["params"]:
        if name_matches(p["name"]):
            seed.add(p["name"])
    for l in rec["locals"]:
        if name_matches(l["name"]):
            seed.add(l["name"])
    for f in rec["field_dataflow"]:
        if name_matches(f["field"]) and f["classification"] == "read_before_write":
            seed.add(f["field"])

    if not seed:
        return []

    tainted = propagate_taint(method_node, seed)
    findings = []

    for _, stmt in method_node.filter(javalang.tree.ForStatement):
        control = stmt.control
        cond = getattr(control, "condition", None) if control is not None else None
        names = collect_member_names(cond)
        hit = names & tainted
        if hit:
            findings.append({
                "rule_id": "dataflow-secret-length-loop",
                "tainted_names": sorted(hit),
            })

    for kind in (javalang.tree.IfStatement, javalang.tree.WhileStatement, javalang.tree.DoStatement):
        for _, stmt in method_node.filter(kind):
            names = collect_member_names(stmt.condition)
            hit = names & tainted
            if hit:
                findings.append({
                    "rule_id": "dataflow-branch-on-secret",
                    "tainted_names": sorted(hit),
                })

    for f in findings:
        f["seed_names"] = sorted(seed)
    return findings


def run(methods_jsonl_path):
    results = []
    with open(methods_jsonl_path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            findings = analyze_method(rec)
            for finding in findings:
                results.append({
                    "file": rec["file"],
                    "class": rec["class"],
                    "method": rec["method"],
                    "start_line": rec["start_line"],
                    **finding,
                })
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("methods_jsonl", type=Path, help="path to ast_symtab's methods.jsonl")
    ap.add_argument("-o", "--output", type=Path, default=None, help="output JSON path (default: stdout)")
    args = ap.parse_args()

    results = run(args.methods_jsonl)
    out = json.dumps(results, indent=2)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print(f"wrote {len(results)} dataflow findings to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
