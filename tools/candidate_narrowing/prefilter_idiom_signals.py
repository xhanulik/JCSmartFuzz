#!/usr/bin/env python3
"""
Detects, per method, by AST shape (not just regex-over-text):
  - early-return-array-compare : `for (...) if (a[i] != b[i]) return ...;`
    (or the `if (a[i]==b[i]) {} else return ...;` inverse) -- classic
    byte/PIN/MAC comparison timing leak.
  - secret-length-loop-bound   : loop bound is `i < X.length` (or `i < X`)
    where X's name looks like secret material (literal-name match; the
    taint-propagated version of this lives in prefilter_dataflow_signals.py).
  - branch-on-secret-value     : if/while condition references a
    literally secret-named variable/field (literal-name match; see
    prefilter_dataflow_signals.py for the taint-propagated version).
  - branch-on-secret-in-loop   : an if/else (both branches present) inside
    a for/while/do loop, whose condition references a secret-named
    variable/field -- a two-way branch repeated every iteration amplifies
    whatever timing difference the branches have (e.g. a hand-rolled
    constant-time swap/select done with if/else instead of a bitmask).
  - custom-xor-loop            : `out[i] = a[i] ^ b[i];` element-wise XOR.
  - custom-bit-rotate          : `(x << n) | (x >>> m)` shift-rotate shape.
"""
import argparse
import json
import sys
from pathlib import Path

import javalang

from prefilter_dataflow_signals import parse_method_snippet
from secret_keywords import name_matches


def unwrap_cast(node):
    while isinstance(node, javalang.tree.Cast):
        node = node.expression
    return node


def array_index_base(node):
    """If node is `name[...]` (a MemberReference with an ArraySelector selector),
    return the base name; else None."""
    node = unwrap_cast(node)
    if (
        isinstance(node, javalang.tree.MemberReference)
        and node.selectors
        and isinstance(node.selectors[0], javalang.tree.ArraySelector)
    ):
        return node.member
    return None


def contains_return(node):
    if node is None:
        return False
    if isinstance(node, javalang.tree.ReturnStatement):
        return True
    if isinstance(node, (list, tuple)):
        return any(contains_return(n) for n in node)
    if not isinstance(node, javalang.ast.Node):
        return False
    return any(contains_return(getattr(node, attr, None)) for attr in node.attrs)


def is_array_compare(cond, operator):
    return (
        isinstance(cond, javalang.tree.BinaryOperation)
        and cond.operator == operator
        and array_index_base(cond.operandl) is not None
        and array_index_base(cond.operandr) is not None
    )


def find_early_return_array_compare(method_node):
    findings = []
    for _, forstmt in method_node.filter(javalang.tree.ForStatement):
        body = forstmt.body
        stmts = body.statements if isinstance(body, javalang.tree.BlockStatement) else [body]
        for st in stmts:
            if not isinstance(st, javalang.tree.IfStatement):
                continue
            cond = st.condition
            if is_array_compare(cond, "!=") and contains_return(st.then_statement):
                findings.append({"line": _line_of(st)})
            elif is_array_compare(cond, "==") and contains_return(st.else_statement):
                findings.append({"line": _line_of(st)})
    return findings


def find_secret_length_loop_bound(method_node):
    findings = []
    for _, forstmt in method_node.filter(javalang.tree.ForStatement):
        cond = forstmt.control.condition if forstmt.control is not None else None
        if not isinstance(cond, javalang.tree.BinaryOperation) or cond.operator not in ("<", "<="):
            continue
        right = cond.operandr
        candidate_name = None
        if isinstance(right, javalang.tree.MemberReference):
            candidate_name = right.qualifier if (right.member == "length" and right.qualifier) else right.member
        if candidate_name and name_matches(candidate_name):
            findings.append({"line": _line_of(forstmt), "name": candidate_name})
    return findings


def find_branch_on_secret_value(method_node):
    findings = []
    for kind in (javalang.tree.IfStatement, javalang.tree.WhileStatement, javalang.tree.DoStatement):
        for _, stmt in method_node.filter(kind):
            names = set()
            _collect_names(stmt.condition, names)
            hit = [n for n in names if name_matches(n)]
            if hit:
                findings.append({"line": _line_of(stmt), "names": sorted(hit)})
    return findings


def find_branch_on_secret_in_loop(method_node):
    """A two-way if/else nested inside a for/while/do loop, whose condition
    references a secret-named variable/field. Distinct from
    branch-on-secret-value: this requires BOTH an else branch (a real
    two-way choice, not a bare early-exit guard) AND loop nesting (the
    branch cost gets paid every iteration, amplifying any timing skew
    between the two arms)."""
    findings = []
    for loop_kind in (javalang.tree.ForStatement, javalang.tree.WhileStatement, javalang.tree.DoStatement):
        for _, loop in method_node.filter(loop_kind):
            body = loop.body
            if body is None or not isinstance(body, javalang.ast.Node):
                continue
            for _, ifstmt in body.filter(javalang.tree.IfStatement):
                if ifstmt.else_statement is None:
                    continue
                names = set()
                _collect_names(ifstmt.condition, names)
                hit = [n for n in names if name_matches(n)]
                if hit:
                    findings.append({"line": _line_of(ifstmt), "names": sorted(hit)})
    return findings


def find_custom_xor_loop(method_node):
    findings = []
    for _, asn in method_node.filter(javalang.tree.Assignment):
        target = array_index_base(asn.expressionl)
        value = unwrap_cast(asn.value)
        if (
            target is not None
            and isinstance(value, javalang.tree.BinaryOperation)
            and value.operator == "^"
            and array_index_base(value.operandl) is not None
            and array_index_base(value.operandr) is not None
        ):
            findings.append({"line": _line_of(asn)})
    return findings


def find_custom_bit_rotate(method_node):
    findings = []
    for _, node in method_node.filter(javalang.tree.BinaryOperation):
        if node.operator != "|":
            continue
        l, r = unwrap_cast(node.operandl), unwrap_cast(node.operandr)
        shapes = [(l, r), (r, l)]
        for shl, shr in shapes:
            if (
                isinstance(shl, javalang.tree.BinaryOperation) and shl.operator == "<<"
                and isinstance(shr, javalang.tree.BinaryOperation) and shr.operator == ">>>"
            ):
                findings.append({"line": _line_of(node)})
                break
    return findings


def _collect_names(node, out):
    if node is None:
        return
    if isinstance(node, (list, tuple)):
        for n in node:
            _collect_names(n, out)
        return
    if isinstance(node, javalang.tree.MemberReference):
        out.add(node.member)
        if node.qualifier:
            out.add(node.qualifier)
    if not isinstance(node, javalang.ast.Node):
        return
    for attr in node.attrs:
        _collect_names(getattr(node, attr, None), out)


def _line_of(node):
    pos = getattr(node, "position", None)
    return pos.line if pos else None


CHECKS = {
    "early-return-array-compare": find_early_return_array_compare,
    "secret-length-loop-bound": find_secret_length_loop_bound,
    "branch-on-secret-value": find_branch_on_secret_value,
    "branch-on-secret-in-loop": find_branch_on_secret_in_loop,
    "custom-xor-loop": find_custom_xor_loop,
    "custom-bit-rotate": find_custom_bit_rotate,
}


def analyze_method(rec):
    source = rec.get("source")
    if not source:
        return []
    try:
        method_node = parse_method_snippet(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
        return []
    if method_node is None or method_node.body is None:
        return []

    findings = []
    for rule_id, check in CHECKS.items():
        for hit in check(method_node):
            findings.append({"rule_id": rule_id, **hit})
    return findings


def run(methods_jsonl_path):
    results = []
    with open(methods_jsonl_path, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            for finding in analyze_method(rec):
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
    ap.add_argument("methods_jsonl", type=Path)
    ap.add_argument("-o", "--output", type=Path, default=None)
    args = ap.parse_args()

    results = run(args.methods_jsonl)
    out = json.dumps(results, indent=2)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print(f"wrote {len(results)} idiom findings to {args.output}", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
