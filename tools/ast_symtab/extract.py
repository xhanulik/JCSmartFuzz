#!/usr/bin/env python3
"""
AST + symbol-table extractor for Java Card applet source trees.

Parses every .java file under an input directory with javalang, builds a
repo-wide symbol table (classes, fields, methods), and emits one JSON
record per method containing:
  - exact parameter types (as declared in source -- no inference needed)
  - non-local (instance/inherited) field reads & writes, with def-use
    classification (read-before-write => value must come from outside the
    method, i.e. a fuzz-input candidate; written-first => the method
    produces/owns that state internally before any read)
  - the transitive call closure (all internally-resolved callees reachable
    from this method, including a separate private-only subset), so an LLM
    reviewing one method can be handed its full helper closure instead of
    just direct calls
  - resolved method calls, locals, and raw source

Usage:
    py extract.py <applet_src_dir> [-o output_dir]

Output:
    <output_dir>/symbol_table.json   - classes/fields/methods index
    <output_dir>/methods.jsonl       - one JSON object per method
    <output_dir>/call_graph.json     - direct + transitive caller -> callee edges

Determinism / known approximations (documented, not hidden):
  - Def-use order is a single lexical DFS over the method body (control-flow
    branches are visited in source order -- then before else, loop body
    visited once). This is NOT a real CFG: a field written only on one
    branch of an if/else and read after the branch will be classified using
    whichever branch is visited first in source order, not a merge of both
    paths. It is deterministic and a fair triage signal, not a precise
    dataflow analysis.
  - A local variable or parameter that shadows a field name causes that
    name to be excluded from field def-use for the whole method (no
    block-scoped shadowing resolution).
  - Overloads collapse to one call-graph node per (class, method name) --
    argument-type-based overload resolution is not performed.
  - Field writes are only counted when the field itself is reassigned
    (`x = ...`, `x += ...`, `x++`). `arr[i] = ...` or `obj.field.member`
    is counted as a READ of `arr`/`obj` (the reference must already exist
    to be dereferenced), not a write to the field.
"""
import argparse
import json
import sys
from pathlib import Path

import javalang
from javalang.ast import Node


def find_java_files(root: Path):
    return sorted(p for p in root.rglob("*.java") if p.is_file())


def type_to_str(t):
    if t is None:
        return "void"
    name = getattr(t, "name", str(t))
    dims = getattr(t, "dimensions", None) or []
    return name + "[]" * len(dims)


def extract_snippet(source_lines, start_line):
    """Brace-match from the first '{' at/after start_line to build a source snippet."""
    idx = start_line - 1
    depth = 0
    started = False
    out = []
    for i in range(idx, len(source_lines)):
        line = source_lines[i]
        out.append(line)
        for ch in line:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth == 0:
            break
    return "\n".join(out)


class ClassInfo:
    def __init__(self, name, package, kind, extends, implements):
        self.name = name
        self.package = package
        self.kind = kind  # class | interface | enum
        self.extends = extends
        self.implements = implements
        self.fields = {}   # name -> type
        self.methods = {}  # name -> [signatures]


def build_symbol_table(files):
    """First pass: parse every file, record class/field/method declarations."""
    classes = {}          # simple_name -> ClassInfo
    file_imports = {}     # file path -> {simple_name: fully_qualified}
    parsed = {}           # file path -> (tree, source_text, source_lines)

    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = javalang.parse.parse(text)
        except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
            print(f"WARN: failed to parse {path}: {e}", file=sys.stderr)
            continue

        parsed[path] = (tree, text, text.splitlines())
        package = tree.package.name if tree.package else ""

        imports = {}
        for imp in tree.imports:
            imports[imp.path.split(".")[-1]] = imp.path
        file_imports[path] = imports

        for _, node in tree.filter(javalang.tree.TypeDeclaration):
            kind = (
                "interface" if isinstance(node, javalang.tree.InterfaceDeclaration)
                else "enum" if isinstance(node, javalang.tree.EnumDeclaration)
                else "class"
            )
            extends = None
            implements = []
            if hasattr(node, "extends") and node.extends:
                ext = node.extends
                extends = type_to_str(ext) if not isinstance(ext, list) else [type_to_str(e) for e in ext]
            if hasattr(node, "implements") and node.implements:
                implements = [type_to_str(i) for i in node.implements]

            info = ClassInfo(node.name, package, kind, extends, implements)

            for _, member in node.filter(javalang.tree.FieldDeclaration):
                ftype = type_to_str(member.type)
                for decl in member.declarators:
                    info.fields[decl.name] = ftype

            for _, m in node.filter(javalang.tree.MethodDeclaration):
                params = [(p.name, type_to_str(p.type)) for p in m.parameters]
                info.methods.setdefault(m.name, []).append({
                    "return_type": type_to_str(m.return_type),
                    "params": params,
                    "modifiers": sorted(m.modifiers),
                })

            for _, c in node.filter(javalang.tree.ConstructorDeclaration):
                params = [(p.name, type_to_str(p.type)) for p in c.parameters]
                info.methods.setdefault("<init>", []).append({
                    "return_type": "void",
                    "params": params,
                    "modifiers": sorted(c.modifiers),
                })

            classes[node.name] = info

    return classes, file_imports, parsed


def resolve_field_owner(class_name, field_name, classes):
    """Walk the extends chain to find which class declares a field."""
    seen = set()
    cur = class_name
    while cur and cur not in seen and cur in classes:
        seen.add(cur)
        info = classes[cur]
        if field_name in info.fields:
            return cur, info.fields[field_name]
        ext = info.extends
        cur = ext if isinstance(ext, str) else None
    return None, None


def resolve_method_owner(class_name, method_name, classes):
    """Walk the extends chain to find which class declares a method (by name only --
    overload/argument-type resolution is not performed, see module docstring)."""
    seen = set()
    cur = class_name
    while cur and cur not in seen and cur in classes:
        seen.add(cur)
        info = classes[cur]
        if method_name in info.methods:
            return cur
        ext = info.extends
        cur = ext if isinstance(ext, str) else None
    return None


def collect_inherited_fields(class_name, classes):
    """name -> (owner_class, type) across the whole extends chain, nearest wins."""
    fields = {}
    seen = set()
    cur = class_name
    while cur and cur not in seen and cur in classes:
        seen.add(cur)
        info = classes[cur]
        for fname, ftype in info.fields.items():
            fields.setdefault(fname, (cur, ftype))
        ext = info.extends
        cur = ext if isinstance(ext, str) else None
    return fields


def collect_shadowing_names(method_node):
    names = {p.name for p in method_node.parameters}
    for _, lv in method_node.filter(javalang.tree.LocalVariableDeclaration):
        for decl in lv.declarators:
            names.add(decl.name)
    return names


def analyze_field_dataflow(method_node, class_name, classes):
    """Single lexical DFS over the method body tracking non-local field read/write
    order. See module docstring for the documented approximations."""
    instance_fields = collect_inherited_fields(class_name, classes)
    shadowed = collect_shadowing_names(method_node)

    def is_own_field(name):
        return name not in shadowed and name in instance_fields

    order = []  # list of (field_name, 'read'|'write') in encounter order

    def visit_member_target(node, is_write_target):
        qualifier = getattr(node, "qualifier", None)
        member = getattr(node, "member", None)
        selectors = getattr(node, "selectors", None) or []
        prefix_ops = getattr(node, "prefix_operators", None) or []
        postfix_ops = getattr(node, "postfix_operators", None) or []
        has_incdec = any(op in ("++", "--") for op in list(prefix_ops) + list(postfix_ops))
        own_instance = qualifier in ("", "this", None)

        if own_instance and member and is_own_field(member):
            if selectors:
                # arr[i] = ... / field.member -- dereferences the field, doesn't reassign it
                order.append((member, "read"))
            elif is_write_target == "plain":
                order.append((member, "write"))
            elif is_write_target == "compound" or has_incdec:
                order.append((member, "read"))
                order.append((member, "write"))
            else:
                order.append((member, "read"))
        for sel in selectors:
            visit(sel)

    def visit(node):
        if node is None:
            return
        if isinstance(node, (list, tuple)):
            for n in node:
                visit(n)
            return
        if isinstance(node, javalang.tree.Assignment):
            visit(node.value)  # RHS evaluated before the write takes effect
            target = node.expressionl
            if isinstance(target, javalang.tree.MemberReference):
                visit_member_target(target, "plain" if node.type == "=" else "compound")
            else:
                visit(target)
            return
        if isinstance(node, javalang.tree.MemberReference):
            visit_member_target(node, False)
            return
        if not isinstance(node, Node):
            return
        for attr in node.attrs:
            visit(getattr(node, attr, None))

    visit(method_node.body)

    first_access = {}
    reads_count = {}
    writes_count = {}
    for name, kind in order:
        first_access.setdefault(name, kind)
        if kind == "read":
            reads_count[name] = reads_count.get(name, 0) + 1
        else:
            writes_count[name] = writes_count.get(name, 0) + 1

    results = []
    for name in sorted(set(n for n, _ in order)):
        owner, ftype = instance_fields[name]
        fa = first_access[name]
        results.append({
            "field": name,
            "owner_class": owner,
            "type": ftype,
            "reads": reads_count.get(name, 0),
            "writes": writes_count.get(name, 0),
            "first_access": fa,
            "classification": "read_before_write" if fa == "read" else "written_first",
        })
    return results


def _extract_one(m, method_name, class_name, imports, classes, lines, path):
    params = [{"name": p.name, "type": type_to_str(p.type)} for p in m.parameters]
    locals_ = []
    for _, lv in m.filter(javalang.tree.LocalVariableDeclaration):
        lt = type_to_str(lv.type)
        for decl in lv.declarators:
            locals_.append({"name": decl.name, "type": lt})

    calls = []
    for _, inv in m.filter(javalang.tree.MethodInvocation):
        qualifier = inv.qualifier or None
        resolved_class = None
        if qualifier is None or qualifier == "this":
            # unqualified or this.foo() -- walk own class + superclass chain
            resolved_class = resolve_method_owner(class_name, inv.member, classes)
        elif qualifier in imports:
            resolved_class = imports[qualifier]
        elif qualifier in classes:
            resolved_class = qualifier
        else:
            owner, ftype = resolve_field_owner(class_name, qualifier, classes)
            if ftype:
                resolved_class = ftype
            else:
                for p in params:
                    if p["name"] == qualifier:
                        resolved_class = p["type"]
                for l in locals_:
                    if l["name"] == qualifier:
                        resolved_class = l["type"]
        calls.append({
            "qualifier": qualifier,
            "method": inv.member,
            "resolved_owner": resolved_class,
            "external": resolved_class is None or resolved_class not in classes,
        })

    field_dataflow = analyze_field_dataflow(m, class_name, classes)

    start_line = m.position.line if m.position else None
    snippet = extract_snippet(lines, start_line) if start_line else None

    return {
        "file": str(path),
        "class": class_name,
        "method": method_name,
        "modifiers": sorted(m.modifiers),
        "return_type": type_to_str(getattr(m, "return_type", None)),
        "params": params,
        "throws": list(m.throws) if m.throws else [],
        "locals": locals_,
        "field_dataflow": field_dataflow,
        "calls": calls,
        "start_line": start_line,
        "source": snippet,
    }


def extract_methods(classes, file_imports, parsed):
    records = []
    for path, (tree, text, lines) in parsed.items():
        imports = file_imports.get(path, {})
        for _, type_node in tree.filter(javalang.tree.TypeDeclaration):
            class_name = type_node.name
            for _, m in type_node.filter(javalang.tree.MethodDeclaration):
                records.append(_extract_one(m, m.name, class_name, imports, classes, lines, path))
            for _, c in type_node.filter(javalang.tree.ConstructorDeclaration):
                # constructors are recorded as "<init>" (matching the symbol table's
                # info.methods key) rather than the class name, so a caller resolving
                # by (class, method) can't confuse a constructor with a same-named method
                records.append(_extract_one(c, "<init>", class_name, imports, classes, lines, path))
    return records


def method_key(class_name, method_name):
    return f"{class_name}.{method_name}"


def is_private_method(class_name, method_name, classes):
    info = classes.get(class_name)
    if not info:
        return False
    overloads = info.methods.get(method_name, [])
    return any("private" in ov["modifiers"] for ov in overloads)


def build_call_graphs(records, classes):
    direct = {}
    for rec in records:
        caller = method_key(rec["class"], rec["method"])
        for c in rec["calls"]:
            if not c["external"]:
                direct.setdefault(caller, set()).add(method_key(c["resolved_owner"], c["method"]))

    def closure(start):
        visited = set()
        stack = list(direct.get(start, ()))
        recursive = False
        while stack:
            node = stack.pop()
            if node == start:
                recursive = True
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.extend(direct.get(node, ()))
        return sorted(visited), recursive

    transitive = {}
    transitive_private = {}
    for caller in direct:
        reach, recursive = closure(caller)
        transitive[caller] = {"reachable": reach, "recursive": recursive}
        transitive_private[caller] = [
            n for n in reach
            if is_private_method(n.rsplit(".", 1)[0], n.rsplit(".", 1)[1], classes)
        ]

    direct_json = {k: sorted(v) for k, v in direct.items()}
    return direct_json, transitive, transitive_private


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src_dir", type=Path, help="path to the applet source directory")
    ap.add_argument("-o", "--output", type=Path, default=None, help="output directory (default: <src_dir>/../ast_out)")
    args = ap.parse_args()

    if not args.src_dir.is_dir():
        print(f"error: {args.src_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    out_dir = args.output or (args.src_dir.parent / "ast_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    files = find_java_files(args.src_dir)
    if not files:
        print(f"error: no .java files found under {args.src_dir}", file=sys.stderr)
        sys.exit(1)
    print(f"found {len(files)} .java files")

    classes, file_imports, parsed = build_symbol_table(files)
    print(f"parsed {len(parsed)} files, {len(classes)} type declarations")

    symbol_table = {
        name: {
            "package": info.package,
            "kind": info.kind,
            "extends": info.extends,
            "implements": info.implements,
            "fields": info.fields,
            "methods": info.methods,
        }
        for name, info in classes.items()
    }
    (out_dir / "symbol_table.json").write_text(json.dumps(symbol_table, indent=2), encoding="utf-8")

    records = extract_methods(classes, file_imports, parsed)

    direct_graph, transitive_graph, transitive_private = build_call_graphs(records, classes)
    for rec in records:
        key = method_key(rec["class"], rec["method"])
        t = transitive_graph.get(key, {"reachable": [], "recursive": False})
        rec["transitive_calls"] = t["reachable"]
        rec["recursive"] = t["recursive"]
        rec["transitive_private_helpers"] = transitive_private.get(key, [])

    with (out_dir / "methods.jsonl").open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    print(f"wrote {len(records)} method records to {out_dir / 'methods.jsonl'}")

    call_graph_out = {
        "direct": direct_graph,
        "transitive": {k: v["reachable"] for k, v in transitive_graph.items()},
        "recursive_methods": sorted(k for k, v in transitive_graph.items() if v["recursive"]),
        "transitive_private_helpers": transitive_private,
    }
    (out_dir / "call_graph.json").write_text(json.dumps(call_graph_out, indent=2), encoding="utf-8")
    print(f"wrote call graph to {out_dir / 'call_graph.json'}")


if __name__ == "__main__":
    main()
