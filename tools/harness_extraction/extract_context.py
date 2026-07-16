#!/usr/bin/env python3
"""
Stage 3a (deterministic): gather everything the LLM extraction step needs
for ONE target method, using data ast_symtab already extracted plus one
extra javalang pass over the original source for the handful of things
ast_symtab doesn't retain verbatim (field declaration text/modifiers).

This automates the manual "paste the whole applet source into the LLM
prompt" step from skeletons/llm_extraction_prompt.md: instead of handing
the LLM the entire applet and asking it to find constants, error codes,
field types, and the helper-method call closure, all of that is derived
mechanically here so the LLM only has to make the judgment calls in
llm_extract_operation.py (what to remove from the core, how to write the
wrapper).

Target method selection:
  --method Class.method   explicit override
  --verdicts path.jsonl   otherwise, picks the first entry (file order =
                          rank order) with verdict.is_security_relevant
                          == true, from candidate_narrowing's output
At least one of the two must resolve to a method, or a --method not found
in --verdicts falls back to being used directly (an explicit --method
always wins).

Usage:
    py extract_context.py <src_dir> <ast_out_dir> --method FixtureApplet.verifyPin -o context.json
    py extract_context.py <src_dir> <ast_out_dir> --verdicts ../candidate_narrowing/fixture/verdicts.jsonl -o context.json
"""
import argparse
import json
import re
import sys
from pathlib import Path

import javalang

SW_NAME_RE = re.compile(r"(?i)^SW_")


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build_method_index(methods):
    index = {}
    for rec in methods:
        index.setdefault((rec["class"], rec["method"]), rec)
    return index


def resolve_source_file(src_dir, recorded_path):
    """methods.jsonl stores str(path) relative to whatever cwd ast_symtab/extract.py
    was originally run from -- which is very often NOT this script's cwd. Re-resolve
    by basename under the given --src-dir instead of trusting the literal path."""
    name = Path(recorded_path).name
    if name not in resolve_source_file._cache:
        matches = list(Path(src_dir).rglob(name))
        resolve_source_file._cache[name] = str(matches[0]) if matches else recorded_path
    return resolve_source_file._cache[name]


resolve_source_file._cache = {}


def build_class_file_index(methods, src_dir):
    """class_name -> a representative, re-resolved source file path (first method record seen)."""
    index = {}
    for rec in methods:
        index.setdefault(rec["class"], resolve_source_file(src_dir, rec["file"]))
    return index


def resolve_target(args, methods, method_index):
    if args.method:
        if "." not in args.method:
            print(f"error: --method must be Class.method, got {args.method!r}", file=sys.stderr)
            sys.exit(1)
        cls, name = args.method.rsplit(".", 1)
        if (cls, name) not in method_index:
            print(f"error: {args.method} not found in {args.ast_out_dir}/methods.jsonl", file=sys.stderr)
            sys.exit(1)
        return cls, name, None

    if args.verdicts:
        verdicts = load_jsonl(args.verdicts)
        for v in verdicts:
            if v.get("verdict", {}).get("is_security_relevant"):
                cls, name = v["class"], v["method"]
                if (cls, name) not in method_index:
                    print(f"error: top verdict {cls}.{name} not found in methods.jsonl "
                          f"(stale verdicts.jsonl?)", file=sys.stderr)
                    sys.exit(1)
                return cls, name, v["verdict"]
        print(f"error: no is_security_relevant=true entry found in {args.verdicts}", file=sys.stderr)
        sys.exit(1)

    print("error: pass --method Class.method or --verdicts verdicts.jsonl", file=sys.stderr)
    sys.exit(1)


def parse_file(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    tree = javalang.parse.parse(text)
    return tree, text.splitlines()


_file_cache = {}


def get_parsed_file(path):
    if path not in _file_cache:
        _file_cache[path] = parse_file(path)
    return _file_cache[path]


def find_field_declaration(path, class_name, field_name):
    """Re-parses the owning file (ast_symtab keeps declared type but not modifiers
    or initializer text) to pull the verbatim field declaration + its modifiers."""
    tree, lines = get_parsed_file(path)
    for _, type_node in tree.filter(javalang.tree.TypeDeclaration):
        if type_node.name != class_name:
            continue
        for _, fd in type_node.filter(javalang.tree.FieldDeclaration):
            if not any(d.name == field_name for d in fd.declarators):
                continue
            if not fd.position:
                return None
            start = fd.position.line
            end = start
            depth = 0
            for i in range(start - 1, len(lines)):
                depth += lines[i].count("(") - lines[i].count(")")
                if ";" in lines[i] and depth <= 0:
                    end = i + 1
                    break
            return {
                "declaration": "\n".join(lines[start - 1:end]).strip(),
                "modifiers": sorted(fd.modifiers),
                "line": start,
            }
    return None


def find_constructor_init_line(constructor_source, field_name):
    """Locate the line in a constructor's own verbatim source (already extracted
    by ast_symtab) that assigns field_name, by re-parsing just that snippet."""
    if not constructor_source:
        return None
    wrapped = f"class __Wrapper__ {{\n{constructor_source}\n}}"
    try:
        tree = javalang.parse.parse(wrapped)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError):
        return None
    ctor = next((n for _, n in tree.filter(javalang.tree.ConstructorDeclaration)), None)
    if ctor is None:
        return None
    lines = constructor_source.splitlines()
    for _, asn in ctor.filter(javalang.tree.Assignment):
        target = asn.expressionl
        if (
            isinstance(target, javalang.tree.MemberReference)
            and target.member == field_name
            and target.qualifier in ("", "this", None)
            and not target.selectors
            and target.position
        ):
            idx = target.position.line - 2  # -1 for the synthetic wrapper line, -1 for 0-index
            if 0 <= idx < len(lines):
                return lines[idx].strip()
    return None


def gather_fields(field_names_by_class, class_file_index, method_index):
    """Split every referenced non-local field into constants / error_codes / fields
    (instance state needing a constructor init line), based on its own
    static+final modifiers -- not a name heuristic."""
    constants, error_codes, fields = [], [], []
    seen = set()

    for owner_class, field_name in field_names_by_class:
        key = (owner_class, field_name)
        if key in seen:
            continue
        seen.add(key)

        path = class_file_index.get(owner_class)
        if path is None:
            continue
        decl = find_field_declaration(path, owner_class, field_name)
        if decl is None:
            continue

        is_const = "static" in decl["modifiers"] and "final" in decl["modifiers"]
        entry = {
            "name": field_name,
            "owner_class": owner_class,
            "modifiers": decl["modifiers"],
            "declaration": decl["declaration"],
            "source_file": str(path),
            "source_line": decl["line"],
        }
        if is_const:
            (error_codes if SW_NAME_RE.match(field_name) else constants).append(entry)
        else:
            ctor = method_index.get((owner_class, "<init>"))
            init_line = find_constructor_init_line(ctor["source"], field_name) if ctor else None
            entry["init_line"] = init_line
            fields.append(entry)

    return constants, error_codes, fields


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src_dir", type=Path, help="original applet source directory (for re-reading field declarations)")
    ap.add_argument("ast_out_dir", type=Path, help="ast_symtab output dir (methods.jsonl, symbol_table.json)")
    ap.add_argument("--method", default=None, help="Class.method to extract (overrides --verdicts)")
    ap.add_argument("--verdicts", type=Path, default=None,
                     help="candidate_narrowing verdicts.jsonl; used if --method is omitted")
    ap.add_argument("--ins", default=None, help="INS byte, e.g. 0x10 (default: next free byte from 0x10)")
    ap.add_argument("-o", "--output", type=Path, default=Path("context.json"))
    args = ap.parse_args()

    methods = load_jsonl(args.ast_out_dir / "methods.jsonl")
    method_index = build_method_index(methods)
    class_file_index = build_class_file_index(methods, args.src_dir)

    target_class, target_method, verdict_hint = resolve_target(args, methods, method_index)
    target = method_index[(target_class, target_method)]

    helper_keys = [tuple(k.rsplit(".", 1)) for k in target.get("transitive_calls", [])]
    helpers = [method_index[k] for k in helper_keys if k in method_index]

    helper_classes = sorted({h["class"] for h in helpers} - {target_class})
    helper_class_files = [
        {"class": c, "file": class_file_index[c]}
        for c in helper_classes if c in class_file_index
    ]

    constructor = method_index.get((target_class, "<init>"))

    field_refs = [(f["owner_class"], f["field"]) for f in target.get("field_dataflow", [])]
    for h in helpers:
        field_refs.extend((f["owner_class"], f["field"]) for f in h.get("field_dataflow", []))
    if constructor:
        # a field's own init line (e.g. `referencePin = new byte[MAX_PIN_LEN];`) can
        # reference a constant the operation body itself never touches directly --
        # without this, MAX_PIN_LEN-style sizing constants silently go missing.
        field_refs.extend((f["owner_class"], f["field"]) for f in constructor.get("field_dataflow", []))

    constants, error_codes, fields = gather_fields(field_refs, class_file_index, method_index)

    ins_byte = args.ins or "0x10"

    context = {
        "target": target,
        "constructor": constructor,
        "helpers": helpers,
        "helper_classes": helper_class_files,
        "constants": constants,
        "error_codes": error_codes,
        "fields": fields,
        "ins_byte": ins_byte,
        "verdict_hint": verdict_hint,
    }

    args.output.write_text(json.dumps(context, indent=2), encoding="utf-8")
    print(f"target: {target_class}.{target_method}  "
          f"({len(helpers)} helper methods, {len(helper_class_files)} helper classes, "
          f"{len(fields)} fields, {len(constants)} constants, {len(error_codes)} error codes)",
          file=sys.stderr)
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
