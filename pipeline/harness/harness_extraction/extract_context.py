#!/usr/bin/env python3
"""
Stage 3a (deterministic): gather everything the LLM extraction step needs
for ONE target method, using data ast_symtab already extracted plus one
extra javalang pass over the original source for the handful of things
ast_symtab doesn't retain verbatim (field declaration text/modifiers).

This automates the manual "paste the whole applet source into the LLM
prompt" step: instead of handing the LLM the entire applet and asking it
to find constants, error codes,
field types, and the helper-method call closure, all of that is derived
mechanically here so the LLM only has to make the judgment calls in
llm_extract_operation.py (what to remove from the core, how to write the
wrapper).

Target method selection (each/each model: one harness per method):
  --method Class.method   extract exactly this ONE method -> context.json holds
                          a single context object.
  --verdicts path.jsonl   extract EVERY entry with
                          verdict.is_security_relevant == true (e.g.
                          filter_verdicts.py's ranked shortlist) -> context.json
                          holds a JSON LIST of per-method context objects. The
                          fuzzing model builds a separate applet + driver per
                          method, so every shortlisted method is carried in the
                          one file (not just the top-ranked one);
                          llm_extract_operation.py then emits one operation per
                          list element.
Exactly one of --method / --verdicts must be given.

Usage:
    py extract_context.py <src_dir> <ast_out_dir> --method FixtureApplet.verifyPin -o context.json
    py extract_context.py <src_dir> <ast_out_dir> --verdicts filtered_verdicts.jsonl -o context.json
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
    by basename under the given --src-dir instead of trusting the literal path.

    The recorded path may use Windows separators (`\\`) when ast_symtab ran on
    Windows; `Path(...).name` only splits on the *host* separator, so normalize
    `\\` to `/` first, otherwise the basename lookup fails on Linux and the raw
    backslash path reaches open() as a FileNotFoundError."""
    name = Path(recorded_path.replace("\\", "/")).name
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


def parse_method_target(method_arg, method_index, ast_out_dir):
    """Parse/validate a single --method Class.method argument."""
    if "." not in method_arg:
        print(f"error: --method must be Class.method, got {method_arg!r}", file=sys.stderr)
        sys.exit(1)
    cls, name = method_arg.rsplit(".", 1)
    if (cls, name) not in method_index:
        print(f"error: {method_arg} not found in {ast_out_dir}/methods.jsonl", file=sys.stderr)
        sys.exit(1)
    return cls, name


def security_relevant_targets(verdicts_path, method_index):
    """Every is_security_relevant verdict, in file order (filter_verdicts.py
    already ranked them). Returns (targets, skipped) where targets is a list of
    (class, method, verdict) that exist in methods.jsonl and skipped is the list
    of (class, method) that don't (stale verdicts)."""
    targets, skipped = [], []
    for v in load_jsonl(verdicts_path):
        if not v.get("verdict", {}).get("is_security_relevant"):
            continue
        cls, name = v["class"], v["method"]
        if (cls, name) in method_index:
            targets.append((cls, name, v["verdict"]))
        else:
            skipped.append((cls, name))
    return targets, skipped


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


def gather_fields(op_refs, ctor_only_refs, class_file_index, method_index):
    """Split referenced non-local fields into constants / error_codes / fields
    (instance state needing a constructor init line), by each field's own
    static+final modifiers -- not a name heuristic.

    `op_refs` are fields the operation (target + its helpers) actually touches;
    they may land in any bucket. `ctor_only_refs` are fields seen *only* via the
    constructor -- they are kept ONLY if they are constants (e.g. a sizing
    constant like MAX_PIN_LEN referenced by an init line). Constructor-only
    *instance* state (e.g. a `final` ResourceManager the operation never uses)
    is dropped: including it would emit an uninitialized `final` field that does
    not compile, for state the harness doesn't need."""
    constants, error_codes, fields = [], [], []
    seen = set()

    def process(owner_class, field_name, allow_instance):
        key = (owner_class, field_name)
        if key in seen:
            return
        path = class_file_index.get(owner_class)
        if path is None:
            return
        decl = find_field_declaration(path, owner_class, field_name)
        if decl is None:
            return

        is_const = "static" in decl["modifiers"] and "final" in decl["modifiers"]
        if not is_const and not allow_instance:
            return  # constructor-only instance field -- not needed by the operation
        seen.add(key)

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

    for owner_class, field_name in op_refs:
        process(owner_class, field_name, allow_instance=True)
    for owner_class, field_name in ctor_only_refs:
        process(owner_class, field_name, allow_instance=False)

    return constants, error_codes, fields


def _base_type(t):
    """Strip array/generic decoration to the bare type name (byte[] -> byte)."""
    return (t or "").split("<", 1)[0].replace("[]", "").strip()


def suggested_mode(target, symbol_table):
    """Heuristic for which harness mode fits this target (the LLM may override):

    - "inline-core": the method body is copied verbatim into the FuzzApplet and
      the wrapper calls it. Right for applet-level entry methods (they bundle
      removable APDU/secure-channel/lifecycle setup) and for static methods.
    - "invoke-instance": the wrapper constructs a REAL receiver (and argument
      objects) and calls the real method on it -- no body copy. Right for an
      instance method of a normal (non-applet) class, whose body relies on
      `this`/private state and so cannot be lifted into the applet.
    """
    if "static" in target.get("modifiers", []):
        return "inline-core"
    # Walk the extends chain: a method on the applet class itself is inline-core.
    cur, seen = target["class"], set()
    while cur and cur not in seen:
        seen.add(cur)
        ext = (symbol_table.get(cur) or {}).get("extends")
        if ext and _base_type(ext).endswith("Applet"):
            return "inline-core"
        cur = _base_type(ext) if ext else None
    return "invoke-instance"


def build_construction_api(target, symbol_table, max_classes=12):
    """Public constructor + method SIGNATURES (no bodies) of the classes an
    invoke-instance wrapper must build/serialize: the target's owning class, its
    parameter/return types that are project classes, and -- transitively -- the
    project classes appearing in those constructors' parameters (e.g. the
    ResourceManager an `Integer(byte[],off,len,rm)` needs). This is what lets the
    LLM write `new Integer(buffer, off, len, rm)` / `a.toByteArray(...)` instead
    of guessing the API. Bodies and private members are deliberately excluded."""
    seed = [target["class"]]
    for p in target.get("params", []):
        seed.append(_base_type(p["type"]))
    seed.append(_base_type(target.get("return_type")))

    api, queue, visited = {}, list(dict.fromkeys(seed)), set()
    while queue and len(api) < max_classes:
        cls = queue.pop(0)
        if cls in visited or cls not in symbol_table:
            continue
        visited.add(cls)
        entry = symbol_table[cls]
        ctors, methods = [], []
        for name, overloads in (entry.get("methods") or {}).items():
            for o in overloads:
                if "public" not in (o.get("modifiers") or []):
                    continue
                param_types = [t for _, t in o.get("params", [])]
                params = ", ".join(param_types)
                if name == "<init>":
                    ctors.append(f"{cls}({params})")
                    # follow constructor dependency types (e.g. ResourceManager)
                    for t in param_types:
                        bt = _base_type(t)
                        if bt in symbol_table and bt not in visited:
                            queue.append(bt)
                else:
                    static = "static " if "static" in (o.get("modifiers") or []) else ""
                    methods.append(f"{static}{o.get('return_type') or 'void'} {name}({params})")
        api[cls] = {
            "package": (entry.get("package") or ""),
            "constructors": sorted(set(ctors)),
            "methods": sorted(set(methods)),
        }
    return api


def build_context(target_class, target_method, verdict_hint,
                  method_index, class_file_index, symbol_table, ins_byte):
    """Assemble the full context.json dict for one target method."""
    def package_of(class_name):
        return (symbol_table.get(class_name) or {}).get("package", "") or ""

    target = method_index[(target_class, target_method)]
    target_package = package_of(target_class)

    helper_keys = [tuple(k.rsplit(".", 1)) for k in target.get("transitive_calls", [])]
    helpers = [method_index[k] for k in helper_keys if k in method_index]

    # Classes (other than the target's own) that own a called helper method. The
    # harness imports these rather than copying them; assemble_harness.py emits an
    # import for any whose package differs from the harness package.
    helper_classes = sorted({h["class"] for h in helpers} - {target_class})
    helper_imports = [
        {"class": c, "package": package_of(c),
         "fqn": f"{package_of(c)}.{c}" if package_of(c) else c}
        for c in helper_classes
    ]

    constructor = method_index.get((target_class, "<init>"))

    # Fields the operation actually touches (target + its helpers) -- these may be
    # real instance state the wrapper must set up, so they land in any bucket.
    op_field_refs = [(f["owner_class"], f["field"]) for f in target.get("field_dataflow", [])]
    for h in helpers:
        op_field_refs.extend((f["owner_class"], f["field"]) for f in h.get("field_dataflow", []))

    # Fields seen only via the constructor. A field's init line (e.g.
    # `referencePin = new byte[MAX_PIN_LEN];`) can reference a sizing CONSTANT the
    # operation body never touches directly -- gather_fields keeps those constants
    # but drops constructor-only instance state (which the operation doesn't need
    # and would otherwise emit as an uninitialized `final` field).
    ctor_field_refs = []
    if constructor:
        ctor_field_refs = [(f["owner_class"], f["field"]) for f in constructor.get("field_dataflow", [])]

    constants, error_codes, fields = gather_fields(
        op_field_refs, ctor_field_refs, class_file_index, method_index)

    return {
        "target": target,
        "target_package": target_package,
        "suggested_mode": suggested_mode(target, symbol_table),
        "construction_api": build_construction_api(target, symbol_table),
        "constructor": constructor,
        "helpers": helpers,
        "helper_imports": helper_imports,
        "constants": constants,
        "error_codes": error_codes,
        "fields": fields,
        "ins_byte": ins_byte,
        "verdict_hint": verdict_hint,
    }


def summarize(cls, name, ctx, prefix=""):
    print(f"{prefix}{cls}.{name} (package {ctx['target_package'] or '(default)'}): "
          f"{len(ctx['helpers'])} helper methods, {len(ctx['helper_imports'])} helper classes, "
          f"{len(ctx['fields'])} fields, {len(ctx['constants'])} constants, "
          f"{len(ctx['error_codes'])} error codes", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src_dir", type=Path, help="original applet source directory (for re-reading field declarations)")
    ap.add_argument("ast_out_dir", type=Path, help="ast_symtab output dir (methods.jsonl, symbol_table.json)")
    ap.add_argument("--method", default=None, help="single Class.method to extract (mutually exclusive with --verdicts)")
    ap.add_argument("--verdicts", type=Path, default=None,
                     help="verdicts.jsonl (e.g. filter_verdicts.py output); extract EVERY "
                          "is_security_relevant method, one context per method")
    ap.add_argument("--ins", default=None,
                    help="INS byte, e.g. 0x10 (default 0x10; each applet ignores INS -- no dispatch -- "
                         "so the same value is fine for every method)")
    ap.add_argument("-o", "--output", type=Path, default=Path("context.json"),
                    help="output context.json: a single context object for --method, or a JSON "
                         "list of per-method context objects for --verdicts")
    args = ap.parse_args()

    if bool(args.method) == bool(args.verdicts):
        print("error: pass exactly one of --method Class.method or --verdicts verdicts.jsonl", file=sys.stderr)
        sys.exit(1)

    methods = load_jsonl(args.ast_out_dir / "methods.jsonl")
    method_index = build_method_index(methods)
    class_file_index = build_class_file_index(methods, args.src_dir)

    # symbol_table.json gives each class's package -- used to build import
    # statements for helper classes (the harness references them; it does not
    # reproduce them, since it compiles inside the applet's own source tree).
    symbol_table = {}
    st_path = args.ast_out_dir / "symbol_table.json"
    if st_path.is_file():
        symbol_table = json.loads(st_path.read_text(encoding="utf-8"))
    else:
        print(f"WARN: {st_path} not found; helper imports may be incomplete", file=sys.stderr)

    ins_byte = args.ins or "0x10"

    args.output.parent.mkdir(parents=True, exist_ok=True)

    if args.method:
        cls, name = parse_method_target(args.method, method_index, args.ast_out_dir)
        ctx = build_context(cls, name, None, method_index, class_file_index, symbol_table, ins_byte)
        args.output.write_text(json.dumps(ctx, indent=2), encoding="utf-8")
        print("target: ", end="", file=sys.stderr)
        summarize(cls, name, ctx)
        print(f"wrote {args.output}", file=sys.stderr)
        return

    # --verdicts: ALL is_security_relevant methods, carried in the one output file
    # as a JSON list (each/each: the harness stage builds an applet+driver per
    # element). llm_extract_operation.py reads the list and emits one operation
    # per element.
    targets, skipped = security_relevant_targets(args.verdicts, method_index)
    if not targets:
        print(f"error: no is_security_relevant=true entry (resolvable in methods.jsonl) "
              f"found in {args.verdicts}", file=sys.stderr)
        sys.exit(1)

    print(f"{len(targets)} security-relevant method(s):", file=sys.stderr)
    contexts = []
    for cls, name, verdict in targets:
        ctx = build_context(cls, name, verdict, method_index, class_file_index, symbol_table, ins_byte)
        contexts.append(ctx)
        summarize(cls, name, ctx, prefix="  ")
    for cls, name in skipped:
        print(f"  SKIP {cls}.{name}: not found in methods.jsonl (stale verdicts?)", file=sys.stderr)

    args.output.write_text(json.dumps(contexts, indent=2), encoding="utf-8")
    print(f"wrote {len(contexts)} method context(s) to {args.output}"
          + (f"; skipped {len(skipped)} stale" if skipped else ""), file=sys.stderr)


if __name__ == "__main__":
    main()
