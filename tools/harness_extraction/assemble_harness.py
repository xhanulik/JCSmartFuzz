#!/usr/bin/env python3
"""
Stage 3c (deterministic): fills every {{GENERATED: ...}} marker in
skeletons/FuzzAppletSkeleton.java and skeletons/FuzzDriverSkeleton.java
from context.json (extract_context.py) + operation.json
(llm_extract_operation.py) -- pure string substitution, no LLM call. Also
copies the helper-class files context.json recorded verbatim into the
output package, and does a final syntactic verification pass.

Usage:
    py assemble_harness.py context.json operation.json
        --package fixture --class-name FuzzAppletVerifyPin
        -o generated/VerifyPin/
"""
import argparse
import json
import sys
from pathlib import Path

import javalang

SKELETONS_DIR = Path(__file__).resolve().parent.parent.parent / "skeletons"

# Imports already present in the skeleton -- don't duplicate these if the
# original applet also imports them.
BASE_APPLET_IMPORTS = {
    "edu.cmu.sv.kelinci.Kelinci",
    "edu.cmu.sv.kelinci.Mem",
    "javacard.framework.APDU",
    "javacard.framework.ISO7816",
    "javacard.framework.ISOException",
    "javacard.framework.JCSystem",
    "javacard.framework.Util",
}


def indent(text, prefix="    "):
    return "\n".join(prefix + line if line.strip() else line for line in text.splitlines())


def resolve_source_file(src_dir, recorded_path):
    name = Path(recorded_path).name
    matches = list(Path(src_dir).rglob(name)) if src_dir else []
    return str(matches[0]) if matches else recorded_path


def collect_extra_imports(target_file):
    """Union in the original applet file's own imports (a safe superset of what
    field/core/wrapper code might reference), skipping ones already fixed in
    the skeleton."""
    try:
        text = Path(target_file).read_text(encoding="utf-8", errors="replace")
        tree = javalang.parse.parse(text)
    except (OSError, javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
        print(f"WARN: could not re-parse {target_file} for imports: {e}", file=sys.stderr)
        return []
    extra = []
    for imp in tree.imports:
        if imp.path not in BASE_APPLET_IMPORTS and imp.path not in extra:
            extra.append(imp.path)
    return extra


def build_core_javadoc(context, operation):
    core = operation["core_method"]
    target = context["target"]
    removals = "\n".join(
        f" *   - lines {r['start_line']}-{r['end_line']}: {r['category']} -- {r['description']}"
        for r in core["removed_lines"]
    ) or " *   (none)"
    field_mapping = ", ".join(core["field_mapping"]) or "(none)"
    precondition = core["precondition"] or "(none)"
    start = target.get("start_line") or "?"
    return f"""/**
 * SOURCE: {Path(target['file']).name}, {target['method']}(), starting at line {start}
 * TIMING RISK: {operation['timing_risk']}
 * ALLOWED REMOVALS:
{removals}
 * FIELD MAPPING: {field_mapping}
 * PRECONDITION: {precondition}
 */"""


def fill_applet(template, context, operation, package, class_name):
    ins_name = operation["ins_name"]
    ins_byte = context["ins_byte"]
    core = operation["core_method"]
    wrapper = operation["wrapper_method"]

    extra_imports = collect_extra_imports(context["target"]["file"])
    imports_block = "\n".join(f"import {i};" for i in extra_imports)

    ins_constants_block = f"private final static byte {ins_name} = (byte) {ins_byte};"

    constants_block = "\n".join(c["declaration"] for c in context["constants"]) or "// (none)"
    error_codes_block = "\n".join(e["declaration"] for e in context["error_codes"]) or "// (none)"
    fields_block = "\n".join(f["declaration"] for f in context["fields"]) or "// (none)"

    init_lines = []
    for f in context["fields"]:
        if f["init_line"]:
            init_lines.append(f["init_line"])
        else:
            init_lines.append(f"// TODO: no constructor init found for '{f['name']}' -- review manually")
    field_init_block = "\n".join(init_lines) or "// (none)"

    dispatcher_entry = f"case {ins_name}: return {wrapper['name']}(apdu, buffer);"
    core_javadoc = build_core_javadoc(context, operation)

    out = template
    out = out.replace("package /* GENERATED: set package name */;", f"package {package};")
    out = out.replace(
        "/* GENERATED: add imports required by core methods (javacard.security.*, javacardx.crypto.*, etc.) */",
        imports_block)
    out = out.replace(
        "public class /* GENERATED: set class name */ extends javacard.framework.Applet {",
        f"public class {class_name} extends javacard.framework.Applet {{")
    out = out.replace("// {{GENERATED: INS constants go here}}", indent(ins_constants_block))
    out = out.replace("// {{GENERATED: applet-specific constants go here}}", indent(constants_block))
    out = out.replace("// {{GENERATED: error codes go here}}", indent(error_codes_block))
    out = out.replace("// {{GENERATED: field declarations go here}}", indent(fields_block))
    out = out.replace(
        "private /* GENERATED: class name */(byte[] bArray, short bOffset, byte bLength) {",
        f"private {class_name}(byte[] bArray, short bOffset, byte bLength) {{")
    out = out.replace("// {{GENERATED: field initialization goes here}}", indent(field_init_block, "        "))
    out = out.replace(
        "new /* GENERATED: class name */(bArray, bOffset, bLength);",
        f"new {class_name}(bArray, bOffset, bLength);")
    out = out.replace("// {{GENERATED: case entries go here}}", indent(dispatcher_entry, "            "))
    out = out.replace("// {{GENERATED: wrapXxx() methods go here}}", wrapper["code"])
    out = out.replace("// {{GENERATED: coreXxx() methods go here}}", f"{core_javadoc}\n{core['code']}")
    return out


def fill_driver(template, context, operation, package, class_name, driver_class_name):
    out = template
    out = out.replace(
        "// {{GENERATED: import of applet class goes here}}",
        f"import {package}.{class_name};")
    out = out.replace(
        "public class FuzzDriverSkeleton {",
        f"public class {driver_class_name} {{")
    out = out.replace(
        'private static final byte FUZZ_INS = (byte) 0x00; // {{GENERATED: INS byte of operation under test}}',
        f'private static final byte FUZZ_INS = {context["ins_byte"]}; // {operation["ins_name"]}')
    out = out.replace(
        "AID appletAID = AIDUtil.create(\"DifFuzzApplet\".getBytes());",
        f'AID appletAID = AIDUtil.create("{class_name}".getBytes());')
    out = out.replace(
        "simulator.installApplet(appletAID, DifFuzzApplet.class);",
        f"simulator.installApplet(appletAID, {class_name}.class);")
    out = out.replace(
        "private static final int MAX_DATA = 64; // {{GENERATED: adjust per target}}",
        "private static final int MAX_DATA = 64; // default -- adjust to the operation's max data size if needed")
    return out


def copy_helper_classes(context, package, out_dir):
    copied = []
    for h in context["helper_classes"]:
        src_path = Path(h["file"])
        if not src_path.exists():
            print(f"WARN: helper class file not found, skipping: {src_path}", file=sys.stderr)
            continue
        text = src_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("package ") and stripped.endswith(";"):
                lines[i] = f"package {package};"
                break
        dest = out_dir / src_path.name
        dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        copied.append(str(dest))
    return copied


def verify_java_files(paths):
    problems = []
    for path in paths:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        if "{{GENERATED" in text or "/* GENERATED:" in text:
            problems.append(f"{path}: unresolved GENERATED marker remains")
            continue
        try:
            javalang.parse.parse(text)
        except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError) as e:
            problems.append(f"{path}: does not parse as valid Java: {e}")
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("context_json", type=Path)
    ap.add_argument("operation_json", type=Path)
    ap.add_argument("--package", required=True)
    ap.add_argument("--class-name", default=None, help="default: FuzzApplet<OperationName>")
    ap.add_argument("--driver-class-name", default=None, help="default: FuzzDriver<OperationName>")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    context = json.loads(args.context_json.read_text(encoding="utf-8"))
    operation = json.loads(args.operation_json.read_text(encoding="utf-8"))

    class_name = args.class_name or f"FuzzApplet{operation['operation_name']}"
    driver_class_name = args.driver_class_name or f"FuzzDriver{operation['operation_name']}"
    args.output.mkdir(parents=True, exist_ok=True)

    applet_template = (SKELETONS_DIR / "FuzzAppletSkeleton.java").read_text(encoding="utf-8")
    driver_template = (SKELETONS_DIR / "FuzzDriverSkeleton.java").read_text(encoding="utf-8")

    applet_out = fill_applet(applet_template, context, operation, args.package, class_name)
    driver_out = fill_driver(driver_template, context, operation, args.package, class_name, driver_class_name)

    applet_path = args.output / f"{class_name}.java"
    driver_path = args.output / f"{driver_class_name}.java"
    applet_path.write_text(applet_out, encoding="utf-8")
    driver_path.write_text(driver_out, encoding="utf-8")

    copied = copy_helper_classes(context, args.package, args.output)

    all_paths = [applet_path, driver_path] + [Path(p) for p in copied]
    problems = verify_java_files(all_paths)

    print(f"wrote {applet_path}", file=sys.stderr)
    print(f"wrote {driver_path}", file=sys.stderr)
    for c in copied:
        print(f"copied helper class {c}", file=sys.stderr)

    if problems:
        print("\nVERIFICATION FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(1)

    print(f"\nverification OK: {len(all_paths)} file(s) parse cleanly, no unresolved GENERATED markers",
          file=sys.stderr)


if __name__ == "__main__":
    main()
