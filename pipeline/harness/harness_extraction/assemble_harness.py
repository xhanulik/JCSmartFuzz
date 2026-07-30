#!/usr/bin/env python3
"""
Stage 3c (deterministic): fills every {{GENERATED: ...}} marker in
skeletons/FuzzAppletSkeleton.java and skeletons/FuzzDriverSkeleton.java
from context.json (extract_context.py) + operation.json
(llm_extract_operation.py) -- pure string substitution, no LLM call.

The harness is meant to be dropped into the applet's own source directory and
compiled there, so helper classes are NOT copied or reproduced: the core
method calls them as-is and this script adds an import for any helper class
whose package differs from the harness package. Ends with a syntactic
verification pass.

context.json / operation.json match whatever the earlier stages wrote:
  - single objects (extract_context.py --method) -> one FuzzApplet/FuzzDriver
    pair written directly into -o.
  - JSON lists (extract_context.py --verdicts, several methods) -> one pair per
    method, paired by the operation's {class, method} target, each written into
    its own -o/<Class>.<method>/ sub-directory. (--class-name/--driver-class-name
    can't be used with lists -- the defaults FuzzApplet<Op>/FuzzDriver<Op> are.)

Usage:
    py assemble_harness.py context.json operation.json --package fixture -o generated/
    py assemble_harness.py context.json operation.json --package fixture \
        --class-name FuzzAppletVerifyPin -o generated/VerifyPin/   # single only
"""
import argparse
import json
import sys
from pathlib import Path

import javalang

# Reuse the shared MAX_DATA resolver so the driver's MAX_DATA constant matches
# the fuzz-input size the seed generator produces (both derive it from the
# operation's wrapper via the same helper + default).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "drivergen"))
try:
    from generate_drivers import resolve_max_data
except Exception:  # pragma: no cover -- drivergen ships alongside; fall back to the shared default
    def resolve_max_data(operation, default=64):
        return default


def _find_skeletons_dir():
    """Walk up from this file until a sibling ``skeletons/`` dir is found
    (repo root), so the lookup survives moving this script around the tree."""
    for base in Path(__file__).resolve().parents:
        candidate = base / "skeletons"
        if candidate.is_dir():
            return candidate
    raise FileNotFoundError("could not locate the repo-root 'skeletons/' directory")


SKELETONS_DIR = _find_skeletons_dir()

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
        if imp.path in BASE_APPLET_IMPORTS:
            continue
        # Preserve the exact import form: `static` prefix and the `.*` wildcard
        # suffix. Without the suffix, `import javacard.security.*` collapses to
        # the invalid `import javacard.security`.
        rendered = ("static " if imp.static else "") + imp.path + (".*" if imp.wildcard else "")
        if rendered not in extra:
            extra.append(rendered)
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
    # invoke-instance: the wrapper builds a real receiver and calls the real
    # method -- there is NO copied core, and the applet declares NO fields/
    # constants (those belong to the constructed object, not the harness).
    invoke_instance = operation.get("mode") == "invoke-instance"
    core = operation.get("core_method")
    wrapper = operation["wrapper_method"]

    # Imports: the original applet's own imports (a safe superset for the
    # field/core/wrapper code), plus an import for every helper class the core
    # calls that lives in a DIFFERENT package than this harness (same-package
    # helpers need none; both compile together in the applet source tree).
    extra_imports = collect_extra_imports(context["target"]["file"])
    for h in context.get("helper_imports", []):
        fqn, pkg = h.get("fqn"), h.get("package")
        if pkg and pkg != package and fqn not in extra_imports and fqn not in BASE_APPLET_IMPORTS:
            extra_imports.append(fqn)
    if invoke_instance:
        # the wrapper constructs these classes; import any in another package.
        for cls, info in (context.get("construction_api") or {}).items():
            pkg = info.get("package")
            fqn = f"{pkg}.{cls}" if pkg else cls
            if pkg and pkg != package and fqn not in extra_imports and fqn not in BASE_APPLET_IMPORTS:
                extra_imports.append(fqn)
    imports_block = "\n".join(f"import {i};" for i in extra_imports)

    if invoke_instance:
        constants_block = error_codes_block = fields_block = "// (none)"
        field_init_block = "// (none)"
    else:
        constants_block = "\n".join(c["declaration"] for c in context["constants"]) or "// (none)"
        error_codes_block = "\n".join(e["declaration"] for e in context["error_codes"]) or "// (none)"
        fields_block = "\n".join(f["declaration"] for f in context["fields"]) or "// (none)"

        init_lines = []
        for f in context["fields"]:
            if f["init_line"]:
                init_lines.append(f["init_line"])
            elif "=" in f["declaration"]:
                # field is initialized inline in its own declaration -- no constructor
                # assignment needed, so don't emit a misleading TODO
                continue
            else:
                init_lines.append(f"// TODO: no constructor init found for '{f['name']}' -- review manually")
        field_init_block = "\n".join(init_lines) or "// (none)"

    out = template
    out = out.replace("package /* GENERATED: set package name */;", f"package {package};")
    out = out.replace(
        "/* GENERATED: add imports required by core methods (javacard.security.*, javacardx.crypto.*, etc.) */",
        imports_block)
    out = out.replace(
        "public class /* GENERATED: set class name */ extends javacard.framework.Applet {",
        f"public class {class_name} extends javacard.framework.Applet {{")
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
    # The skeleton's process() calls the wrapper by the fixed name `wrapOperation`
    # (each applet fuzzes one operation, so there is no INS dispatch). The prompt
    # + validation gate make llm_extract_operation.py emit exactly that name;
    # rename defensively so a legacy/differently-named operation.json still wires up.
    wrapper_code = wrapper["code"]
    if wrapper.get("name") and wrapper["name"] != "wrapOperation":
        wrapper_code = wrapper_code.replace(wrapper["name"], "wrapOperation")
    out = out.replace("// {{GENERATED: wrapXxx() methods go here}}", wrapper_code)

    if invoke_instance:
        core_block = ("// (invoke-instance mode: no core copy -- wrapOperation() calls the real "
                      f"{context['target']['class']}.{context['target']['method']}() on a constructed object)")
    else:
        core_block = f"{build_core_javadoc(context, operation)}\n{core['code']}"
    out = out.replace("// {{GENERATED: coreXxx() methods go here}}", core_block)
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
    max_data = resolve_max_data(operation)
    out = out.replace(
        "private static final int MAX_DATA = 64; // {{GENERATED: adjust per target}}",
        f"private static final int MAX_DATA = {max_data}; "
        f"// resolved from the operation's wrapper -- shared with seed generation")
    return out


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


def assemble_pair(context, operation, package_arg, class_name_arg, driver_class_name_arg, out_dir):
    """Fill + write one FuzzApplet/FuzzDriver pair into out_dir. Returns
    (package, applet_path, driver_path, problems), or (None, None, None, [error])
    if the package can't be resolved."""
    package = package_arg or context.get("target_package") or ""
    if not package:
        return None, None, None, [
            "could not determine the harness package (target applet has no package "
            "and --package was not given); pass --package explicitly"]

    class_name = class_name_arg or f"FuzzApplet{operation['operation_name']}"
    driver_class_name = driver_class_name_arg or f"FuzzDriver{operation['operation_name']}"
    out_dir.mkdir(parents=True, exist_ok=True)

    applet_template = (SKELETONS_DIR / "FuzzAppletSkeleton.java").read_text(encoding="utf-8")
    driver_template = (SKELETONS_DIR / "FuzzDriverSkeleton.java").read_text(encoding="utf-8")

    applet_out = fill_applet(applet_template, context, operation, package, class_name)
    driver_out = fill_driver(driver_template, context, operation, package, class_name, driver_class_name)

    applet_path = out_dir / f"{class_name}.java"
    driver_path = out_dir / f"{driver_class_name}.java"
    applet_path.write_text(applet_out, encoding="utf-8")
    driver_path.write_text(driver_out, encoding="utf-8")

    return package, applet_path, driver_path, verify_java_files([applet_path, driver_path])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("context_json", type=Path)
    ap.add_argument("operation_json", type=Path)
    ap.add_argument("--package", default=None,
                    help="harness package (default: the target applet's own package, so it "
                         "drops into the source tree and same-package helpers need no import)")
    ap.add_argument("--class-name", default=None, help="single input only; default: FuzzApplet<OperationName>")
    ap.add_argument("--driver-class-name", default=None, help="single input only; default: FuzzDriver<OperationName>")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    context = json.loads(args.context_json.read_text(encoding="utf-8"))
    operation = json.loads(args.operation_json.read_text(encoding="utf-8"))

    single = isinstance(context, dict) and isinstance(operation, dict)
    listmode = isinstance(context, list) and isinstance(operation, list)
    if not (single or listmode):
        print("error: context.json and operation.json must both be single objects "
              "(--method) or both be JSON lists (--verdicts) -- they must come from the "
              "same extract_context/llm_extract_operation mode", file=sys.stderr)
        sys.exit(1)

    # --- single method: one pair straight into -o (unchanged behavior) ---
    if single:
        package, applet_path, driver_path, problems = assemble_pair(
            context, operation, args.package, args.class_name, args.driver_class_name, args.output)
        if package is None:
            print(f"error: {problems[0]}", file=sys.stderr)
            sys.exit(1)
        print(f"wrote {applet_path}", file=sys.stderr)
        print(f"wrote {driver_path}", file=sys.stderr)
        print(f"package {package}; drop these into the applet source tree to compile "
              f"(helper classes referenced by import, not copied)", file=sys.stderr)
        if problems:
            print("\nVERIFICATION FAILED:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            sys.exit(1)
        print("\nverification OK: 2 file(s) parse cleanly, no unresolved GENERATED markers", file=sys.stderr)
        return

    # --- several methods: one pair per method, paired by {class, method} ---
    if args.class_name or args.driver_class_name:
        print("error: --class-name/--driver-class-name can't be used with list inputs "
              "(many methods); omit them so each pair gets FuzzApplet<Op>/FuzzDriver<Op>",
              file=sys.stderr)
        sys.exit(1)

    ctx_by_target = {(c["target"]["class"], c["target"]["method"]): c for c in context}
    n_ok = 0
    problems_total, missing = [], []
    for op in operation:
        t = op.get("target", {})
        key = (t.get("class"), t.get("method"))
        ctx = ctx_by_target.get(key)
        if ctx is None:
            print(f"SKIP {key[0]}.{key[1]}: no matching context entry", file=sys.stderr)
            missing.append(key)
            continue
        out_dir = args.output / f"{key[0]}.{key[1]}"
        package, applet_path, _driver_path, problems = assemble_pair(
            ctx, op, args.package, None, None, out_dir)
        if package is None:
            print(f"FAIL {key[0]}.{key[1]}: {problems[0]}", file=sys.stderr)
            problems_total.append(key)
            continue
        if problems:
            print(f"FAIL {key[0]}.{key[1]}:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            problems_total.append(key)
            continue
        print(f"OK {key[0]}.{key[1]} -> {applet_path.parent}/ (package {package})", file=sys.stderr)
        n_ok += 1

    n_bad = len(problems_total) + len(missing)
    print(f"\n{n_ok}/{len(operation)} harness pair(s) written under {args.output}/ "
          f"(helper classes referenced by import, not copied)"
          + (f"; {n_bad} failed/unmatched" if n_bad else ""), file=sys.stderr)
    sys.exit(1 if n_bad else 0)


if __name__ == "__main__":
    main()
