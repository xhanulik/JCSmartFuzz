#!/usr/bin/env python3
"""Fill skeletons/ProfileAppletSkeleton.java with the extracted core + wrapper
methods and context -- the profiling counterpart of
harness_extraction/assemble_harness.py.

It reuses the harness-extraction data (context.json from extract_context.py +
operation.json from llm_extract_operation.py) and assemble_harness.py's own
substitution logic: the ProfileApplet skeleton carries the exact same
{{GENERATED}} markers as the FuzzApplet skeleton, so `fill_applet` works on it
unchanged. The only difference is the fixed Layer-1 framing (single invocation
vs dual), which is baked into the skeleton, not the generated code.

Usage:
    py assemble_profile.py context.json operation.json [--package P] [--class-name N] -o generated/
"""
import argparse
import json
import sys
from pathlib import Path

# reuse the harness-extraction assembler (fill_applet, verify_java_files, SKELETONS_DIR)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "harness_extraction"))
import assemble_harness as ah


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("context_json", type=Path)
    ap.add_argument("operation_json", type=Path)
    ap.add_argument("--package", default=None,
                    help="applet package (default: the target applet's own package)")
    ap.add_argument("--class-name", default=None, help="default: ProfileApplet<OperationName>")
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()

    context = json.loads(args.context_json.read_text(encoding="utf-8"))
    operation = json.loads(args.operation_json.read_text(encoding="utf-8"))

    package = args.package or context.get("target_package") or ""
    if not package:
        print("error: could not determine the applet package (target applet has no package "
              "and --package was not given); pass --package explicitly", file=sys.stderr)
        sys.exit(1)

    class_name = args.class_name or f"ProfileApplet{operation['operation_name']}"
    args.output.mkdir(parents=True, exist_ok=True)

    template = (ah.SKELETONS_DIR / "ProfileAppletSkeleton.java").read_text(encoding="utf-8")
    applet_out = ah.fill_applet(template, context, operation, package, class_name)

    applet_path = args.output / f"{class_name}.java"
    applet_path.write_text(applet_out, encoding="utf-8")
    print(f"wrote {applet_path}", file=sys.stderr)
    print(f"package {package}; drop into the applet source tree to compile "
          f"(helper classes referenced by import, not copied)", file=sys.stderr)

    problems = ah.verify_java_files([applet_path])
    if problems:
        print("\nVERIFICATION FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(1)
    print("\nverification OK: parses cleanly, no unresolved GENERATED markers", file=sys.stderr)


if __name__ == "__main__":
    main()
