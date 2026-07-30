#!/usr/bin/env python3
"""Generate fuzzing harnesses for one corpus repo, ready for the fuzz_build step.

Thin orchestrator: it glues together the existing `pipeline/` scripts (nothing
is reimplemented) for a single repository chosen from corpus/dataset.json, and
stops right before compilation (automation/fuzz_build/build_target.py).

Flow (mirrors flow.md; each step shells out to a pipeline/ script):
  1. look up --entry in the corpus, clone its repo (reusing build_target)
  2. analyze/ast_symtab/extract.py            -> ast_out/
  3. analyze/candidate_narrowing/prefilter_rank_candidates.py -> candidates.jsonl
  4. analyze/candidate_narrowing/llm_final_verdict.py --candidates -> verdicts.jsonl   (LLM)
  5. COUNT BRANCH on --count/-n desired methods:
       - enough security-relevant verdicts  -> filter_verdicts.py -n N
       - not enough                         -> re-verdict ALL methods with the LLM
                                               (no pre-filter), then filter_verdicts.py -n N
  6. harness/harness_extraction/extract_context.py --verdicts   -> context.json (list)
  7. harness/harness_extraction/llm_extract_operation.py        -> operation.json (list)  (LLM)
  8. harness/harness_extraction/assemble_harness.py             -> generated/<Class>.<method>/
  9. print the per-method build_target command (the fuzz_build hand-off)

The LLM steps run automatically as subprocesses; export LLM_API_TOKEN first
(or use --mock to smoke-test the wiring with a canned local responder).

Usage:
    export LLM_API_TOKEN=...
    python3 generate_harnesses.py --entry "JCMathLib" -n 5
    python3 generate_harnesses.py --entry "JCMathLib" -n 5 --dry-run   # print the plan only
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

# Reuse the corpus lookup + clone from the build stage (importable: its real work
# is guarded by `if __name__ == "__main__"`).
sys.path.insert(0, str(REPO_ROOT / "automation" / "fuzz_build"))
import build_target  # noqa: E402  (find_entry, clone, DATASET)

# pipeline/ scripts we glue together (only steps from pipeline/).
PIPE = REPO_ROOT / "pipeline"
AST_SYMTAB = PIPE / "analyze" / "ast_symtab" / "extract.py"
PREFILTER = PIPE / "analyze" / "candidate_narrowing" / "prefilter_rank_candidates.py"
VERDICT = PIPE / "analyze" / "candidate_narrowing" / "llm_final_verdict.py"
FILTER = PIPE / "analyze" / "candidate_narrowing" / "filter_verdicts.py"
EXTRACT_CONTEXT = PIPE / "harness" / "harness_extraction" / "extract_context.py"
LLM_OPERATION = PIPE / "harness" / "harness_extraction" / "llm_extract_operation.py"
ASSEMBLE = PIPE / "harness" / "harness_extraction" / "assemble_harness.py"
BUILD_TARGET = REPO_ROOT / "automation" / "fuzz_build" / "build_target.py"


def repo_slug(build):
    """Same repo directory name build_target.clone() derives, for a matching out dir."""
    return re.sub(r"[^\w.-]", "_", build["repo_url"].rstrip("/").split("/")[-1].removesuffix(".git"))


def resolve_src(clone_dest, source_roots):
    """ast_symtab/extract_context take ONE source dir; corpus source_roots may be a
    list. Use it directly when there is one, else the common ancestor (with a warning)."""
    if len(source_roots) == 1:
        return clone_dest / source_roots[0]
    common = os.path.commonpath(source_roots)
    print(f"WARN: {len(source_roots)} source roots {source_roots}; ast_symtab takes one dir "
          f"-> using common ancestor {common!r}", file=sys.stderr)
    return clone_dest / common


def run(script, script_args, dry):
    """Run one pipeline step (or just print it in --dry-run). Subprocesses inherit
    the environment, so LLM_API_TOKEN reaches the LLM steps."""
    cmd = [sys.executable, str(script), *[str(a) for a in script_args]]
    print("  $ " + " ".join(cmd))
    if dry:
        return
    if subprocess.run(cmd).returncode != 0:
        sys.exit(f"error: step {Path(script).name} failed; aborting")


def count_security_relevant(verdicts_path):
    n = 0
    for line in verdicts_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and json.loads(line).get("verdict", {}).get("is_security_relevant") is True:
            n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--entry", required=True, help="corpus entry name or link substring (as in build_target)")
    ap.add_argument("-n", "--count", type=int, default=5, help="desired number of harnesses (default 5)")
    ap.add_argument("--out", type=Path, default=None,
                    help="artifacts dir (default ./harness-out/<repo>/); holds ast_out/, *.jsonl, "
                         "context.json, operation.json, generated/")
    ap.add_argument("--work", type=Path, default=Path.home() / ".cache" / "jcsmartscan-builds",
                    help="clone cache (default matches build_target, so the clone is reused at build time)")
    ap.add_argument("--ins", default=None, help="INS byte passed to extract_context (default 0x10)")
    ap.add_argument("--mock", action="store_true", help="pass --mock to the LLM steps (no token/network)")
    ap.add_argument("--dry-run", action="store_true", help="print the ordered command plan and exit")
    args = ap.parse_args()

    data = json.loads(build_target.DATASET.read_text(encoding="utf-8"))
    entry = build_target.find_entry(data, args.entry)
    build = entry.get("fuzz_build")
    if not build:
        sys.exit(f"error: entry {entry['name']!r} has no fuzz_build metadata (run discover_builds.py)")
    if not build.get("buildable"):
        sys.exit(f"error: {entry['name']!r} is not buildable: {build.get('reason')}")

    slug = repo_slug(build)
    out = args.out or (Path.cwd() / "harness-out" / slug)
    mockf = ["--mock"] if args.mock else []

    print(f"entry:        {entry['name']}")
    print(f"repo:         {build['repo_url']} @ {build.get('git_ref')}")
    print(f"source_roots: {build['source_roots']}")
    print(f"target count: {args.count}")
    print(f"out:          {out}")
    print(f"LLM:          {'--mock (canned)' if args.mock else 'live (LLM_API_TOKEN from env)'}\n")

    # 1. clone (predicted path in --dry-run) + resolve the single source dir
    clone_dest = (args.work / slug) if args.dry_run else build_target.clone(build, args.work)
    src_dir = resolve_src(clone_dest, build["source_roots"])
    if not args.dry_run:
        out.mkdir(parents=True, exist_ok=True)

    ast_out = out / "ast_out"
    methods = ast_out / "methods.jsonl"
    candidates = out / "candidates.jsonl"
    verdicts = out / "verdicts.jsonl"
    verdicts_all = out / "verdicts_all.jsonl"
    filtered = out / "filtered_verdicts.jsonl"
    context = out / "context.json"
    operation = out / "operation.json"
    generated = out / "generated"

    # 2-4. analyze
    print("[analyze] ast_symtab -> prefilter -> LLM verdict")
    run(AST_SYMTAB, [src_dir, "-o", ast_out], args.dry_run)
    run(PREFILTER, [methods, "-o", candidates], args.dry_run)
    run(VERDICT, [methods, "--candidates", candidates, "-o", verdicts, *mockf], args.dry_run)

    # 5. count branch
    print(f"\n[narrow] keep top {args.count} security-relevant methods")
    if args.dry_run:
        print(f"  # count is_security_relevant in {verdicts.name}:")
        print(f"  #   >= {args.count}: filter that; else re-verdict ALL methods (no prefilter) and filter that")
        run(VERDICT, [methods, "-o", verdicts_all, *mockf], args.dry_run)  # shown as the fallback
        run(FILTER, [verdicts_all, "-n", args.count, "-o", filtered], args.dry_run)
    else:
        n_sr = count_security_relevant(verdicts)
        if n_sr >= args.count:
            print(f"  {n_sr} security-relevant from pre-filter+LLM (>= {args.count}); filtering those")
            run(FILTER, [verdicts, "-n", args.count, "-o", filtered], args.dry_run)
        else:
            print(f"  only {n_sr} security-relevant from pre-filter+LLM (< {args.count}); "
                  f"re-verdicting ALL methods with the LLM (no pre-filter)")
            run(VERDICT, [methods, "-o", verdicts_all, *mockf], args.dry_run)
            run(FILTER, [verdicts_all, "-n", args.count, "-o", filtered], args.dry_run)

    # A run may legitimately end up with 0 (or fewer than N) security-relevant
    # methods; report that cleanly instead of letting extract_context abort on an
    # empty --verdicts file.
    if not args.dry_run:
        n_kept = sum(1 for l in filtered.read_text(encoding="utf-8").splitlines() if l.strip())
        if n_kept == 0:
            print("\n[done] no security-relevant methods to harness "
                  "(even after the all-methods LLM pass). Nothing generated.")
            return
        if n_kept < args.count:
            print(f"  note: only {n_kept} security-relevant method(s) available (< requested {args.count})")

    # 6-8. harness
    print("\n[harness] extract_context -> LLM operation -> assemble")
    ec = [src_dir, ast_out, "--verdicts", filtered, "-o", context]
    if args.ins:
        ec += ["--ins", args.ins]
    run(EXTRACT_CONTEXT, ec, args.dry_run)
    run(LLM_OPERATION, [context, "-o", operation, *mockf], args.dry_run)
    run(ASSEMBLE, [context, operation, "-o", generated], args.dry_run)

    # 9. hand-off to fuzz_build
    print("\n[done] harnesses ready for fuzz_build:")
    if args.dry_run:
        print(f"  (each generated/<Class>.<method>/ ->)")
        print(f'  python3 {BUILD_TARGET} --entry "{args.entry}" --harness-out {generated}/<Class>.<method>/')
        return

    made = sorted(d for d in generated.iterdir() if d.is_dir() and any(d.glob("FuzzApplet*.java"))) \
        if generated.exists() else []
    print(f"  {len(made)} harness(es) generated (requested {args.count}):")
    for d in made:
        print(f"    - {d.name}")
    if len(made) < args.count:
        print(f"  NOTE: produced {len(made)} < requested {args.count} -- not enough security-relevant "
              f"methods, or some failed the extraction gate (see {operation.with_name('operation_errors.json')})")
    print("\n  build (per method):")
    for d in made:
        print(f'    python3 {BUILD_TARGET} --entry "{args.entry}" --harness-out {d}')


if __name__ == "__main__":
    main()
