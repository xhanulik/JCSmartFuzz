#!/usr/bin/env python3
"""Print statistics about the applet corpus (corpus/dataset.json):
usable-repo counts, build-system distribution, and categories.

"Usable" = compilable into differential-fuzzing .class files, i.e. its `fuzz_build`
object (populated by automation/fuzz_build/discover_builds.py) has
`buildable: true`. Repos without a `fuzz_build` object are reported as "not yet
assessed" (fuzz_build is populated for the Java build systems:
build_systems javac/Ant/Gradle/Maven).

Usage:
    python3 corpus_stats.py [--json]
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DATASET = Path(__file__).resolve().parents[2] / "corpus" / "dataset.json"
BASE_LIBS = {"jcardsim", "kelinci", "bouncycastle"}


def pct(n, total):
    return f"{100 * n / total:4.1f}%" if total else "  0.0%"


def print_dist(title, counter, total, width=28):
    print(f"\n{title}")
    for label, n in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        bar = "#" * round(30 * n / max(counter.values())) if counter else ""
        print(f"  {str(label):<{width}} {n:4d}  {pct(n, total)}  {bar}")


def compute(data):
    total = len(data)
    with_build = [e for e in data if e.get("fuzz_build")]
    usable = [e for e in with_build if e["fuzz_build"].get("buildable")]
    not_usable = [e for e in with_build if not e["fuzz_build"].get("buildable")]
    unassessed = [e for e in data if not e.get("fuzz_build")]

    # build systems: membership (combos count each token) + exact combination
    by_token = Counter(b for e in data for b in e["build_systems"])
    by_combo = Counter(" + ".join(e["build_systems"]) for e in data)

    categories = Counter(e["category"] for e in data)

    # extra libs (beyond the base three) across usable repos
    extra_libs = Counter()
    for e in usable:
        for lib in e["fuzz_build"].get("required_libs", []):
            if lib not in BASE_LIBS:
                extra_libs[lib] += 1

    # not-usable reasons
    reasons = Counter(e["fuzz_build"].get("reason", "(no reason)") for e in not_usable)

    # usable count per individual build system
    usable_by_token = Counter(b for e in usable for b in e["build_systems"])

    return {
        "total": total,
        "usable": len(usable),
        "not_usable": len(not_usable),
        "unassessed": len(unassessed),
        "build_systems_by_token": dict(by_token),
        "build_systems_by_combo": dict(by_combo),
        "categories": dict(categories),
        "extra_libs_for_usable": dict(extra_libs),
        "not_usable_reasons": dict(reasons),
        "usable_by_build_system": dict(usable_by_token),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit the stats as JSON instead of a text report")
    ap.add_argument("--dataset", type=Path, default=DATASET)
    args = ap.parse_args()

    data = json.loads(args.dataset.read_text(encoding="utf-8"))
    s = compute(data)

    if args.json:
        json.dump(s, sys.stdout, indent=2)
        print()
        return

    t = s["total"]
    print("=" * 60)
    print(f"  JCSmartFuzz corpus statistics  ({args.dataset})")
    print("=" * 60)
    print(f"\nTotal repositories: {t}")
    print(f"  usable (buildable for differential fuzzing): {s['usable']:4d}  {pct(s['usable'], t)}")
    print(f"  not usable (assessed, cannot build):         {s['not_usable']:4d}  {pct(s['not_usable'], t)}")
    print(f"  not yet assessed (no build metadata):        {s['unassessed']:4d}  {pct(s['unassessed'], t)}")

    print_dist("Build systems (by presence; combinations count each):",
               Counter(s["build_systems_by_token"]), t)
    print_dist("Build systems (exact combination):",
               Counter(s["build_systems_by_combo"]), t)
    print_dist("Categories:", Counter(s["categories"]), t, width=40)

    if s["usable_by_build_system"]:
        print_dist("Usable repos by build system:",
                   Counter(s["usable_by_build_system"]), s["usable"])
    if s["extra_libs_for_usable"]:
        print_dist("Extra libraries needed (beyond jcardsim/kelinci/bouncycastle):",
                   Counter(s["extra_libs_for_usable"]), s["usable"])
    if s["not_usable_reasons"]:
        print_dist("Not-usable reasons:", Counter(s["not_usable_reasons"]), s["not_usable"], width=52)


if __name__ == "__main__":
    main()
