#!/usr/bin/env python3
"""Parse an AFL++ output directory and report campaign metrics.

Usage:
    python parse_afl_output.py <out_dir> [--instance main] [--json]

Works with:
  * single-instance layouts (``<out_dir>/fuzzer_stats`` next to ``queue/``)
  * -M/-S layouts (``<out_dir>/main/fuzzer_stats``, etc.) --
    the instance is auto-detected, or pick one with ``--instance``.

Reads ``fuzzer_stats``, ``queue/`` filenames, ``crashes/``, ``hangs/``,
and (if present) ``path_costs.csv`` -- a custom CSV produced by this
project's instrumented AFL++ build with per-entry (time, memory,
instructions, user-defined) cost rows.

Statistics are reported for three subsets of the queue:
  1. Initial seeds    -- original corpus entries (orig: tag)
  2. All queue        -- every entry including mutations and imports
  3. Imported only    -- entries synced in from another instance (sync: tag)

Per-subset metrics:
  - Max instructions
  - Max user-defined cost
  - Zero-cost inputs  (A and B took identical paths)
  - CV = stdev / mean  (<0.1 near constant-time, 0.1-0.5 moderate, >0.5 strong)
  - Unique user-defined costs  (distinct timing paths found)

Campaign-level metrics (from fuzzer_stats):
  - cycles_done
  - max_depth
"""

import argparse
import glob
import json
import os
import re
import statistics
import sys


# --------------------------------------------------------------------- #
#  Queue filename parsing                                               #
# --------------------------------------------------------------------- #

# Queue filenames use colon between key and value:
#   id:000000,time:0,execs:0,orig:testcase0.bin          (initial seed)
#   id:000001,src:000000,time:463,execs:9,op:(null),+cov (mutated)
#   id:000022,sync:seeds_gpt-oss-1,src:llm_seed_000008   (imported)
_RE_OP     = re.compile(r",op:([^,]+)")
_RE_ORIG   = re.compile(r",orig:([^,]+)")
_RE_SYNC   = re.compile(r",sync:([^,]+)")
_RE_TIME   = re.compile(r",time:(\d+)")
_RE_EXECS  = re.compile(r",execs:(\d+)")


def _kind_from_name(name):
    """Return 'initial', 'imported', or 'mutated' for a queue entry name.

    Works on either the bare filename or a full path — the basename is used.

    Rules (checked in order):
      ,orig:  → initial   original seed corpus entry
      ,sync:  → imported  synced from another AFL++ instance (LLM seeds)
      otherwise → mutated AFL++-generated mutation
    """
    basename = os.path.basename(name)
    if _RE_ORIG.search(basename):
        return "initial"
    if _RE_SYNC.search(basename):
        return "imported"
    return "mutated"


def classify_queue_entry(name):
    """Decode an AFL++ queue filename into a structured record."""
    orig_m  = _RE_ORIG.search(name)
    sync_m  = _RE_SYNC.search(name)
    op_m    = _RE_OP.search(name)
    time_m  = _RE_TIME.search(name)
    execs_m = _RE_EXECS.search(name)

    kind = _kind_from_name(name)
    if orig_m:
        source = orig_m.group(1)
    elif sync_m:
        source = sync_m.group(1)
    else:
        source = None

    return {
        "name":          name,
        "kind":          kind,
        "source":        source,
        "op":            op_m.group(1) if op_m else None,
        "is_cov":        ",+cov" in name,
        "time_ms":       int(time_m.group(1)) if time_m else None,
        "execs_at_find": int(execs_m.group(1)) if execs_m else None,
    }


# --------------------------------------------------------------------- #
#  File readers                                                         #
# --------------------------------------------------------------------- #

def find_instance_dir(out_dir, instance=None):
    """Resolve the AFL++ instance directory."""
    if instance:
        cand = os.path.join(out_dir, instance)
        return cand if os.path.isfile(os.path.join(cand, "fuzzer_stats")) else None
    if os.path.isfile(os.path.join(out_dir, "fuzzer_stats")):
        return out_dir
    matches = glob.glob(os.path.join(out_dir, "*", "fuzzer_stats"))
    if not matches:
        return None
    if len(matches) == 1:
        return os.path.dirname(matches[0])
    for m in matches:
        if os.path.basename(os.path.dirname(m)) in ("main", "master", "m0"):
            return os.path.dirname(m)
    return os.path.dirname(matches[0])


def read_fuzzer_stats(path):
    """Parse key: value lines from fuzzer_stats into a dict."""
    stats = {}
    try:
        with open(path) as f:
            for line in f:
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                stats[k.strip()] = v.strip()
    except OSError:
        pass
    return stats


def read_path_costs(path):
    """Parse path_costs.csv. Returns [] if file missing/unparseable."""
    rows = []
    try:
        with open(path) as f:
            if not f.readline():   # skip header
                return []
            for line in f:
                parts = line.strip().split(";")
                if len(parts) < 5:
                    continue
                try:
                    rows.append({
                        "filename":     parts[0].strip(),
                        "time":         int(parts[1].strip()),
                        "memory":       int(parts[2].strip()),
                        "instructions": int(parts[3].strip()),
                        "user_defined": int(parts[4].strip()),
                    })
                except (ValueError, IndexError):
                    continue
    except OSError:
        return []
    return rows


def count_entries(path):
    """Count queue-style (``id:``-prefixed) files in a directory."""
    if not os.path.isdir(path):
        return 0
    return sum(1 for f in os.listdir(path) if f.startswith("id:"))


# --------------------------------------------------------------------- #
#  Focused statistics                                                   #
# --------------------------------------------------------------------- #

def _cv_verdict(cv):
    if cv < 0.1:
        return "near constant-time"
    if cv < 0.5:
        return "moderate variability, some timing difference but not strongly visible"
    return "HIGH — strong timing side-channel signal"


def _focused_stats(rows):
    """Compute the focused side-channel statistics for a list of path_costs rows.

    Returns None when the row list is empty.
    Each row must have keys 'instructions' and 'user_defined'.
    """
    if not rows:
        return None

    ud     = [r["user_defined"]  for r in rows]
    instr  = [r["instructions"]  for r in rows]
    n      = len(ud)
    zeros  = sum(1 for v in ud if v == 0)
    mean   = statistics.mean(ud)
    stdev  = statistics.stdev(ud) if n >= 2 else 0.0
    cv     = stdev / mean if mean > 0 else 0.0
    unique = len(set(ud))

    return {
        "count":            n,
        "max_instructions": max(instr),
        "max_user_cost":    max(ud),
        "zeros":            zeros,
        "zero_pct":         round(100.0 * zeros / n, 1),
        "cv":               round(cv, 3),
        "cv_verdict":       _cv_verdict(cv),
        "unique_costs":     unique,
        "unique_pct":       round(100.0 * unique / n, 1),
    }


# --------------------------------------------------------------------- #
#  Summarise                                                            #
# --------------------------------------------------------------------- #

FUZZER_STATS_KEYS = [
    "start_time", "last_update", "run_time",
    "execs_done", "execs_per_sec",
    "corpus_count", "corpus_found", "corpus_imported",
    "corpus_favored", "corpus_variable",
    "max_depth", "cycles_done",
    "pending_favs", "pending_total",
    "saved_crashes", "saved_hangs",
    "bitmap_cvg", "edges_found",
    "last_find", "last_crash", "last_hang",
    "afl_version", "target_mode", "command_line",
]


def summarize(instance_dir):
    out = {"instance_dir": instance_dir}

    fs = read_fuzzer_stats(os.path.join(instance_dir, "fuzzer_stats"))
    out["fuzzer_stats"] = {k: fs[k] for k in FUZZER_STATS_KEYS if k in fs}

    # ---- Queue walk -------------------------------------------------- #
    queue_dir = os.path.join(instance_dir, "queue")
    entries = []
    if os.path.isdir(queue_dir):
        for name in sorted(os.listdir(queue_dir)):
            if not name.startswith("id:"):
                continue
            if not os.path.isfile(os.path.join(queue_dir, name)):
                continue
            entries.append(classify_queue_entry(name))

    # Build a filename → kind lookup for joining with path_costs
    kind_by_name = {e["name"]: e["kind"] for e in entries}

    # Queue summary counts (kept for JSON consumers)
    by_kind = {"initial": 0, "mutated": 0, "imported": 0}
    ops, sources = {}, {}
    cov_total = imported_cov = 0
    cov_times_ms = []

    for e in entries:
        by_kind[e["kind"]] += 1
        if e["is_cov"]:
            cov_total += 1
            if e["kind"] == "imported":
                imported_cov += 1
            if e["time_ms"] is not None:
                cov_times_ms.append(e["time_ms"])
        if e["op"]:
            ops[e["op"]] = ops.get(e["op"], 0) + 1
        if e["source"]:
            sources[e["source"]] = sources.get(e["source"], 0) + 1

    out["queue"] = {
        "total":                by_kind["initial"] + by_kind["mutated"] + by_kind["imported"],
        "initial":              by_kind["initial"],
        "mutated":              by_kind["mutated"],
        "imported":             by_kind["imported"],
        "coverage_increasing":  cov_total,
        "imported_and_cov":     imported_cov,
        "by_operator":          dict(sorted(ops.items(),     key=lambda kv: -kv[1])),
        "by_source":            dict(sorted(sources.items(), key=lambda kv: -kv[1])),
        "time_to_first_cov_ms": min(cov_times_ms) if cov_times_ms else None,
    }

    out["crashes"] = count_entries(os.path.join(instance_dir, "crashes"))
    out["hangs"]   = count_entries(os.path.join(instance_dir, "hangs"))

    # ---- path_costs — split into three subsets ----------------------- #
    pc_rows = read_path_costs(os.path.join(instance_dir, "path_costs.csv"))

    if pc_rows:
        # Classify each row directly from the filename embedded in path_costs.csv.
        # The filename column contains the full path; _kind_from_name uses os.path.basename
        # so it works regardless of the path prefix.
        rows_initial  = [r for r in pc_rows if _kind_from_name(r["filename"]) == "initial"]
        rows_imported = [r for r in pc_rows if _kind_from_name(r["filename"]) == "imported"]
        rows_all      = pc_rows

        out["path_costs"] = {
            "rows":          len(pc_rows),
            "initial":       _focused_stats(rows_initial),
            "all":           _focused_stats(rows_all),
            "imported":      _focused_stats(rows_imported),
            "max_ud_value":  max(r["user_defined"] for r in pc_rows),
            "max_ud_filename": max(pc_rows, key=lambda r: r["user_defined"])["filename"],
        }
    else:
        out["path_costs"] = None

    return out


# --------------------------------------------------------------------- #
#  Reporting                                                            #
# --------------------------------------------------------------------- #

def _fmt_duration(seconds_str):
    try:
        s = int(seconds_str)
    except (TypeError, ValueError):
        return seconds_str or "?"
    h, rem = divmod(s, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _fmt_int(s):
    try:
        return f"{int(s):,}"
    except (TypeError, ValueError):
        return s or "?"


def _print_focused_block(label, block, indent="  "):
    """Print the focused side-channel stat block for one subset."""
    SEP = "─" * 52
    print(f"\n{indent}{label}")
    print(f"{indent}{SEP}")
    if not block:
        print(f"{indent}  (no path_costs rows for this subset)")
        return
    print(f"{indent}  inputs evaluated    : {block['count']:,}")
    print(f"{indent}  max instructions    : {block['max_instructions']:,}")
    print(f"{indent}  max user cost       : {block['max_user_cost']:,}")
    print(f"{indent}  zero-cost inputs    : {block['zeros']:,}  ({block['zero_pct']} %)"
          "  ← lower is better")
    print(f"{indent}  CV (stdev/mean)     : {block['cv']:.3f}"
          f"  → {block['cv_verdict']}")
    print(f"{indent}  unique cost values  : {block['unique_costs']:,}"
          f"  ({block['unique_pct']} % of inputs)"
          "  ← more is better")


def _cycles_interpretation(cycles_str, last_find_str):
    try:
        c = int(cycles_str)
    except (TypeError, ValueError):
        return ""
    if c < 3:
        return "  (preliminary — fuzzer is still in its first pass)"
    return f"  (last new input: {last_find_str})"


def print_report(m):
    W = 72
    print(f"AFL++ campaign summary — {m['instance_dir']}")
    print("=" * W)

    fs = m.get("fuzzer_stats") or {}

    # ---- Campaign-level AFL++ stats ---------------------------------- #
    print("\nCampaign stats")
    print("-" * 40)
    print(f"  AFL version      : {fs.get('afl_version', '?')}")
    print(f"  Run time         : {_fmt_duration(fs.get('run_time'))}")
    print(f"  Executions       : {_fmt_int(fs.get('execs_done'))}"
          f"  ({fs.get('execs_per_sec', '?')} exec/s)")

    cycles     = fs.get('cycles_done', '?')
    last_find  = fs.get('last_find', '?')
    depth      = fs.get('max_depth', '?')
    print(f"  Cycles done      : {cycles}"
          + _cycles_interpretation(cycles, last_find))
    print(f"  Max depth        : {depth}"
          + ("  (deep chaining — AFL++ builds on discovered paths)"
             if _depth_notable(depth) else ""))
    print(f"  Bitmap coverage  : {fs.get('bitmap_cvg', '?')}"
          f"  (edges: {fs.get('edges_found', '?')})")
    print(f"  Corpus count     : {_fmt_int(fs.get('corpus_count'))}")
    print(f"  Saved crashes    : {fs.get('saved_crashes', '?')}")
    print(f"  Saved hangs      : {fs.get('saved_hangs', '?')}")

    # ---- Queue breakdown --------------------------------------------- #
    q = m["queue"]
    print("\nQueue")
    print("-" * 40)
    print(f"  Total entries       : {q['total']}")
    print(f"    initial           : {q['initial']}")
    print(f"    mutated           : {q['mutated']}")
    print(f"    imported (-F sync): {q['imported']}")
    pct = (100.0 * q['coverage_increasing'] / q['total']) if q['total'] else 0
    print(f"  Coverage-increasing : {q['coverage_increasing']} ({pct:.1f} %)")
    if q["time_to_first_cov_ms"] is not None:
        print(f"  Time to 1st +cov    : {q['time_to_first_cov_ms']} ms")

    print(f"\n  Crashes : {m['crashes']}")
    print(f"  Hangs   : {m['hangs']}")

    # ---- path_costs — three subset blocks ---------------------------- #
    print("\nSide-channel assessment  (path_costs.csv)")
    print("=" * W)
    pc = m["path_costs"]
    if not pc:
        print("  (path_costs.csv not present — vanilla AFL++ build, or not produced yet)")
        return

    print(f"  Total rows in path_costs.csv: {pc['rows']}")

    _print_focused_block("1. Initial seeds (original corpus)", pc["initial"])
    _print_focused_block("2. All queue entries",               pc["all"])
    _print_focused_block("3. Imported entries only",           pc["imported"])

    print(f"\n  Input with highest user cost : {pc['max_ud_value']:,}")
    print(f"  Filename                     : {pc['max_ud_filename']}")


def _depth_notable(depth_str):
    try:
        return int(depth_str) >= 5
    except (TypeError, ValueError):
        return False


# --------------------------------------------------------------------- #
#  CLI                                                                  #
# --------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Parse an AFL++ output directory and report metrics.")
    ap.add_argument("out_dir",
                    help="AFL++ output directory (the path passed to -o)")
    ap.add_argument("--instance", default=None,
                    help="Instance subdirectory (e.g. 'main'). "
                         "Auto-detected when omitted.")
    ap.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON instead of a text report")
    args = ap.parse_args()

    instance_dir = find_instance_dir(args.out_dir, args.instance)
    if not instance_dir:
        print(f"[error] no AFL++ instance (fuzzer_stats) found under "
              f"{args.out_dir}", file=sys.stderr)
        sys.exit(2)

    metrics = summarize(instance_dir)

    if args.json:
        json.dump(metrics, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
    else:
        print_report(metrics)


if __name__ == "__main__":
    main()
