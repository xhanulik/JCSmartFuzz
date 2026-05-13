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

_RE_OP     = re.compile(r",op:([^,]+)")
_RE_ORIG   = re.compile(r",orig:([^,]+)")
_RE_SYNC   = re.compile(r",sync:([^,]+)")
_RE_TIME   = re.compile(r",time:(\d+)")
_RE_EXECS  = re.compile(r",execs:(\d+)")


def classify_queue_entry(name):
    """Decode an AFL++ queue filename into a structured record."""
    orig_m = _RE_ORIG.search(name)
    sync_m = _RE_SYNC.search(name)

    if orig_m:
        kind, source = "initial", orig_m.group(1)
    elif sync_m:
        kind, source = "imported", sync_m.group(1)
    else:
        kind, source = "mutated", None

    op_m = _RE_OP.search(name)
    time_m = _RE_TIME.search(name)
    execs_m = _RE_EXECS.search(name)

    return {
        "name": name,
        "kind": kind,
        "source": source,
        "op": op_m.group(1) if op_m else None,
        "is_cov": ",+cov" in name,
        "time_ms": int(time_m.group(1)) if time_m else None,
        "execs_at_find": int(execs_m.group(1)) if execs_m else None,
    }


# --------------------------------------------------------------------- #
#  File readers                                                         #
# --------------------------------------------------------------------- #

def find_instance_dir(out_dir, instance=None):
    """Resolve the AFL++ instance directory.

    Priority:
      1. Explicit ``--instance`` subdirectory.
      2. ``out_dir`` itself (single-instance layout).
      3. Glob ``out_dir/*/fuzzer_stats``; prefer common main-node names.
    """
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
            if not f.readline():
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
#  Metrics                                                              #
# --------------------------------------------------------------------- #

def percentile(data, p):
    """Linear-interpolated p-th percentile (0..100)."""
    if not data:
        return None
    s = sorted(data)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _stat_block(values):
    if not values:
        return None
    return {
        "count":  len(values),
        "min":    min(values),
        "max":    max(values),
        "mean":   statistics.mean(values),
        "median": statistics.median(values),
        "stdev":  statistics.stdev(values) if len(values) >= 2 else 0.0,
        "p90":    percentile(values, 90),
        "p95":    percentile(values, 95),
        "p99":    percentile(values, 99),
    }


def _side_channel_stat_block(values):
    """Extended stat block for user-defined cost, focused on timing side-channel quality."""
    if not values:
        return None

    n           = len(values)
    zeros       = sum(1 for v in values if v == 0)
    nonzero     = [v for v in values if v > 0]
    mn          = min(values)
    mx          = max(values)
    mean        = statistics.mean(values)
    median      = statistics.median(values)
    stdev       = statistics.stdev(values) if n >= 2 else 0.0
    cv          = stdev / mean if mean > 0 else 0.0
    unique      = len(set(values))
    p25         = percentile(values, 25)
    p75         = percentile(values, 75)
    p95_val     = percentile(values, 95)
    p99_val     = percentile(values, 99)
    iqr         = p75 - p25 if (p75 is not None and p25 is not None) else 0
    tail_ratio  = (p95_val / median) if (median and median > 0 and p95_val is not None) else None
    range_val   = mx - mn

    # Verdict signals
    zero_pct    = 100.0 * zeros / n
    unique_pct  = 100.0 * unique / n

    signals = []
    if zero_pct > 50:
        signals.append("WARN: >50% zeros — cost model may not be triggered")
    elif zero_pct > 10:
        signals.append("NOTE: >10% zeros — some inputs produce no timing difference")

    if cv < 0.1:
        signals.append("WARN: CV < 0.1 — near constant-time, low side-channel potential")
    elif cv < 0.3:
        signals.append("NOTE: CV 0.1–0.3 — moderate timing variability")
    else:
        signals.append("OK: CV > 0.3 — high timing variability")

    if unique_pct < 5:
        signals.append("WARN: <5% unique values — fuzzer likely stuck on few paths")
    elif unique_pct < 30:
        signals.append("NOTE: 30% unique values — moderate cost diversity")
    else:
        signals.append("OK: >30% unique values — good cost diversity")

    if tail_ratio is not None:
        if tail_ratio > 3:
            signals.append("OK: p95/median > 3 — strong tail, worst-case inputs present")
        else:
            signals.append("NOTE: p95/median ≤ 3 — weak tail, few extreme-cost inputs")

    if range_val == 0:
        signals.append("WARN: range = 0 — all inputs produce identical cost")

    return {
        "count":        n,
        "zeros":        zeros,
        "zero_pct":     round(zero_pct, 1),
        "min":          mn,
        "max":          mx,
        "range":        range_val,
        "mean":         mean,
        "median":       median,
        "stdev":        stdev,
        "cv":           round(cv, 3),
        "p25":          p25,
        "p75":          p75,
        "p95":          p95_val,
        "p99":          p99_val,
        "iqr":          iqr,
        "tail_ratio":   round(tail_ratio, 2) if tail_ratio is not None else None,
        "unique":       unique,
        "unique_pct":   round(unique_pct, 1),
        "verdict":      signals,
    }


# Fields from fuzzer_stats we surface in the report. Values are kept as
# raw strings -- display formatting happens in print_report().
FUZZER_STATS_KEYS = [
    "start_time", "last_update", "run_time",
    "execs_done", "execs_per_sec", "execs_since_crash",
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

    # Queue walk + classification.
    queue_dir = os.path.join(instance_dir, "queue")
    entries = []
    if os.path.isdir(queue_dir):
        for name in sorted(os.listdir(queue_dir)):
            if not name.startswith("id:"):
                continue
            if not os.path.isfile(os.path.join(queue_dir, name)):
                continue
            entries.append(classify_queue_entry(name))

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
        "by_operator":          dict(sorted(ops.items(), key=lambda kv: -kv[1])),
        "by_source":            dict(sorted(sources.items(), key=lambda kv: -kv[1])),
        "time_to_first_cov_ms": min(cov_times_ms) if cov_times_ms else None,
    }

    out["crashes"] = count_entries(os.path.join(instance_dir, "crashes"))
    out["hangs"]   = count_entries(os.path.join(instance_dir, "hangs"))

    pc = read_path_costs(os.path.join(instance_dir, "path_costs.csv"))
    if pc:
        max_ud_row = max(pc, key=lambda r: r["user_defined"])
        out["path_costs"] = {
            "rows":             len(pc),
            "instructions":     _stat_block([r["instructions"] for r in pc]),
            "time":             _stat_block([r["time"] for r in pc]),
            "memory":           _stat_block([r["memory"] for r in pc]),
            "user_defined":     _side_channel_stat_block([r["user_defined"] for r in pc]),
            "max_ud_filename":  max_ud_row["filename"],
            "max_ud_value":     max_ud_row["user_defined"],
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


def _fmt_num(x, digits=1):
    if x is None:
        return "-"
    if isinstance(x, float):
        return f"{x:,.{digits}f}"
    return f"{x:,}"


def _print_stat_block(label, block, indent="    "):
    if not block:
        print(f"{indent}{label}: (no data)")
        return
    print(f"{indent}{label}:")
    print(f"{indent}  min  = {_fmt_num(block['min'])}")
    print(f"{indent}  max  = {_fmt_num(block['max'])}")
    print(f"{indent}  mean = {_fmt_num(block['mean'])}")
    print(f"{indent}  med  = {_fmt_num(block['median'])}")
    print(f"{indent}  sd   = {_fmt_num(block['stdev'])}")
    print(f"{indent}  p90  = {_fmt_num(block['p90'])}")
    print(f"{indent}  p95  = {_fmt_num(block['p95'])}")
    print(f"{indent}  p99  = {_fmt_num(block['p99'])}")


def _print_side_channel_block(block, indent="  "):
    if not block:
        print(f"{indent}(no data)")
        return
    print(f"{indent}count        = {block['count']:,}")
    print(f"{indent}zeros        = {block['zeros']:,} ({block['zero_pct']}%)")
    print(f"{indent}unique vals  = {block['unique']:,} ({block['unique_pct']}%)")
    print(f"{indent}range        = {_fmt_num(block['range'])}"
          f"  [{_fmt_num(block['min'])} … {_fmt_num(block['max'])}]")
    print(f"{indent}mean         = {_fmt_num(block['mean'], 1)}")
    print(f"{indent}median       = {_fmt_num(block['median'], 1)}")
    print(f"{indent}stdev        = {_fmt_num(block['stdev'], 1)}")
    print(f"{indent}CV           = {block['cv']:.3f}"
          f"  (stdev/mean; >0.3 = high variability)")
    print(f"{indent}IQR          = {_fmt_num(block['iqr'])}"
          f"  (p25={_fmt_num(block['p25'])}, p75={_fmt_num(block['p75'])})")
    print(f"{indent}p95          = {_fmt_num(block['p95'])}")
    print(f"{indent}p99          = {_fmt_num(block['p99'])}")
    tr = block["tail_ratio"]
    print(f"{indent}p95/median   = {f'{tr:.2f}' if tr is not None else '-'}"
          f"  (>3 = strong tail)")
    print(f"{indent}Verdict:")
    for sig in block["verdict"]:
        print(f"{indent}  {sig}")


def print_report(m):
    print(f"AFL++ campaign summary — {m['instance_dir']}")
    print("=" * 72)

    fs = m.get("fuzzer_stats") or {}
    if fs:
        print("\nFuzzer stats")
        print("------------")
        print(f"  AFL version      : {fs.get('afl_version', '?')}")
        print(f"  Run time         : {_fmt_duration(fs.get('run_time'))}")
        print(f"  Executions       : {_fmt_int(fs.get('execs_done'))}"
              f" ({fs.get('execs_per_sec', '?')} exec/s)")
        print(f"  Cycles done      : {fs.get('cycles_done', '?')}")
        print(f"  Max depth        : {fs.get('max_depth', '?')}")
        print(f"  Bitmap coverage  : {fs.get('bitmap_cvg', '?')}"
              f"  (edges: {fs.get('edges_found', '?')})")
        print(f"  Corpus count     : {_fmt_int(fs.get('corpus_count'))}")
        print(f"  Corpus imported  : {_fmt_int(fs.get('corpus_imported'))}")
        print(f"  Saved crashes    : {fs.get('saved_crashes', '?')}")
        print(f"  Saved hangs      : {fs.get('saved_hangs', '?')}")

    q = m["queue"]
    print("\nQueue")
    print("-----")
    print(f"  Total entries       : {q['total']}")
    print(f"    initial           : {q['initial']}")
    print(f"    mutated           : {q['mutated']}")
    print(f"    imported (-F sync): {q['imported']}")
    pct = (100.0 * q['coverage_increasing'] / q['total']) if q['total'] else 0
    print(f"  Coverage-increasing : {q['coverage_increasing']} ({pct:.1f}%)")
    if q["imported"]:
        pct_i = 100.0 * q['imported_and_cov'] / q['imported']
        print(f"  Imported AND +cov   : {q['imported_and_cov']}"
              f" / {q['imported']} ({pct_i:.1f}% of imports)")
    if q["time_to_first_cov_ms"] is not None:
        print(f"  Time to 1st +cov    : {q['time_to_first_cov_ms']} ms")

    if q["by_operator"]:
        print("\n  By mutation operator (mutated entries only):")
        for op, n in list(q["by_operator"].items())[:10]:
            print(f"    {op:<32s} {n}")

    if q["by_source"]:
        print("\n  By source (orig / sync):")
        for src, n in list(q["by_source"].items())[:10]:
            print(f"    {src:<32s} {n}")

    print("\nFindings")
    print("--------")
    print(f"  Crashes : {m['crashes']}")
    print(f"  Hangs   : {m['hangs']}")

    pc = m["path_costs"]
    print("\nPath costs (path_costs.csv)")
    print("---------------------------")
    if not pc:
        print("  (file not present — vanilla AFL++ build, or not produced yet)")
    else:
        print(f"  Rows: {pc['rows']}")
        _print_stat_block("Instructions", pc["instructions"])
        _print_stat_block("Time",         pc["time"])
        _print_stat_block("Memory",       pc["memory"])
        print()
        print("  User-defined cost — timing side-channel assessment")
        print("  " + "-" * 50)
        _print_side_channel_block(pc["user_defined"])
        print(f"  Max user-cost    = {_fmt_num(pc['max_ud_value'])}")
        print(f"  Max user-cost input: {pc['max_ud_filename']}")


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
