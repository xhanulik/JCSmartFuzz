#!/usr/bin/env python3
"""Split FuzzApplet fuzzing inputs into ProfileApplet inputs.

A FuzzApplet input file (the fixed-offset layout the FuzzDriver reads) packs two
input sets A and B:

    [ p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA)      <- slot A (3+MAX_DATA)
    | p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA) ]    <- slot B (3+MAX_DATA)
    total = 6 + 2*MAX_DATA bytes

A ProfileApplet processes a SINGLE input set, so its input is exactly one slot:

    [ p1(1) | p2(1) | len(1) | data(MAX_DATA) ]            (3+MAX_DATA bytes)

i.e. half a FuzzApplet input. This script reads a directory of FuzzApplet inputs
and, for each, writes the A slot and the B slot as two separate ProfileApplet
inputs (matching the FuzzDriver's fixed-offset interpretation: short files are
zero-padded, longer files truncated, to 6 + 2*MAX_DATA).

Usage:
    python3 split_inputs.py <fuzz_input_dir> -o <profile_out_dir> \
        [--max-data 64] [--which both|A|B] [--recursive]

--max-data must match the FuzzDriver's MAX_DATA for the operation (default 64).
"""
import argparse
import sys
from pathlib import Path


def iter_input_files(root, recursive):
    it = root.rglob("*") if recursive else root.iterdir()
    for p in sorted(it):
        if p.is_file() and not p.name.startswith("."):
            yield p


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input_dir", type=Path, help="directory of FuzzApplet-format fuzzing inputs")
    ap.add_argument("-o", "--output-dir", type=Path, required=True, help="directory for ProfileApplet inputs")
    ap.add_argument("--max-data", type=int, default=64, help="MAX_DATA of the FuzzDriver (default: 64)")
    ap.add_argument("--which", choices=["both", "A", "B"], default="both",
                    help="which slot(s) to emit per input (default: both)")
    ap.add_argument("--recursive", action="store_true", help="recurse into subdirectories")
    args = ap.parse_args()

    if not args.input_dir.is_dir():
        sys.exit(f"error: {args.input_dir} is not a directory")
    if args.max_data < 0:
        sys.exit("error: --max-data must be >= 0")

    half = 3 + args.max_data              # one slot: p1 + p2 + len + data(MAX_DATA)
    total = 2 * half                      # full FuzzApplet input: 6 + 2*MAX_DATA
    args.output_dir.mkdir(parents=True, exist_ok=True)

    files = list(iter_input_files(args.input_dir, args.recursive))
    if not files:
        sys.exit(f"error: no input files found under {args.input_dir}")

    written = odd = 0
    for f in files:
        raw = f.read_bytes()
        if len(raw) != total:
            odd += 1
        buf = (raw + b"\x00" * total)[:total]   # zero-pad, then truncate (as the driver does)
        rel = f.relative_to(args.input_dir)
        stem = str(rel).replace("/", "_")
        slots = {"A": buf[:half], "B": buf[half:]}
        for name in (["A", "B"] if args.which == "both" else [args.which]):
            out = args.output_dir / f"{stem}_{name}"
            out.write_bytes(slots[name])
            written += 1

    print(f"split {len(files)} FuzzApplet input(s) -> {written} ProfileApplet input(s) "
          f"({half} bytes each) in {args.output_dir}", file=sys.stderr)
    if odd:
        print(f"note: {odd} input(s) were not exactly {total} bytes (6 + 2*MAX_DATA) and were "
              f"zero-padded/truncated; check --max-data matches the FuzzDriver's MAX_DATA.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
