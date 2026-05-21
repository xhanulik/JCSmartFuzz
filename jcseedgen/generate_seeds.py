#!/usr/bin/env python3
"""
generate_seeds.py — Generate initial corpus seeds for JCSmartFuzz fuzzing campaigns.

Seeds conform to the fixed-offset format consumed by FuzzDriverSkeleton.java:

  [p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA) |
   p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA)]
  Total: 6 + 2*MAX_DATA bytes

Each seed carries two independent input sets (A and B). AFL++ mutates the whole
file, but the driver always reads them at fixed offsets, so every byte position
has a stable semantic role.

The generated seeds cover:
  - Identical A/B pairs          baseline: timing cost should be zero
  - P1-differential pairs        exercises data-dependent loop bounds on P1 (e.g. key_length)
  - P2-differential pairs        exercises data-dependent processing on P2 (e.g. msg_length)
  - Length-differential pairs    len_A != len_B
  - Data-content pairs           zeros vs 0xFF, alternating pattern, MSB boundary
  - Random pairs                 AFL++-friendly starting diversity

Usage:
  # Provide MAX_DATA directly:
  python generate_seeds.py --max-data 64 --output-dir /tmp/seeds/

  # Auto-detect MAX_DATA per operation from a FuzzApplet:
  python generate_seeds.py --applet path/to/XxxFuzzApplet.java --output-dir /tmp/seeds/

  # Limit random seeds:
  python generate_seeds.py --max-data 4 --output-dir /tmp/seeds/ --random-count 20
"""

import argparse
import os
import random
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Optionally reuse the applet parser from drivergen/
# ---------------------------------------------------------------------------

_DRIVERGEN = Path(__file__).resolve().parent.parent / 'drivergen'
sys.path.insert(0, str(_DRIVERGEN))

try:
    from generate_drivers import parse_applet
    HAS_APPLET_PARSER = True
except ImportError:
    HAS_APPLET_PARSER = False


# ---------------------------------------------------------------------------
# Seed construction helpers
# ---------------------------------------------------------------------------

def make_seed(max_data: int,
              p1_a: int, p2_a: int, len_a: int, data_a: bytes,
              p1_b: int, p2_b: int, len_b: int, data_b: bytes) -> bytes:
    """
    Build one seed file conforming to the fixed-offset layout.
    data_a / data_b are padded or truncated to exactly MAX_DATA bytes.
    len_a / len_b are clamped to [0, MAX_DATA].
    """
    len_a = max(0, min(len_a, max_data))
    len_b = max(0, min(len_b, max_data))
    slot_a = (data_a + bytes(max_data))[:max_data]
    slot_b = (data_b + bytes(max_data))[:max_data]
    return bytes([
        p1_a & 0xFF,
        p2_a & 0xFF,
        len_a & 0xFF,
        *slot_a,
        p1_b & 0xFF,
        p2_b & 0xFF,
        len_b & 0xFF,
        *slot_b,
    ])


def _rand_bytes(n: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(n))


# ---------------------------------------------------------------------------
# Seed strategies
# ---------------------------------------------------------------------------

def seeds_identical(max_data: int) -> list[tuple[str, bytes]]:
    """A == B — timing cost should be zero (sanity-check seeds)."""
    result = []
    for name, pattern in [('zeros', bytes(max_data)),
                           ('ones',  bytes([0xFF] * max_data)),
                           ('alt',   bytes([0x55 if i % 2 == 0 else 0xAA
                                            for i in range(max_data)]))]:
        seed = make_seed(max_data,
                         0, 0, max_data, pattern,
                         0, 0, max_data, pattern)
        result.append((f'identical_{name}', seed))
    return result


def seeds_p1_differential(max_data: int, p1_max: int) -> list[tuple[str, bytes]]:
    """
    A and B use different P1 values with the same data.
    Targets operations where P1 encodes a loop-bound parameter (e.g. key_length).
    """
    if p1_max < 2:
        return []
    mid = p1_max // 2
    data = bytes(max_data)  # zeros — focus the diff on P1 only
    pairs = [
        (1,   p1_max),
        (1,   mid),
        (mid, p1_max),
    ]
    result = []
    for lo, hi in pairs:
        seed = make_seed(max_data,
                         lo, 0, max_data, data,
                         hi, 0, max_data, data)
        result.append((f'p1_{lo:03d}_vs_{hi:03d}', seed))
    return result


def seeds_p2_differential(max_data: int, p2_max: int) -> list[tuple[str, bytes]]:
    """
    A and B use different P2 values with the same data.
    Targets operations where P2 encodes a variable-length parameter (e.g. msg_length).
    """
    if p2_max < 2:
        return []
    mid = p2_max // 2
    data = bytes(max_data)
    pairs = [
        (0,   p2_max),
        (1,   p2_max),
        (mid, p2_max),
    ]
    result = []
    for lo, hi in pairs:
        seed = make_seed(max_data,
                         0, lo, max_data, data,
                         0, hi, max_data, data)
        result.append((f'p2_{lo:03d}_vs_{hi:03d}', seed))
    return result


def seeds_len_differential(max_data: int) -> list[tuple[str, bytes]]:
    """
    A and B use different len values (actual data bytes used by the wrapper).
    Targets operations whose processing time scales with data length.
    """
    if max_data < 2:
        return []
    data = bytes([0x42] * max_data)
    pairs = [(1, max_data), (max_data // 2, max_data)]
    result = []
    for lo, hi in pairs:
        seed = make_seed(max_data,
                         0, 0, lo, data,
                         0, 0, hi, data)
        result.append((f'len_{lo:03d}_vs_{hi:03d}', seed))
    return result


def seeds_data_differential(max_data: int) -> list[tuple[str, bytes]]:
    """
    A and B have the same P1/P2/len but different data content.
    Covers: zeros vs 0xFF, and MSB boundary (0x00 vs 0x80 in first byte).
    The MSB boundary seed specifically targets hardened-vs-normal BIP32 derivation.
    """
    result = []

    # zeros vs 0xFF
    seed = make_seed(max_data,
                     0, 0, max_data, bytes(max_data),
                     0, 0, max_data, bytes([0xFF] * max_data))
    result.append(('data_zeros_vs_ones', seed))

    # MSB boundary: data_A[0] = 0x00 (normal BIP32 path), data_B[0] = 0x80 (hardened)
    data_normal   = bytes(max_data)
    data_hardened = bytes([0x80] + [0x00] * (max_data - 1))
    seed = make_seed(max_data,
                     0, 0, max_data, data_normal,
                     0, 0, max_data, data_hardened)
    result.append(('data_msb_normal_vs_hardened', seed))

    return result


def seeds_random(max_data: int, count: int) -> list[tuple[str, bytes]]:
    """Fully random seeds — give AFL++ diverse starting material to mutate from."""
    result = []
    for i in range(count):
        p1_a, p2_a = random.randint(0, 255), random.randint(0, 255)
        p1_b, p2_b = random.randint(0, 255), random.randint(0, 255)
        len_a = random.randint(0, max_data)
        len_b = random.randint(0, max_data)
        data_a = _rand_bytes(max_data)
        data_b = _rand_bytes(max_data)
        seed = make_seed(max_data, p1_a, p2_a, len_a, data_a,
                                   p1_b, p2_b, len_b, data_b)
        result.append((f'random_{i:04d}', seed))
    return result


# ---------------------------------------------------------------------------
# High-level generation
# ---------------------------------------------------------------------------

def generate_all(max_data: int,
                 p1_max: int,
                 p2_max: int,
                 random_count: int) -> list[tuple[str, bytes]]:
    seeds = []
    seeds += seeds_identical(max_data)
    seeds += seeds_p1_differential(max_data, p1_max)
    seeds += seeds_p2_differential(max_data, p2_max)
    seeds += seeds_len_differential(max_data)
    seeds += seeds_data_differential(max_data)
    seeds += seeds_random(max_data, random_count)
    return seeds


def write_seeds(seeds: list[tuple[str, bytes]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in seeds:
        path = out_dir / f'seed_{name}.bin'
        path.write_bytes(data)
    print(f"  Wrote {len(seeds)} seeds → {out_dir}/")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Generate initial corpus seeds for JCSmartFuzz drivers.'
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        '--applet', metavar='PATH',
        help='Path to *FuzzApplet.java — MAX_DATA is detected per operation'
    )
    src.add_argument(
        '--max-data', metavar='N', type=int,
        help='Fixed MAX_DATA value (use when not providing an applet)'
    )
    parser.add_argument(
        '--output-dir', metavar='DIR', default='seeds',
        help='Root directory for output (default: seeds/). '
             'When --applet is used, one sub-directory is created per operation.'
    )
    parser.add_argument(
        '--p1-max', metavar='N', type=int, default=32,
        help='Maximum meaningful P1 value for differential seeds (default: 32)'
    )
    parser.add_argument(
        '--p2-max', metavar='N', type=int, default=32,
        help='Maximum meaningful P2 value for differential seeds (default: 32)'
    )
    parser.add_argument(
        '--random-count', metavar='N', type=int, default=32,
        help='Number of random seeds to generate (default: 32)'
    )
    args = parser.parse_args()

    out_root = Path(args.output_dir)

    if args.max_data is not None:
        # Simple mode: single MAX_DATA, flat output directory
        max_data = args.max_data
        if max_data < 1:
            print('ERROR: --max-data must be >= 1', file=sys.stderr)
            sys.exit(1)
        seeds = generate_all(max_data, args.p1_max, args.p2_max, args.random_count)
        total_bytes = 6 + 2 * max_data
        print(f"MAX_DATA={max_data}  seed size={total_bytes} bytes")
        write_seeds(seeds, out_root)

    else:
        # Applet mode: parse operations and generate per-operation seed directories
        if not HAS_APPLET_PARSER:
            print(
                'ERROR: drivergen/generate_drivers.py not found. '
                'Run from the repo root or add drivergen/ to PYTHONPATH.',
                file=sys.stderr
            )
            sys.exit(1)

        applet_path = Path(args.applet)
        if not applet_path.is_file():
            print(f'ERROR: {applet_path} does not exist.', file=sys.stderr)
            sys.exit(1)

        source = applet_path.read_text(encoding='utf-8')
        try:
            info = parse_applet(source)
        except ValueError as exc:
            print(f'ERROR: {exc}', file=sys.stderr)
            sys.exit(1)

        print(f"Parsed applet: {info['class_name']}  "
              f"(package {info['package']})")
        print(f"Operations:")

        for op in info['operations']:
            max_data    = op['max_data']
            op_name     = op['wrapper_name'].removeprefix('wrap')
            total_bytes = 6 + 2 * max_data
            print(f"  {op['ins_name']:<22} {op['ins_value']}  "
                  f"{op['wrapper_name']:<24} MAX_DATA={max_data} "
                  f"({total_bytes} bytes/seed)")

            seeds = generate_all(max_data, args.p1_max, args.p2_max,
                                 args.random_count)
            write_seeds(seeds, out_root / op_name)


if __name__ == '__main__':
    main()
