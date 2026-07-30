#!/usr/bin/env python3
"""CLI entry point for the LLM-based initial seed generator.

Works from the JSON produced by the harness-extraction stage -- no FuzzApplet
source parsing.

Run with:
    python -m initial --operation path/to/operation.json \\
                        --output-dir /tmp/seeds/HmacSha160

Optionally pass the matching context.json for extra prompt context, and/or
override MAX_DATA (otherwise it is detected from the wrapper's guard/Javadoc):
    python -m initial --operation operation.json --context context.json \\
                        --max-data 64 --output-dir /tmp/seeds/HmacSha160

Deterministic-only baseline (no LLM, no JSON -- just a MAX_DATA):
    python -m initial --no-llm --max-data 64 --output-dir /tmp/seeds/HmacSha160

All logic lives in generator.py (LLMSeedGenerator) and generate_seeds.py
(deterministic baseline seeds).
"""

import argparse
import json
import logging
import sys
import urllib.request
from pathlib import Path

# Allow running as both "python -m initial" and "python __main__.py".
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Shared LLM backend config (env var > llm_config.ini > default).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import llm_config

from generator import LLMSeedGenerator

# Optional: deterministic seed integration
try:
    from generate_seeds import generate_all, write_seeds
    HAS_DETERMINISTIC = True
except ImportError:
    HAS_DETERMINISTIC = False

# MAX_DATA detection reuses drivergen's helper (run against the wrapper code
# stored in operation.json, not the applet source).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "harness" / "drivergen"))

log = logging.getLogger("seeds.initial")


def list_models(api_token):
    """Fetch and print available models from the configured LLM API."""
    models_url = llm_config.endpoint().replace("/chat/completions", "/models")
    req = urllib.request.Request(
        models_url,
        headers={"Authorization": f"Bearer {api_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"Error fetching models: {exc}", file=sys.stderr)
        sys.exit(1)
    for m in sorted(m["id"] for m in data.get("data", [])):
        print(m)


def _detect_max_data(operation):
    """MAX_DATA for the operation, via the SAME resolver assemble_harness uses to
    set the driver's `MAX_DATA` constant -- so the seeds and the driver always
    agree on the fuzz-input size. Returns the wrapper's declared value (Javadoc
    ``MAX_DATA = N`` or a ``dataLen < (short) N`` guard), else the shared default.
    Returns None only if drivergen can't be imported."""
    try:
        from generate_drivers import resolve_max_data
        return resolve_max_data(operation)
    except Exception:
        return None


def run_for_operation(operation, context, max_data, out_dir, args):
    """Run LLM generation (and optionally deterministic seeds) for one operation."""
    op_name = operation.get("operation_name")
    if max_data is None:
        max_data = _detect_max_data(operation)
        if max_data is not None:
            log.info("MAX_DATA=%d for %s (from the wrapper, or the shared default) "
                     "-- matches the driver assemble_harness generates", max_data, op_name)
        else:
            log.warning(
                "could not resolve MAX_DATA for %s (drivergen unavailable) -- seed size "
                "will be symbolic in the prompt and deterministic seeds will be "
                "skipped. Pass --max-data N explicitly.", op_name)

    log.info("Operation: %s  MAX_DATA=%s  → %s", op_name, max_data, out_dir)

    if not args.no_llm:
        gen = LLMSeedGenerator(
            operation=operation,
            seed_output_dir=str(out_dir),
            max_data=max_data,
            context=context,
            model=args.model,
            print_prompt=args.print_prompt,
            llm_timeout=args.timeout,
        )
        gen.run(count=args.count)

    if HAS_DETERMINISTIC and not args.no_deterministic and max_data is not None:
        det_seeds = generate_all(max_data, args.p1_max, args.p2_max, args.random_count)
        write_seeds(det_seeds, Path(out_dir))
        log.info("Wrote %d deterministic seeds to %s", len(det_seeds), out_dir)


def main():
    parser = argparse.ArgumentParser(
        description="LLM-based initial seed generator for JCSmartFuzz campaigns.")

    parser.add_argument(
        "--list-models", action="store_true",
        help="List available models from the configured LLM API and exit")

    # Input: the JSON already produced by the harness-extraction stage.
    parser.add_argument(
        "--operation", metavar="PATH",
        help="Path to operation.json (harness-extraction output). Required for "
             "LLM generation.")
    parser.add_argument(
        "--context", metavar="PATH",
        help="Optional path to the matching context.json for extra prompt context.")

    # LLM control
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Skip LLM generation entirely; write only deterministic seeds. "
             "With --max-data, no operation.json is required.")

    parser.add_argument(
        "--max-data", metavar="N", type=int, default=None,
        help="MAX_DATA override. Detected from operation.json's wrapper when omitted; "
             "required for --no-llm without --operation.")
    parser.add_argument(
        "--output-dir", metavar="DIR", default="seeds",
        help="Output directory (default: seeds/).")

    # LLM options
    parser.add_argument(
        "--count", metavar="N", type=int, default=1,
        help="Number of LLM generation cycles (default: 1). Each cycle makes one "
             "LLM call; seeds are deduplicated across cycles.")
    parser.add_argument(
        "--model", default=None,
        help="Model name; overrides the value from env (LLM_MODEL) / llm_config.ini.")
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Seconds to wait for the LLM API; overrides env (LLM_TIMEOUT) / "
             "llm_config.ini (default 120). Increase for slow/thinking models.")
    parser.add_argument(
        "--print-prompt", action="store_true",
        help="Print the prompt sent to the LLM before each cycle")

    # Deterministic seed options
    parser.add_argument(
        "--no-deterministic", action="store_true",
        help="Skip the deterministic baseline seeds (identical/differential/random). "
             "By default, deterministic seeds are also written alongside LLM seeds.")
    parser.add_argument(
        "--p1-max", metavar="N", type=int, default=32,
        help="Max meaningful P1 value for P1-differential seeds (default: 32)")
    parser.add_argument(
        "--p2-max", metavar="N", type=int, default=32,
        help="Max meaningful P2 value for P2-differential seeds (default: 32)")
    parser.add_argument(
        "--random-count", metavar="N", type=int, default=32,
        help="Number of random deterministic seeds to generate (default: 32)")

    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S")

    if args.list_models:
        api_token = llm_config.api_token()
        if not api_token:
            print("Error: no API token (set LLM_API_TOKEN or api_token in llm_config.ini).",
                  file=sys.stderr)
            sys.exit(1)
        list_models(api_token)
        return

    out_root = Path(args.output_dir)

    # ------------------------------------------------------------------
    # --no-llm --max-data N  (no operation.json needed)
    # ------------------------------------------------------------------
    if args.no_llm and not args.operation:
        if args.max_data is None:
            parser.error("--max-data is required when --no-llm is used without --operation")
        if not HAS_DETERMINISTIC:
            print("ERROR: generate_seeds.py not found.", file=sys.stderr)
            sys.exit(1)
        seeds = generate_all(args.max_data, args.p1_max, args.p2_max, args.random_count)
        print(f"MAX_DATA={args.max_data}  seed size={6 + 2 * args.max_data} bytes")
        write_seeds(seeds, out_root)
        return

    # ------------------------------------------------------------------
    # operation.json-driven mode
    # ------------------------------------------------------------------
    if not args.operation:
        parser.error("--operation operation.json is required (or use --no-llm --max-data N)")

    op_path = Path(args.operation)
    if not op_path.is_file():
        print(f"ERROR: {op_path} does not exist.", file=sys.stderr)
        sys.exit(1)
    operation = json.loads(op_path.read_text(encoding="utf-8"))

    context = None
    if args.context:
        ctx_path = Path(args.context)
        if not ctx_path.is_file():
            print(f"ERROR: {ctx_path} does not exist.", file=sys.stderr)
            sys.exit(1)
        context = json.loads(ctx_path.read_text(encoding="utf-8"))

    run_for_operation(
        operation=operation,
        context=context,
        max_data=args.max_data,
        out_dir=out_root,
        args=args,
    )


if __name__ == "__main__":
    main()
