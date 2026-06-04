#!/usr/bin/env python3
"""CLI entry point for the LLM-based initial seed generator.

Run with:
    python -m jcseedgen --source path/to/XxxFuzzApplet.java \\
                        --op-name HmacSha160 \\
                        --output-dir /tmp/seeds/HmacSha160

Or use --applet to auto-detect all operations from the applet and generate
seeds in one sub-directory per operation:

    python -m jcseedgen --applet path/to/XxxFuzzApplet.java \\
                        --output-dir /tmp/seeds/

All logic lives in generator.py (LLMSeedGenerator) and generate_seeds.py
(deterministic baseline seeds).
"""

import argparse
import json
import logging
import os
import sys
import urllib.request
from pathlib import Path

# Allow running as both "python -m jcseedgen" and "python __main__.py".
sys.path.insert(0, str(Path(__file__).resolve().parent))

from generator import (
    LLMSeedGenerator,
    E_INFRA_DEFAULT_MODEL,
    E_INFRA_ENDPOINT,
    E_INFRA_TIMEOUT_SECONDS,
)

# Optional: deterministic seed integration
try:
    from generate_seeds import generate_all, write_seeds
    HAS_DETERMINISTIC = True
except ImportError:
    HAS_DETERMINISTIC = False

# Optional: applet parser for multi-operation mode
_DRIVERGEN = Path(__file__).resolve().parent.parent / "drivergen"
sys.path.insert(0, str(_DRIVERGEN))
try:
    from generate_drivers import parse_applet
    HAS_APPLET_PARSER = True
except ImportError:
    HAS_APPLET_PARSER = False

log = logging.getLogger("jcseedgen")


def list_models(api_token):
    """Fetch and print available models from the e-INFRA CZ API."""
    models_url = E_INFRA_ENDPOINT.replace("/chat/completions", "/models")
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


def _detect_max_data(source_path, op_name):
    """Try to read MAX_DATA for *op_name* from the wrapper in *source_path*.

    Delegates to drivergen._find_max_data which looks for:
      1. Javadoc ``* MAX_DATA = N``
      2. Guard   ``if (dataLen < (short) N)``
    Returns the integer value, or None if not found or drivergen is absent.
    """
    if not HAS_APPLET_PARSER:
        return None
    try:
        from generate_drivers import _find_max_data  # private but stable
        source = Path(source_path).read_text(encoding="utf-8")
        return _find_max_data(source, f"wrap{op_name}")
    except Exception:
        return None


def run_for_operation(source_path, op_name, max_data, out_dir, args):
    """Run LLM generation (and optionally deterministic seeds) for one operation.

    When args.no_llm is True the LLM call is skipped entirely; source_path may
    be None in that case.
    """
    # Auto-detect MAX_DATA from the source if it was not supplied explicitly.
    if max_data is None and source_path is not None and op_name is not None:
        max_data = _detect_max_data(source_path, op_name)
        if max_data is not None:
            log.info("Auto-detected MAX_DATA=%d for %s from source", max_data, op_name)
        else:
            log.warning(
                "MAX_DATA not found for %s in %s — "
                "seed size will be symbolic in the prompt and deterministic "
                "seeds will be skipped. Add a '* MAX_DATA = N' Javadoc line "
                "or 'if (dataLen < (short) N)' guard to the wrapper.",
                op_name, source_path)

    log.info("Operation: %s  MAX_DATA=%s  → %s", op_name, max_data, out_dir)

    if not args.no_llm:
        gen = LLMSeedGenerator(
            source_code_path=str(source_path),
            seed_output_dir=str(out_dir),
            op_name=op_name,
            max_data=max_data,
            model=args.model,
            print_prompt=args.print_prompt,
            llm_timeout=args.timeout,
        )
        gen.run(count=args.count)

    if HAS_DETERMINISTIC and not args.no_deterministic and max_data is not None:
        det_seeds = generate_all(max_data, args.p1_max, args.p2_max,
                                 args.random_count)
        write_seeds(det_seeds, Path(out_dir))
        log.info("Wrote %d deterministic seeds to %s", len(det_seeds), out_dir)


def main():
    parser = argparse.ArgumentParser(
        description="LLM-based initial seed generator for JCSmartFuzz campaigns.")

    parser.add_argument(
        "--list-models", action="store_true",
        help="List available models from the e-INFRA CZ API and exit")

    # Source specification (mutually exclusive)
    src = parser.add_mutually_exclusive_group()
    src.add_argument(
        "--source", metavar="PATH",
        help="Path to *FuzzApplet.java — use with --op-name for single-operation mode")
    src.add_argument(
        "--applet", metavar="PATH",
        help="Path to *FuzzApplet.java — auto-detect all operations and generate "
             "one sub-directory per operation (requires drivergen/)")

    # LLM control
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Skip LLM generation entirely; write only deterministic seeds. "
             "When used with --max-data a source file is not required.")

    parser.add_argument(
        "--op-name", metavar="NAME",
        help="Operation name Xxx (used with --source).  The prompt will include "
             "only wrapXxx and coreXxx.  Omit to use full-class extraction.")
    parser.add_argument(
        "--max-data", metavar="N", type=int, default=None,
        help="MAX_DATA override.  Detected automatically from --applet; "
             "required for precise prompt wording when using --source.")
    parser.add_argument(
        "--output-dir", metavar="DIR", default="seeds",
        help="Root output directory (default: seeds/).  When --applet is used, "
             "one sub-directory is created per operation.")

    # LLM options
    parser.add_argument(
        "--count", metavar="N", type=int, default=1,
        help="Number of LLM generation cycles per operation (default: 1).  "
             "Each cycle makes one LLM call; seeds are deduplicated across cycles.")
    parser.add_argument(
        "--model", default=E_INFRA_DEFAULT_MODEL,
        help=f"e-INFRA CZ model name (default: {E_INFRA_DEFAULT_MODEL}). "
             "See https://docs.cerit.io/en/docs/ai-as-a-service/ai-api")
    parser.add_argument(
        "--timeout", type=int, default=E_INFRA_TIMEOUT_SECONDS,
        help=f"Seconds to wait for the LLM API (default: {E_INFRA_TIMEOUT_SECONDS}). "
             "Increase for slow/thinking models.")
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
        api_token = os.environ.get("LLM_API_TOKEN")
        if not api_token:
            print("Error: LLM_API_TOKEN environment variable is not set.",
                  file=sys.stderr)
            sys.exit(1)
        list_models(api_token)
        return

    out_root = Path(args.output_dir)

    # ------------------------------------------------------------------
    # Applet mode: auto-detect all operations
    # ------------------------------------------------------------------
    if args.applet:
        if not HAS_APPLET_PARSER:
            print(
                "ERROR: drivergen/generate_drivers.py not found. "
                "Cannot auto-detect operations.",
                file=sys.stderr)
            sys.exit(1)
        applet_path = Path(args.applet)
        if not applet_path.is_file():
            print(f"ERROR: {applet_path} does not exist.", file=sys.stderr)
            sys.exit(1)

        source = applet_path.read_text(encoding="utf-8")
        try:
            info = parse_applet(source)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)

        print(f"Parsed applet: {info['class_name']}  "
              f"(package {info['package']})")
        print(f"Operations:")
        for op in info["operations"]:
            op_name = op["wrapper_name"].removeprefix("wrap")
            print(f"  {op['ins_name']:<22} {op['ins_value']}  "
                  f"{op['wrapper_name']:<24} MAX_DATA={op['max_data']}")
            run_for_operation(
                source_path=applet_path,
                op_name=op_name,
                max_data=op["max_data"],
                out_dir=out_root / op_name,
                args=args,
            )
        return

    # ------------------------------------------------------------------
    # --no-llm --max-data N  (no source file needed)
    # ------------------------------------------------------------------
    if args.no_llm and not args.source and not args.applet:
        if args.max_data is None:
            parser.error(
                "--max-data is required when --no-llm is used without --source or --applet")
        if not HAS_DETERMINISTIC:
            print("ERROR: generate_seeds.py not found.", file=sys.stderr)
            sys.exit(1)
        seeds = generate_all(args.max_data, args.p1_max, args.p2_max,
                             args.random_count)
        print(f"MAX_DATA={args.max_data}  seed size={6 + 2 * args.max_data} bytes")
        write_seeds(seeds, out_root)
        return

    # ------------------------------------------------------------------
    # Single-source mode
    # ------------------------------------------------------------------
    if not args.source:
        parser.error("one of --source or --applet is required "
                     "(or use --no-llm --max-data N)")

    source_path = Path(args.source)
    if not source_path.is_file():
        print(f"ERROR: {source_path} does not exist.", file=sys.stderr)
        sys.exit(1)

    run_for_operation(
        source_path=source_path,
        op_name=args.op_name,
        max_data=args.max_data,
        out_dir=out_root,
        args=args,
    )


if __name__ == "__main__":
    main()
