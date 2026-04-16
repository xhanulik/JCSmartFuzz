#!/usr/bin/env python3
"""CLI entry point for the LLM seed generator.

Run with:
    python -m llm_seed_generator --source /path/to/src \
                                 --afl-out /tmp/afl-out \
                                 --seed-dir /tmp/llm-seeds

This file only contains argument parsing and the skeleton that tells
users what to implement.  All logic lives in ``generator.py`` and
``afl_stats_reader.py``.
"""

import argparse
import logging
import sys

from generator import LLMSeedGenerator

log = logging.getLogger("llm_seed_generator")


def main():
    parser = argparse.ArgumentParser(
        description="LLM-based seed generator for AFL++ (via -F foreign sync)")
    parser.add_argument(
        "--source", required=False,
        help="Path to target source code (file or directory)")
    parser.add_argument(
        "--afl-out", required=True,
        help="AFL++ output directory (-o flag)")
    parser.add_argument(
        "--seed-dir", required=True,
        help="Directory for generated seeds (AFL++ -F flag points here)")
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between generation cycles (default: 60)")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S")

    generator = LLMSeedGenerator(
        source_code_path=args.source,
        afl_out_dir=args.afl_out,
        seed_output_dir=args.seed_dir,
    )
    #generator.run_loop(interval_seconds=args.interval)
    generator.run_once()

    log.error(
        "This is a skeleton package. To use it:\n"
        "  1. Subclass LLMSeedGenerator (from generator.py)\n"
        "  2. Implement read_source_context() and call_llm()\n"
        "  3. Instantiate your subclass in this file and call run_loop()\n"
        "\n"
        "See generator.py for which methods MUST / SHOULD / CAN be overridden.")
    sys.exit(1)


if __name__ == "__main__":
    main()
