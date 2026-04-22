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

from generator import LLMSeedGenerator, E_INFRA_DEFAULT_MODEL

log = logging.getLogger("llm_seed_generator")


def main():
    parser = argparse.ArgumentParser(
        description="LLM-based seed generator for AFL++ (via -F foreign sync)")
    parser.add_argument(
        "--source", required=True,
        help="Path to the target applet .java source file")
    parser.add_argument(
        "--op-name", required=True,
        help="Operation name Xxx. The prompt will include only wrapXxx "
             "and coreXxx extracted from --source. When omitted, the "
             "prompt falls back to whole-class extraction.")
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
        "--model", default=E_INFRA_DEFAULT_MODEL,
        help=f"e-INFRA CZ model name or alias (default: {E_INFRA_DEFAULT_MODEL}). "
             "See https://docs.cerit.io/en/docs/ai-as-a-service/ai-api")
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
        op_name=args.op_name,
        model=args.model,
    )
    generator.run_loop(interval_seconds=args.interval)
    #generator.run_once()


if __name__ == "__main__":
    main()
