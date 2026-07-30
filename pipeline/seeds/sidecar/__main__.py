#!/usr/bin/env python3
"""CLI entry point for the LLM seed generator.

Run with:
    python -m sidecar --source /path/to/src \
                                 --afl-out /tmp/afl-out \
                                 --seed-dir /tmp/llm-seeds

This file only contains argument parsing and the skeleton that tells
users what to implement.  All logic lives in ``generator.py`` and
``afl_stats_reader.py``.
"""

import argparse
import json
import logging
import sys
import urllib.request
from pathlib import Path

# Shared LLM backend config (env var > llm_config.ini > default).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import llm_config

from generator import LLMSeedGenerator

log = logging.getLogger("sidecar")


def list_models():
    """Fetch and print available models from the configured LLM API."""
    api_token = llm_config.api_token()
    if not api_token:
        print("Error: no API token (set LLM_API_TOKEN or api_token in llm_config.ini).", file=sys.stderr)
        sys.exit(1)

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

    models = [m["id"] for m in data.get("data", [])]
    for model_id in sorted(models):
        print(model_id)


def main():
    parser = argparse.ArgumentParser(
        description="LLM-based seed generator for AFL++ (via -F foreign sync)")
    parser.add_argument(
        "--list-models", action="store_true",
        help="List available models from the configured LLM API and exit")
    parser.add_argument(
        "--source",
        help="Path to the target applet .java source file")
    parser.add_argument(
        "--op-name",
        help="Operation name Xxx. The prompt will include only wrapXxx "
             "and coreXxx extracted from --source. When omitted, the "
             "prompt falls back to whole-class extraction.")
    parser.add_argument(
        "--afl-out",
        help="AFL++ output directory (-o flag)")
    parser.add_argument(
        "--seed-dir",
        help="Directory for generated seeds (AFL++ -F flag points here)")
    parser.add_argument(
        "--interval", type=int, default=60,
        help="Seconds between generation cycles (default: 60)")
    parser.add_argument(
        "--duration", type=int, default=None,
        help="Total runtime in seconds; the generator exits after this many "
             "seconds have elapsed since the first generation cycle began. "
             "Match this to AFL++'s -V value. Omit to run indefinitely.")
    parser.add_argument(
        "--timeout", type=int, default=None,
        help="Seconds to wait for the LLM API; overrides env (LLM_TIMEOUT) / "
             "llm_config.ini (default 120). Increase for slow/thinking models.")
    parser.add_argument(
        "--model", default=None,
        help="Model name or alias; overrides the value from env (LLM_MODEL) / llm_config.ini.")
    parser.add_argument(
        "--print-prompt", action="store_true",
        help="Print the prompt sent to the LLM before each generation cycle")
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging")
    args = parser.parse_args()

    if args.list_models:
        list_models()
        return

    missing = [name for name, val in [("--source", args.source),
                                       ("--op-name", args.op_name),
                                       ("--afl-out", args.afl_out),
                                       ("--seed-dir", args.seed_dir)]
               if val is None]
    if missing:
        parser.error(f"the following arguments are required: {', '.join(missing)}")

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
        print_prompt=args.print_prompt,
        llm_timeout=args.timeout,
    )
    generator.run_loop(interval_seconds=args.interval,
                       duration_seconds=args.duration)
    #generator.run_once()


if __name__ == "__main__":
    main()
