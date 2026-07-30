"""initial — LLM-based initial corpus seed generator for JCSmartFuzz.

Public API
----------
LLMSeedGenerator
    Generates initial seeds using an LLM before fuzzing starts, driven by the
    harness-extraction JSON (operation.json) rather than the applet source.

generate_all / write_seeds
    Deterministic seed generators (no LLM required) — useful as a baseline
    corpus that the LLM-generated seeds augment.

Example::

    import json
    from initial import LLMSeedGenerator

    operation = json.load(open("path/to/operation.json"))
    gen = LLMSeedGenerator(
        operation=operation,
        seed_output_dir="/tmp/seeds/HmacSha160",
        max_data=64,
    )
    gen.run(count=2)
"""

from .generator import LLMSeedGenerator
from .generate_seeds import generate_all, write_seeds

__all__ = [
    "LLMSeedGenerator",
    "generate_all",
    "write_seeds",
]
