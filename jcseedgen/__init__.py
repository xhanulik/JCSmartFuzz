"""jcseedgen — LLM-based initial corpus seed generator for JCSmartFuzz.

Public API
----------
LLMSeedGenerator
    Generates initial seeds using an LLM before fuzzing starts.
    Reuses SourceReader from jcfuzzgen/llm_seed_generator/ for Java source
    extraction.

generate_all / write_seeds
    Deterministic seed generators (no LLM required) — useful as a baseline
    corpus that the LLM-generated seeds augment.

Example::

    from jcseedgen import LLMSeedGenerator

    gen = LLMSeedGenerator(
        source_code_path="path/to/XxxFuzzApplet.java",
        seed_output_dir="/tmp/seeds/HmacSha160",
        op_name="HmacSha160",
        max_data=64,
    )
    gen.run(count=2)
"""

from generator import LLMSeedGenerator, E_INFRA_DEFAULT_MODEL, E_INFRA_ENDPOINT
from generate_seeds import generate_all, write_seeds

__all__ = [
    "LLMSeedGenerator",
    "E_INFRA_DEFAULT_MODEL",
    "E_INFRA_ENDPOINT",
    "generate_all",
    "write_seeds",
]
