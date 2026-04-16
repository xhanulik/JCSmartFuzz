"""LLM-based seed generator for AFL++.

Plugs into AFL++ via the ``-F`` (foreign sync) mechanism.  Reads fuzzer
stats and queue state from the AFL++ output directory, calls an LLM API
to generate new test inputs, and writes them to a seed directory that
AFL++ polls automatically.

Quick start::

    from llm_seed_generator import LLMSeedGenerator

    class MyGenerator(LLMSeedGenerator):
        def read_source_context(self):       # MUST implement
            ...
        def call_llm(self, prompt):          # MUST implement
            ...

    gen = MyGenerator(source_path, afl_out, seed_dir)
    gen.run_loop()

See ``generator.py`` for the full list of extension points.
"""

from .afl_stats_reader import AFLStatsReader
from .generator import LLMSeedGenerator
from .source_reader import SourceReader

__all__ = ["AFLStatsReader", "LLMSeedGenerator", "SourceReader"]
