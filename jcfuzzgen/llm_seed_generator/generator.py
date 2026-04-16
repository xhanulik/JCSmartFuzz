"""Base class for LLM-based seed generation.

Subclass ``LLMSeedGenerator`` and implement ``call_llm()`` to create a
working generator.  ``read_source_context()`` has a default that reads
Java source via ``SourceReader`` -- override it if the target is not
Java or if you need custom extraction.

See ``__main__.py`` for the CLI entry point.
"""

import logging
import os
import sys
import time

from afl_stats_reader import AFLStatsReader
from source_reader import SourceReader

log = logging.getLogger(__name__)


class LLMSeedGenerator:
    """Generates seeds using an LLM and writes them for AFL++ foreign sync.

    Lifecycle:
        1. Instantiate with paths.
        2. Call ``run_loop()`` (or ``run_once()`` for one-shot use).
        3. The loop reads AFL++ state, calls ``build_prompt()``, passes
           the prompt to ``call_llm()``, parses the response, and writes
           seeds to the foreign-sync directory.

    Extension points -- see the per-method comments below.
    """

    def __init__(self, source_code_path, afl_out_dir, seed_output_dir):
        self.source_code_path = source_code_path
        self.source_reader = SourceReader(source_code_path)
        self.stats_reader = AFLStatsReader(afl_out_dir)
        self.seed_output_dir = seed_output_dir
        self.seed_counter = 0
        self.seeds_accepted = 0
        os.makedirs(seed_output_dir, exist_ok=True)

    # ==================================================================
    # Has a working default via SourceReader -- override to customise.
    # ==================================================================

    def read_source_context(self):
        """Return source code of the target program for the LLM prompt.

        The default reads ``.java`` files from ``self.source_code_path``,
        extracts complete class definitions (prioritising applet /
        parser / input-handling classes), and assembles them into a
        budget-limited string via ``SourceReader``.

        CAN be overridden to:
          - Return a hand-written protocol summary instead.
          - Read only specific files or packages.
          - Swap in a different ``SourceReader`` configuration.

        Returns:
            str: Source code snippet or summary.
        """
        return self.source_reader.build_context()

    # ==================================================================
    # MUST implement -- no sensible default is possible here.
    # ==================================================================

    def call_llm(self, prompt):
        """Send *prompt* to an LLM and return the response text.

        MUST be implemented by every subclass.

        Connect to whichever LLM backend you prefer (Anthropic, OpenAI,
        a local model, etc.).

        Args:
            prompt: The full prompt string built by ``build_prompt()``.

        Returns:
            str: The raw LLM response text.
        """
        raise NotImplementedError(
            "Subclass LLMSeedGenerator and implement call_llm()")

    # ==================================================================
    # SHOULD consider overriding -- the defaults work but are generic.
    # Tailoring these to your target will significantly improve results.
    # ==================================================================

    def build_prompt(self, stats, queue_samples, source_context):
        """Build the LLM prompt from fuzzer state and source code.

        SHOULD be overridden to tailor the prompt to your target.

        The default prompt is a reasonable starting point, but you will
        get much better seeds if you:
          - Describe the expected input format (grammar, protocol, etc.).
          - Include coverage gaps or unreached branches if available.
          - Ask for specific mutation strategies when coverage stalls.

        Args:
            stats: dict from AFLStatsReader.read_stats().
            queue_samples: list of (filename, bytes) from read_queue_entries().
            source_context: str from read_source_context().

        Returns:
            str: The prompt to send to the LLM.
        """
        # Show a few queue samples as hex (truncated to 64 bytes each)
        sample_lines = []
        for fname, data in queue_samples[:5]:
            hex_str = data[:64].hex()
            sample_lines.append(f"  {fname}: {hex_str}")
        samples_text = "\n".join(sample_lines) if sample_lines else "  (none)"

        stalling = self.stats_reader.is_coverage_stalling()

        prompt = f"""\
You are a fuzzing expert. Generate new test inputs for a target program
that will explore uncovered code paths.

=== Target Source Code ===
{source_context}

=== Current Fuzzer Stats ===
- Total paths: {stats.get('paths_total', '?')}
- Paths found this run: {stats.get('paths_found', '?')}
- Unique crashes: {stats.get('saved_crashes', '?')}
- Bitmap coverage: {stats.get('bitmap_cvg', '?')}
- Execs per second: {stats.get('execs_per_sec', '?')}
- Cycles without new finds: {stats.get('cycles_wo_finds', '?')}
- Coverage is stalling: {stalling}

=== Recent Queue Samples (hex, truncated to 64 bytes) ===
{samples_text}

=== Instructions ===
Generate 5 new test inputs. Each input should be designed to exercise
different code paths in the target. Consider:
- Edge cases in parsing logic
- Boundary values
- Unusual but valid input structures
- Inputs that might trigger error-handling paths

Return ONLY the raw hex-encoded test inputs, one per line.
Do not include any explanation or commentary, just hex strings."""

        return prompt

    def parse_seeds_from_response(self, response):
        """Parse LLM response text into a list of seed byte strings.

        CAN be overridden if your prompt asks for a different output
        format (e.g. base64, JSON array, raw text).

        The default implementation expects one hex-encoded seed per line
        and is fairly tolerant of markdown fences, ``0x`` prefixes, and
        bullet markers.

        Args:
            response: Raw LLM response text.

        Returns:
            list[bytes]: Parsed seeds.
        """
        seeds = []
        for line in response.strip().split("\n"):
            line = line.strip()
            # Skip empty lines and lines that look like commentary
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            # Strip markdown code fences
            if line.startswith("```") or line.startswith("---"):
                continue
            # Remove common prefixes like "0x" or bullet markers
            if line.startswith("0x") or line.startswith("0X"):
                line = line[2:]
            if line[:2] in ("- ", "* ", "> "):
                line = line[2:]
            # Remove any non-hex characters (spaces, colons in hex dumps)
            cleaned = "".join(c for c in line if c in "0123456789abcdefABCDEF")
            if not cleaned or len(cleaned) % 2 != 0:
                continue
            try:
                seed = bytes.fromhex(cleaned)
                if len(seed) > 0:
                    seeds.append(seed)
            except ValueError:
                continue
        return seeds

    # ==================================================================
    # CAN override -- these work out of the box for most setups.
    # Override only if you need custom file naming, deduplication, etc.
    # ==================================================================

    def write_seed(self, data):
        """Write a single seed file to the output directory.

        CAN be overridden to add deduplication, size limits, or custom
        file naming.

        AFL++ foreign sync detects new files by mtime, so each seed
        gets a unique filename.

        Args:
            data: Seed content as bytes.
        """
        fname = f"llm_seed_{self.seed_counter:06d}"
        path = os.path.join(self.seed_output_dir, fname)
        with open(path, "wb") as f:
            f.write(data)
        self.seed_counter += 1
        log.debug("Wrote seed %s (%d bytes)", fname, len(data))

    def check_accepted_seeds(self):
        """Check how many of our seeds AFL++ added to its queue.

        CAN be overridden for custom acceptance tracking or feedback
        mechanisms (e.g. adjusting prompts based on acceptance rate).

        Returns:
            int: Number of accepted seeds found in the queue.
        """
        if not self.stats_reader.instance_dir:
            return 0
        queue_dir = os.path.join(self.stats_reader.instance_dir, "queue")
        # Foreign sync entries contain the directory name in the filename
        dir_name = os.path.basename(self.seed_output_dir.rstrip("/"))
        count = 0
        try:
            for entry in os.listdir(queue_dir):
                if dir_name in entry:
                    count += 1
        except OSError:
            pass
        return count

    # ==================================================================
    # Core loop
    # ==================================================================

    def run_once(self):
        """Run one generation cycle: read state -> call LLM -> write seeds.

        Returns:
            int: Number of seeds generated and written.
        """
        stats = self.stats_reader.read_stats()
        if not stats:
            log.warning("No fuzzer stats available yet")
            return 0

        queue_samples = self.stats_reader.read_queue_entries(max_entries=10)
        # source_context = self.read_source_context()

        # prompt = self.build_prompt(stats, queue_samples, source_context)
        # log.info("Calling LLM (prompt length: %d chars) ...", len(prompt))
        #
        # response = self.call_llm(prompt)
        # log.debug("LLM response length: %d chars", len(response))
        #
        # seeds = self.parse_seeds_from_response(response)
        # log.info("Parsed %d seeds from LLM response", len(seeds))
        #
        # for seed in seeds:
        #     self.write_seed(seed)
        #
        # return len(seeds)

    def run_loop(self, interval_seconds=60):
        """Main loop: generate seeds periodically.

        Args:
            interval_seconds: Seconds between generation cycles.
        """
        log.info("LLM seed generator started")
        log.info("  Source: %s", self.source_code_path)
        log.info("  AFL++ output dir: %s", self.stats_reader.out_dir)
        log.info("  Seed output dir: %s", self.seed_output_dir)
        log.info("  Interval: %ds", interval_seconds)

        # Wait for AFL++ to start
        if not self.stats_reader.wait_for_fuzzer():
            log.error("AFL++ did not start within timeout. Exiting.")
            sys.exit(1)

        while True:
            try:
                t0 = time.time()
                n = self.run_once()
                elapsed = time.time() - t0

                accepted = self.check_accepted_seeds()
                log.info(
                    "Generated %d seeds in %.1fs "
                    "(total written: %d, accepted by AFL++: %d)",
                    n, elapsed, self.seed_counter, accepted)

            except KeyboardInterrupt:
                log.info("Interrupted. Total seeds written: %d",
                         self.seed_counter)
                break
            except Exception:
                log.exception("Error in generation cycle")

            time.sleep(interval_seconds)
