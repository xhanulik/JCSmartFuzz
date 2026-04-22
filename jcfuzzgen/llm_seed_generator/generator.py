"""Base class for LLM-based seed generation.

Subclass ``LLMSeedGenerator`` and implement ``call_llm()`` to create a
working generator.  ``read_source_context()`` has a default that reads
Java source via ``SourceReader`` -- override it if the target is not
Java or if you need custom extraction.

See ``__main__.py`` for the CLI entry point.
"""

import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request

from afl_stats_reader import AFLStatsReader, parse_queue_name
from source_reader import SourceReader

log = logging.getLogger(__name__)

# e-INFRA CZ AI-as-a-Service (OpenAI-compatible) chat completions endpoint.
# See https://docs.cerit.io/en/docs/ai-as-a-service/ai-api
E_INFRA_ENDPOINT = "https://llm.ai.e-infra.cz/v1/chat/completions"
E_INFRA_DEFAULT_MODEL = "gpt-oss-120b"
E_INFRA_TIMEOUT_SECONDS = 120


def _format_hex(data, bytes_per_line=16):
    """Render *data* as space-separated uppercase hex, wrapped in lines."""
    out = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        out.append(" ".join(f"{b:02X}" for b in chunk))
    return "\n".join(out) if out else "(empty)"


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

    def __init__(self, source_code_path, afl_out_dir, seed_output_dir,
                 op_name=None, model=E_INFRA_DEFAULT_MODEL, api_token=None):
        """
        Args:
            source_code_path: Path to the target applet .java source file.
            afl_out_dir: AFL++ ``-o`` output directory.
            seed_output_dir: Destination for generated seeds
                (AFL++ ``-F`` foreign-sync target).
            op_name: Operation name ``Xxx``.  When set, the prompt
                contains only ``wrap<Xxx>`` and ``core<Xxx>`` extracted
                from the source.  When ``None``, the source reader falls
                back to full-class extraction.
            model: Model name or alias on the e-INFRA CZ endpoint
                (e.g. ``"llama3.3:latest"``, ``"coder"``, ``"mini"``).
            api_token: Bearer token for the e-INFRA CZ API.  When
                ``None``, falls back to the ``LLM_API_TOKEN`` env var.
        """
        self.source_code_path = source_code_path
        self.op_name = op_name
        self.source_reader = SourceReader(source_code_path)
        self.stats_reader = AFLStatsReader(afl_out_dir)
        self.seed_output_dir = seed_output_dir
        self.seed_counter = 0
        self.seeds_accepted = 0
        self.model = model
        self.api_token = api_token or os.environ.get("LLM_API_TOKEN")
        os.makedirs(seed_output_dir, exist_ok=True)

    # ==================================================================
    # Has a working default via SourceReader -- override to customise.
    # ==================================================================

    def read_source_context(self):
        """Return source code of the target program for the LLM prompt.

        When ``self.op_name`` is set, returns just ``wrap<OpName>`` and
        ``core<OpName>`` extracted from the source.  Otherwise, falls
        back to the full class extraction provided by ``SourceReader``.

        CAN be overridden to:
          - Return a hand-written protocol summary instead.
          - Read only specific files or packages.
          - Swap in a different ``SourceReader`` configuration.

        Returns:
            str: Source code snippet or summary.
        """
        if self.op_name:
            return self.source_reader.build_method_context(
                [f"wrap{self.op_name}", f"core{self.op_name}"])
        return self.source_reader.build_context()

    # ==================================================================
    # MUST implement -- no sensible default is possible here.
    # ==================================================================

    def call_llm(self, prompt):
        """Send *prompt* to the e-INFRA CZ AI API and return the reply text.

        Uses the OpenAI-compatible ``/v1/chat/completions`` endpoint at
        ``llm.ai.e-infra.cz`` with ``self.model`` and ``self.api_token``.

        CAN be overridden to target a different backend (Anthropic,
        OpenAI, local, etc.).

        Args:
            prompt: The full prompt string built by ``build_prompt()``.

        Returns:
            str: The assistant message content from the first choice.

        Raises:
            RuntimeError: if the API token is missing, the HTTP call
                fails, or the response has no choices.
        """
        if not self.api_token:
            raise RuntimeError(
                "LLM_API_TOKEN is not set. Export the env var or pass "
                "api_token=... to LLMSeedGenerator.")

        body = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }).encode("utf-8")

        req = urllib.request.Request(
            E_INFRA_ENDPOINT,
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=E_INFRA_TIMEOUT_SECONDS) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"LLM API HTTP {e.code} {e.reason}: {err_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"LLM API network error: {e.reason}") from e

        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError(
                f"LLM API returned no choices: {payload!r}")
        return choices[0]["message"]["content"]

    # ==================================================================
    # SHOULD consider overriding -- the defaults work but are generic.
    # Tailoring these to your target will significantly improve results.
    # ==================================================================

    # Scoring weights for non-original queue entries.  The tuple order
    # is (coverage-increasing flag, instructions hit); sorted descending,
    # so +cov entries outrank non-+cov entries regardless of instruction
    # count, and among equals the higher instruction count wins.
    def score_queue_entry(self, entry):
        """Return a sort key for ranking non-original queue entries.

        CAN be overridden to combine other signals (time, memory,
        user-defined cost).  Originals are never scored -- they are
        always included unconditionally.
        """
        return (1 if entry["is_cov"] else 0, entry["instructions"])

    def select_interesting_inputs(self, max_entries=10):
        """Select queue entries to show to the LLM.

        All original seeds are included unconditionally.  The remaining
        slots are filled with the highest-scoring non-original entries
        according to ``score_queue_entry()``.

        Args:
            max_entries: Soft cap on the number of non-original entries;
                originals are always in addition to this.

        Returns:
            list[dict]: Each dict has keys ``filename``, ``content``,
                ``instructions``, ``is_original``, ``is_cov``, ``op``.
        """
        if not self.stats_reader.instance_dir:
            return []
        queue_dir = os.path.join(self.stats_reader.instance_dir, "queue")
        if not os.path.isdir(queue_dir):
            return []

        # filename -> instructions (from path_costs.csv, if present)
        costs_by_name = {row["filename"]: row
                         for row in self.stats_reader.read_path_costs()}

        entries = []
        for fname in sorted(os.listdir(queue_dir)):
            if not fname.startswith("id:"):
                continue
            path = os.path.join(queue_dir, fname)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as f:
                    content = f.read()
            except OSError:
                continue
            meta = parse_queue_name(fname)
            cost = costs_by_name.get(fname, {})
            entries.append({
                "filename":     fname,
                "content":      content,
                "instructions": cost.get("instructions", 0),
                "is_original":  meta["is_original"],
                "is_cov":       meta["is_cov"],
                "op":           meta["op"],
            })

        originals = [e for e in entries if e["is_original"]]
        others    = [e for e in entries if not e["is_original"]]
        others.sort(key=self.score_queue_entry, reverse=True)

        return originals + others[:max_entries]

    def format_interesting_inputs(self, entries):
        """Render selected queue entries as prompt-ready text blocks."""
        if not entries:
            return "(no queue entries available yet)"

        blocks = []
        seed_n = 0
        input_n = 0
        for e in entries:
            if e["is_original"]:
                seed_n += 1
                header = f"Seed {seed_n}:"
            else:
                input_n += 1
                header = f"Input {input_n}:"
            cov = "YES" if (e["is_cov"] or e["is_original"]) else "NO"
            blocks.append(
                f"{header}\n"
                f"Length: {len(e['content'])}\n"
                f"Instructions: {e['instructions']}\n"
                f"Discovered via: {e['op'] or 'unknown'}\n"
                f"Coverage-increasing: {cov}\n"
                f"Hex encoded fuzzing input:\n"
                f"{_format_hex(e['content'])}"
            )
        return "\n\n".join(blocks)

    def build_prompt(self, stats, interesting_inputs, source_context):
        """Build the LLM prompt from fuzzer state and source code.

        Args:
            stats: dict from AFLStatsReader.read_stats().
            interesting_inputs: list[dict] from select_interesting_inputs().
            source_context: str from read_source_context().

        Returns:
            str: The prompt to send to the LLM.
        """
        input_format = (
            "[ p1_A | p2_A | len_A | data_A(MAX_DATA) "
            "| p1_B | p2_B | len_B | data_B(MAX_DATA) ]"
        )

        input_mapping = (
            "buffer[ISO7816.OFFSET_P1]    = p1\n"
            "buffer[ISO7816.OFFSET_P2]    = p2\n"
            "buffer[ISO7816.OFFSET_LC]    = len\n"
            "buffer[ISO7816.OFFSET_CDATA] = start of data"
        )

        inputs_section = self.format_interesting_inputs(interesting_inputs)

        prompt = f"""\
You are a fuzzing expert.  Generate new test inputs for a Java Card
applet that will explore uncovered code paths and expose timing
side-channel differences between input sets A and B.

=== 1. Fuzzing input format received by driver ===
{input_format}

=== 2. Mapping of one fuzzing input to the actual values ===
{input_mapping}

=== 3. Fuzzed source code ===
{source_context}

=== 4. AFL++ interesting inputs ===
{inputs_section}

=== Instructions ===
Generate new test inputs that follow the exact byte layout shown in
section 1.  Prefer inputs that:
- Exercise code paths not covered by the seeds/inputs above.
- Drive A and B down divergent branches to surface timing leaks.
- Explore edge values of p1, p2, and len (including len == 0 and
  len == MAX_DATA).

Return ONLY the raw hex-encoded test inputs, one per line.  No prose,
no code fences, no commentary."""

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

        interesting = self.select_interesting_inputs(max_entries=10)
        source_context = self.read_source_context()

        prompt = self.build_prompt(stats, interesting, source_context)
        log.info("Calling LLM (prompt length: %d chars) ...", len(prompt))

        response = self.call_llm(prompt)
        log.debug("LLM response length: %d chars", len(response))

        seeds = self.parse_seeds_from_response(response)
        log.info("Parsed %d seeds from LLM response", len(seeds))

        for seed in seeds:
            self.write_seed(seed)

        return len(seeds)

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
