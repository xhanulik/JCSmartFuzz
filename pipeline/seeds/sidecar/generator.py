"""Base class for LLM-based seed generation.

Subclass ``LLMSeedGenerator`` and implement ``call_llm()`` to create a
working generator.  ``read_source_context()`` has a default that reads
Java source via ``SourceReader`` -- override it if the target is not
Java or if you need custom extraction.

See ``__main__.py`` for the CLI entry point.
"""

import hashlib
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from afl_stats_reader import AFLStatsReader, parse_queue_name
from source_reader import SourceReader

# ---------------------------------------------------------------------------
# Prompt templates live in prompts/ as editable text files (with {{marker}}
# placeholders) so the wording can be tuned without touching this code.
# ---------------------------------------------------------------------------
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt(name):
    """Read a prompt template from prompts/<name>."""
    return (PROMPTS_DIR / name).read_text(encoding="utf-8")


def render_prompt(template, **values):
    """Substitute every {{name}} marker in *template* from *values* in a single
    pass (inserted values are never re-scanned for further markers). Raises
    KeyError if the template references a marker that was not supplied."""
    return re.sub(r"{{\s*(\w+)\s*}}", lambda m: str(values[m.group(1)]), template)

log = logging.getLogger(__name__)

# LLM backend settings (endpoint/model/timeout/token) are resolved through the
# shared pipeline config loader -- env var > llm_config.ini > default -- so no
# provider specifics are hardcoded here.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import llm_config


def _parse_ab_halves(content):
    """Parse the fixed-offset A/B input layout from a queue entry's bytes.

    Layout: [ p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA)
             | p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA) ]

    MAX_DATA is inferred as (len(content) - 6) // 2.

    Returns a dict with p1_A/B, p2_A/B, len_A/B, or None if content is
    too short to parse.
    """
    if len(content) < 6:
        return None
    max_data = (len(content) - 6) // 2
    slot_b = 3 + max_data
    if slot_b + 2 >= len(content):
        return None
    return {
        "p1_A":  content[0],
        "p2_A":  content[1],
        "len_A": content[2],
        "p1_B":  content[slot_b],
        "p2_B":  content[slot_b + 1],
        "len_B": content[slot_b + 2],
    }


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
                 op_name=None, model=None, api_token=None,
                 print_prompt=False, llm_timeout=None):
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
            model: Model name or alias; when ``None``, resolved from
                env/llm_config.ini via pipeline.llm_config.
            api_token: Bearer token for the LLM API.  When ``None``, resolved
                from env (LLM_API_TOKEN) / llm_config.ini.
        """
        self.source_code_path = source_code_path
        self.op_name = op_name
        self.source_reader = SourceReader(source_code_path)
        self.stats_reader = AFLStatsReader(afl_out_dir)
        self.seed_output_dir = seed_output_dir
        self.seed_counter = 0
        self.seeds_accepted = 0
        # Resolve backend settings via env var > llm_config.ini > default.
        self.model = model or llm_config.model()
        self.api_token = api_token or llm_config.api_token()
        self.print_prompt = print_prompt
        self.llm_timeout = llm_timeout if llm_timeout is not None else llm_config.timeout()
        os.makedirs(seed_output_dir, exist_ok=True)

        # Deduplication: hashes of seeds already written (pre-populated from
        # existing files so restarts don't re-write the same seeds).
        self._seen_hashes: set = set()
        for fname in os.listdir(seed_output_dir):
            fpath = os.path.join(seed_output_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "rb") as f:
                        self._seen_hashes.add(hashlib.sha256(f.read()).digest())
                except OSError:
                    pass

        # Acceptance-rate tracking across generation cycles.
        self._last_acceptance_rate: float = 0.0
        self._seed_counter_prev: int = 0
        self._seeds_accepted_prev: int = 0

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
        """Send *prompt* to the configured LLM API and return the reply text.

        Uses the OpenAI-compatible ``/v1/chat/completions`` endpoint from
        pipeline.llm_config with ``self.model`` and ``self.api_token``.

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
            llm_config.endpoint(),
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.llm_timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"LLM API HTTP {e.code} {e.reason}: {err_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"LLM API network error: {e.reason}") from e
        except TimeoutError as e:
            raise RuntimeError(
                f"LLM API timed out after {self.llm_timeout}s "
                f"(increase --timeout for slow models)") from e

        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError(
                f"LLM API returned no choices: {payload!r}")
        return choices[0]["message"]["content"]

    # ==================================================================
    # SHOULD consider overriding -- the defaults work but are generic.
    # Tailoring these to your target will significantly improve results.
    # ==================================================================

    # Scoring weights for non-original queue entries.  The tuple order is
    # (coverage-increasing flag, instructions, time, user_defined, len_diff,
    # param_diff); sorted descending, so +cov entries always outrank non-+cov
    # ones, then by instruction count, wall-clock time, user-defined cost, and
    # finally a bonus for entries whose A/B halves already differ structurally.
    def score_queue_entry(self, entry):
        """Return a sort key for ranking non-original queue entries.

        CAN be overridden to combine other signals (time, memory,
        user-defined cost).  Originals are never scored -- they are
        always included unconditionally.
        """
        ab = entry.get("ab") or {}
        len_diff  = abs(ab.get("len_A", 0) - ab.get("len_B", 0))
        param_diff = int(ab.get("p1_A", 0) != ab.get("p1_B", 0) or
                         ab.get("p2_A", 0) != ab.get("p2_B", 0))
        return (
            1 if entry["is_cov"] else 0,
            entry["instructions"],
            entry.get("time", 0),
            entry.get("user_defined", 0),
            len_diff,
            param_diff,
        )

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
                ``instructions``, ``time``, ``user_defined``,
                ``is_original``, ``is_cov``, ``op``, ``ab``.
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
                "time":         cost.get("time", 0),
                "user_defined": cost.get("user_defined", 0),
                "is_original":  meta["is_original"],
                "is_cov":       meta["is_cov"],
                "op":           meta["op"],
                "ab":           _parse_ab_halves(content),
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
            ab = e.get("ab")
            if ab:
                p1_rel = "DIFFER" if ab["p1_A"] != ab["p1_B"] else "same"
                p2_rel = "DIFFER" if ab["p2_A"] != ab["p2_B"] else "same"
                ab_line = (
                    f"A/B diff: "
                    f"p1=0x{ab['p1_A']:02X}/0x{ab['p1_B']:02X} ({p1_rel})  "
                    f"p2=0x{ab['p2_A']:02X}/0x{ab['p2_B']:02X} ({p2_rel})  "
                    f"len={ab['len_A']}/{ab['len_B']} "
                    f"(delta={abs(ab['len_A'] - ab['len_B'])})\n"
                )
            else:
                ab_line = ""
            blocks.append(
                f"{header}\n"
                f"Length: {len(e['content'])}\n"
                f"Instructions: {e['instructions']}\n"
                f"Time: {e.get('time', 0)}\n"
                f"User-defined cost: {e.get('user_defined', 0)}\n"
                f"Discovered via: {e['op'] or 'unknown'}\n"
                f"Coverage-increasing: {cov}\n"
                f"{ab_line}"
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

        # --- Fuzzer state section (enhancement 2) ---
        bitmap_cvg  = stats.get("bitmap_cvg",  "?")
        cycles_done = stats.get("cycles_done", "?")
        corpus_count= stats.get("corpus_count","?")
        edges_found = stats.get("edges_found", "?")
        try:
            last_find_age = int(time.time()) - int(stats["last_find"])
            last_find_str = f"{last_find_age // 60}m {last_find_age % 60}s ago"
        except (KeyError, ValueError):
            last_find_str = "unknown"

        try:
            cycles_int   = int(cycles_done)
            coverage_pct = float(str(bitmap_cvg).rstrip("%"))
            if cycles_int > 5 and coverage_pct < 5.0:
                coverage_hint = (
                    "Coverage has been low for many cycles. "
                    "Focus on unexplored edge-case byte values and rarely-taken branches."
                )
            else:
                coverage_hint = (
                    "Diversify the structural variety of inputs across different "
                    "p1, p2, and len combinations."
                )
        except (ValueError, TypeError):
            coverage_hint = "Diversify inputs across different p1, p2, and len combinations."

        fuzzer_state_section = (
            f"Cycles completed: {cycles_done}\n"
            f"Edges found: {edges_found}  (bitmap coverage: {bitmap_cvg})\n"
            f"Corpus size: {corpus_count}\n"
            f"Last new path: {last_find_str}\n"
            f"Guidance: {coverage_hint}"
        )

        # --- Acceptance-rate feedback (enhancement 6) ---
        rate = self._last_acceptance_rate
        if rate > 0:
            acceptance_feedback = (
                f"Last generation cycle: {rate * 100:.0f}% of generated seeds "
                f"were accepted into the AFL++ queue."
            )
            if rate < 0.15:
                acceptance_feedback += (
                    " Acceptance is low — try more structurally varied inputs."
                )
        else:
            acceptance_feedback = ""

        acceptance_line = f"- {acceptance_feedback}" if acceptance_feedback else ""

        return render_prompt(
            load_prompt("seed_generation.md"),
            input_format=input_format,
            input_mapping=input_mapping,
            source_context=source_context,
            fuzzer_state_section=fuzzer_state_section,
            inputs_section=inputs_section,
            acceptance_line=acceptance_line,
        )

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
        h = hashlib.sha256(data).digest()
        if h in self._seen_hashes:
            log.debug("Skipping duplicate seed (%d bytes)", len(data))
            return
        self._seen_hashes.add(h)

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
        count = 0
        try:
            for entry in os.listdir(queue_dir):
                if "sync" in entry:
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
        if self.print_prompt:
            print("\n" + "=" * 72)
            print(prompt)
            print("=" * 72 + "\n")

        response = self.call_llm(prompt)
        log.debug("LLM response length: %d chars", len(response))

        seeds = self.parse_seeds_from_response(response)
        log.info("Parsed %d seeds from LLM response", len(seeds))

        for seed in seeds:
            self.write_seed(seed)

        return len(seeds)

    def run_loop(self, interval_seconds=60, duration_seconds=None):
        """Main loop: generate seeds periodically.

        Args:
            interval_seconds: Seconds between generation cycles.
            duration_seconds: Stop after this many seconds have elapsed since
                the first cycle started.  ``None`` means run indefinitely.
                Set to the same value as AFL++'s ``-V`` flag so both processes
                finish together.
        """
        log.info("LLM seed generator started")
        log.info("  Source: %s", self.source_code_path)
        log.info("  AFL++ output dir: %s", self.stats_reader.out_dir)
        log.info("  Seed output dir: %s", self.seed_output_dir)
        log.info("  Model: %s", self.model)
        log.info("  LLM timeout: %ds", self.llm_timeout)
        log.info("  Interval: %ds", interval_seconds)
        if duration_seconds is not None:
            log.info("  Duration: %ds", duration_seconds)

        # Wait for AFL++ to start
        if not self.stats_reader.wait_for_fuzzer():
            log.error("AFL++ did not start within timeout. Exiting.")
            sys.exit(1)

        start_time = time.time()

        while True:
            if duration_seconds is not None:
                if time.time() - start_time >= duration_seconds:
                    log.info("Duration limit reached. Total seeds written: %d",
                             self.seed_counter)
                    break

            try:
                t0 = time.time()
                n = self.run_once()
                elapsed = time.time() - t0

                accepted = self.check_accepted_seeds()

                delta_written  = self.seed_counter - self._seed_counter_prev
                delta_accepted = accepted - self._seeds_accepted_prev
                if delta_written > 0:
                    self._last_acceptance_rate = delta_accepted / delta_written
                self._seed_counter_prev  = self.seed_counter
                self._seeds_accepted_prev = accepted

                log.info(
                    "Generated %d seeds in %.1fs "
                    "(total written: %d, accepted by AFL++: %d, "
                    "cycle acceptance: %.0f%%)",
                    n, elapsed, self.seed_counter, accepted,
                    self._last_acceptance_rate * 100)

            except KeyboardInterrupt:
                log.info("Interrupted. Total seeds written: %d",
                         self.seed_counter)
                break
            except Exception:
                log.exception("Error in generation cycle")

            if duration_seconds is not None:
                remaining = duration_seconds - (time.time() - start_time)
                if remaining <= 0:
                    log.info("Duration limit reached. Total seeds written: %d",
                             self.seed_counter)
                    break
                time.sleep(min(interval_seconds, remaining))
            else:
                time.sleep(interval_seconds)
