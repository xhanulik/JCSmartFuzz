"""LLM-based initial seed generator for JCSmartFuzz campaigns.

Unlike the AFL++ side-car in jcfuzzgen/llm_seed_generator/, this generator runs
*before* fuzzing starts and produces the initial corpus.  It reads the target
FuzzApplet Java source, extracts the relevant method(s) via SourceReader, and
asks the LLM to produce seeds covering timing-sensitive branches.

The generated seeds conform to the fixed-offset layout consumed by every
generated FuzzDriverXxx.java:

    [ p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA)
    | p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA) ]
    Total: 6 + 2 × MAX_DATA bytes

Reuses SourceReader from jcfuzzgen/llm_seed_generator/ (imported via sys.path).

Extension points
----------------
- ``read_source_context()``        -- override to change source extraction.
- ``build_prompt()``               -- override to tune the prompt.
- ``call_llm()``                   -- override to use a different backend.
- ``parse_seeds_from_response()``  -- override for a different output format.
- ``write_seed()``                 -- override for custom naming/deduplication.
"""

import hashlib
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Reuse SourceReader from jcfuzzgen/llm_seed_generator/
# ---------------------------------------------------------------------------

_LLM_GEN_DIR = Path(__file__).resolve().parent.parent / "jcfuzzgen" / "llm_seed_generator"
if str(_LLM_GEN_DIR) not in sys.path:
    sys.path.insert(0, str(_LLM_GEN_DIR))

try:
    from source_reader import SourceReader
    HAS_SOURCE_READER = True
except ImportError:
    HAS_SOURCE_READER = False
    SourceReader = None  # type: ignore[assignment,misc]

log = logging.getLogger(__name__)

# e-INFRA CZ AI-as-a-Service (OpenAI-compatible) chat completions endpoint.
# See https://docs.cerit.io/en/docs/ai-as-a-service/ai-api
E_INFRA_ENDPOINT = "https://llm.ai.e-infra.cz/v1/chat/completions"
E_INFRA_DEFAULT_MODEL = "gpt-oss-120b"
E_INFRA_TIMEOUT_SECONDS = 120


class LLMSeedGenerator:
    """Generates initial corpus seeds using an LLM.

    Reads a FuzzApplet Java source file, extracts the relevant wrapper and core
    method(s) via SourceReader, and calls an LLM to produce hex-encoded seeds
    that maximally cover timing-sensitive branches in the target operation.

    Lifecycle::

        gen = LLMSeedGenerator(source_path, output_dir, op_name="HmacSha160")
        gen.run_once()   # one-shot
        # or
        gen.run(count=3) # multiple cycles, seeds deduplicated across runs

    Extension points — see the per-method docstrings below.
    """

    def __init__(self, source_code_path, seed_output_dir,
                 op_name=None, max_data=None,
                 model=E_INFRA_DEFAULT_MODEL, api_token=None,
                 print_prompt=False, llm_timeout=E_INFRA_TIMEOUT_SECONDS):
        """
        Args:
            source_code_path: Path to the ``*FuzzApplet.java`` source file.
            seed_output_dir:  Directory where seed files are written.
            op_name:          Operation name ``Xxx``.  When set, the prompt
                              contains only ``wrap<Xxx>`` and ``core<Xxx>``
                              extracted from the source.  When ``None``, the
                              full class is used.
            max_data:         ``MAX_DATA`` value for the operation.  When set,
                              the prompt and length validation use this value.
                              When ``None``, the LLM is instructed to infer it
                              from the source.
            model:            Model name on the e-INFRA CZ endpoint.
            api_token:        Bearer token.  Falls back to ``LLM_API_TOKEN``
                              env var when ``None``.
            print_prompt:     Print the prompt to stdout before each cycle.
            llm_timeout:      Seconds to wait for the LLM API response.
        """
        if not HAS_SOURCE_READER:
            raise ImportError(
                "SourceReader not found. "
                "Ensure jcfuzzgen/llm_seed_generator/ exists in the repo.")

        self.source_code_path = source_code_path
        self.op_name = op_name
        self.max_data = max_data
        self.source_reader = SourceReader(source_code_path)
        self.seed_output_dir = seed_output_dir
        self.seed_counter = 0
        self.model = model
        self.api_token = api_token or os.environ.get("LLM_API_TOKEN")
        self.print_prompt = print_prompt
        self.llm_timeout = llm_timeout
        os.makedirs(seed_output_dir, exist_ok=True)

        # Deduplication: hashes of seeds already in the output directory so
        # restarts and multiple cycles don't re-write the same content.
        self._seen_hashes: set = set()
        for fname in os.listdir(seed_output_dir):
            fpath = os.path.join(seed_output_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "rb") as f:
                        self._seen_hashes.add(hashlib.sha256(f.read()).digest())
                except OSError:
                    pass

    # ==================================================================
    # Has a working default via SourceReader — override to customise.
    # ==================================================================

    def read_source_context(self):
        """Return source code of the target operation for the LLM prompt.

        When ``self.op_name`` is set, returns just ``wrap<OpName>`` and
        ``core<OpName>`` extracted from the source (same strategy as the
        jcfuzzgen AFL++ side-car).  Otherwise, falls back to full-class
        extraction.

        CAN be overridden to return a hand-written summary, read multiple
        files, or swap in a different extraction strategy.

        Returns:
            str: Source code snippet or full-class text.
        """
        if self.op_name:
            return self.source_reader.build_method_context(
                [f"wrap{self.op_name}", f"core{self.op_name}"])
        return self.source_reader.build_context()

    # ==================================================================
    # MUST implement — no sensible default is possible here.
    # ==================================================================

    def call_llm(self, prompt):
        """Send *prompt* to the e-INFRA CZ AI API and return the reply text.

        Uses the OpenAI-compatible ``/v1/chat/completions`` endpoint.

        CAN be overridden to target a different backend (Anthropic, OpenAI,
        local Ollama, etc.).

        Args:
            prompt: The full prompt string built by ``build_prompt()``.

        Returns:
            str: The assistant message content from the first choice.

        Raises:
            RuntimeError: on missing token, HTTP error, or empty response.
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
                "(increase --timeout for slow models)") from e

        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError(f"LLM API returned no choices: {payload!r}")
        return choices[0]["message"]["content"]

    # ==================================================================
    # SHOULD consider overriding — the defaults work but are generic.
    # ==================================================================

    def build_prompt(self, source_context):
        """Build the LLM prompt from source code.

        CAN be overridden to tune wording, add extra constraints, or include
        previously generated seeds as negative examples.

        Args:
            source_context: str from ``read_source_context()``.

        Returns:
            str: The prompt to send to the LLM.
        """
        if self.max_data is not None:
            seed_size_info = (
                f"MAX_DATA = {self.max_data}  "
                f"(each seed is exactly {6 + 2 * self.max_data} bytes = "
                f"{(6 + 2 * self.max_data) * 2} hex characters)"
            )
        else:
            seed_size_info = (
                "MAX_DATA is defined in the source (see the wrapXxx Javadoc "
                "or guard). Each seed is 6 + 2*MAX_DATA bytes."
            )

        input_format = (
            "[ p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA) "
            "| p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA) ]"
        )

        input_mapping = (
            "buffer[ISO7816.OFFSET_P1]    = p1\n"
            "buffer[ISO7816.OFFSET_P2]    = p2\n"
            "buffer[ISO7816.OFFSET_LC]    = len\n"
            "buffer[ISO7816.OFFSET_CDATA] = start of data"
        )

        return f"""\
You are a fuzzing expert specialising in timing side-channel detection.
Your goal is to generate an initial corpus of seeds for a differential fuzzing
campaign targeting a Java Card applet operation.

Each seed encodes TWO independent invocations (A and B) of the same operation.
The applet executes the operation once with (p1_A, p2_A, len_A, data_A) and
once with (p1_B, p2_B, len_B, data_B) under identical applet state.  A timing
side-channel exists when the two executions take different code paths and
produce different instruction counts.

=== 1. Fuzzing input format ===
{input_format}
{seed_size_info}

Bytes 0–2       : p1_A, p2_A, len_A  (one byte each)
Bytes 3 – 3+MAX_DATA-1      : data_A slot (MAX_DATA bytes, padded)
Bytes 3+MAX_DATA – 5+MAX_DATA : p1_B, p2_B, len_B  (one byte each)
Bytes 6+MAX_DATA – 6+2*MAX_DATA-1 : data_B slot (MAX_DATA bytes, padded)

=== 2. Mapping of one input half to the actual APDU ===
{input_mapping}

=== 3. Fuzzed source code ===
{source_context}

=== Instructions ===
Examine the conditional branches in the source (section 3) that depend on
p1, p2, len, or data content.  Generate seeds that:

- Set A and B halves to enter OPPOSITE branches of timing-sensitive conditions
  (e.g. different p1/p2/len values, boundary data byte patterns).
- Cover edge values: p1=0 and p1=max, p2=0 and p2=max, len=0 and len=MAX_DATA.
- Include data patterns targeting known branches:
    all-zeros, all-0xFF, MSB=0x00 vs MSB=0x80, alternating 0x55/0xAA.
- Produce structurally diverse seeds: vary p1, p2, len, and data independently
  rather than changing all parameters at once.
- Pair boundary values: e.g. (p1_A=1, p1_B=max) to exercise loop-bound paths.

Return ONLY raw hex-encoded seeds, one per line.  No prose, no code fences,
no labels, no commentary.  Each line must represent a complete seed of the
correct length ({(6 + 2 * self.max_data) * 2} hex characters).""" \
            if self.max_data is not None else f"""\
You are a fuzzing expert specialising in timing side-channel detection.
Your goal is to generate an initial corpus of seeds for a differential fuzzing
campaign targeting a Java Card applet operation.

Each seed encodes TWO independent invocations (A and B) of the same operation.
The applet executes the operation once with (p1_A, p2_A, len_A, data_A) and
once with (p1_B, p2_B, len_B, data_B) under identical applet state.  A timing
side-channel exists when the two executions take different code paths and
produce different instruction counts.

=== 1. Fuzzing input format ===
{input_format}
{seed_size_info}

Bytes 0–2       : p1_A, p2_A, len_A  (one byte each)
Bytes 3 – 3+MAX_DATA-1      : data_A slot (MAX_DATA bytes, padded)
Bytes 3+MAX_DATA – 5+MAX_DATA : p1_B, p2_B, len_B  (one byte each)
Bytes 6+MAX_DATA – 6+2*MAX_DATA-1 : data_B slot (MAX_DATA bytes, padded)

=== 2. Mapping of one input half to the actual APDU ===
{input_mapping}

=== 3. Fuzzed source code ===
{source_context}

=== Instructions ===
Examine the conditional branches in the source (section 3) that depend on
p1, p2, len, or data content.  Generate seeds that:

- Set A and B halves to enter OPPOSITE branches of timing-sensitive conditions
  (e.g. different p1/p2/len values, boundary data byte patterns).
- Cover edge values: p1=0 and p1=max, p2=0 and p2=max, len=0 and len=MAX_DATA.
- Include data patterns targeting known branches:
    all-zeros, all-0xFF, MSB=0x00 vs MSB=0x80, alternating 0x55/0xAA.
- Produce structurally diverse seeds: vary p1, p2, len, and data independently
  rather than changing all parameters at once.
- Pair boundary values: e.g. (p1_A=1, p1_B=max) to exercise loop-bound paths.

Return ONLY raw hex-encoded seeds, one per line.  No prose, no code fences,
no labels, no commentary.  Each line must represent a complete seed of the
correct length (6 + 2*MAX_DATA bytes, expressed as 12 + 4*MAX_DATA hex chars)."""

    def parse_seeds_from_response(self, response):
        """Parse LLM response text into seed byte strings.

        Tolerant hex parser: strips markdown fences, ``0x`` prefixes, and
        bullet markers.  Skips empty lines and comment lines.

        CAN be overridden if the prompt asks for a different output format.

        Args:
            response: Raw LLM response text.

        Returns:
            list[bytes]: Parsed seeds (may be empty if the model misbehaved).
        """
        seeds = []
        for line in response.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if line.startswith("```") or line.startswith("---"):
                continue
            if line.lower().startswith("0x"):
                line = line[2:]
            if line[:2] in ("- ", "* ", "> "):
                line = line[2:]
            cleaned = "".join(c for c in line if c in "0123456789abcdefABCDEF")
            if not cleaned or len(cleaned) % 2 != 0:
                continue
            try:
                seed = bytes.fromhex(cleaned)
                if seed:
                    seeds.append(seed)
            except ValueError:
                continue
        return seeds

    # ==================================================================
    # CAN override — these work out of the box for most setups.
    # ==================================================================

    def write_seed(self, data):
        """Write a single deduplicated seed file to the output directory.

        Uses SHA-256 to skip identical seeds across calls and restarts.
        Filenames follow the ``llm_seed_XXXXXX`` pattern used by the
        jcfuzzgen AFL++ side-car, so both tools can write to the same
        directory without collisions.

        CAN be overridden for custom naming, size limits, or extra validation.

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

    # ==================================================================
    # Core execution
    # ==================================================================

    def run_once(self):
        """Run one generation cycle: read source → call LLM → write seeds.

        Returns:
            int: Number of new seeds written in this cycle.
        """
        source_context = self.read_source_context()
        prompt = self.build_prompt(source_context)

        log.info("Calling LLM (prompt %d chars, model %s) ...",
                 len(prompt), self.model)
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

    def run(self, count=1):
        """Run *count* independent generation cycles.

        Each cycle calls the LLM once.  Seeds are deduplicated across cycles
        so the same content is never written twice.

        Args:
            count: Number of LLM calls to make (default: 1).

        Returns:
            int: Total number of unique seeds written.
        """
        log.info("LLM seed generator — initial corpus mode")
        log.info("  Source      : %s", self.source_code_path)
        log.info("  Operation   : %s", self.op_name or "(full class)")
        log.info("  Output dir  : %s", self.seed_output_dir)
        log.info("  Model       : %s", self.model)
        log.info("  Cycles      : %d", count)

        total = 0
        for i in range(count):
            log.info("--- Cycle %d / %d ---", i + 1, count)
            try:
                n = self.run_once()
                total += n
                log.info("Cycle %d: %d seeds (total so far: %d)", i + 1, n, total)
            except KeyboardInterrupt:
                log.info("Interrupted after %d seeds.", total)
                break
            except Exception:
                log.exception("Error in generation cycle %d", i + 1)

        log.info("Done. Total seeds written: %d", total)
        return total
