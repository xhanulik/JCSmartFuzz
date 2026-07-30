"""LLM-based initial seed generator for JCSmartFuzz campaigns.

Unlike the AFL++ side-car in ../sidecar/, this generator runs *before* fuzzing
starts and produces the initial corpus. It works entirely from the JSON the
harness-extraction stage already produced -- `operation.json` (and optionally
`context.json`) -- rather than re-parsing the FuzzApplet source: `operation.json`
already contains the wrapper method (the exact byte->parameter unpacking), the
core method (the timing-sensitive logic), and a `data_layout_comment`. The LLM
is asked to produce seeds that drive those branches.

The generated seeds conform to the fixed-offset layout consumed by every
generated FuzzDriverXxx.java:

    [ p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA)
    | p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA) ]
    Total: 6 + 2 × MAX_DATA bytes

Extension points
----------------
- ``build_prompt()``               -- override to tune the prompt.
- ``call_llm()``                   -- override to use a different backend.
- ``parse_seeds_from_response()``  -- override for a different output format.
- ``write_seed()``                 -- override for custom naming/deduplication.
"""

import hashlib
import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# LLM backend settings (endpoint/model/timeout/token) are resolved through the
# shared pipeline config loader -- env var > llm_config.ini > default -- so no
# provider specifics are hardcoded here.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import llm_config

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

class LLMSeedGenerator:
    """Generates initial corpus seeds using an LLM.

    Reads the harness-extraction ``operation.json`` (wrapper + core methods and
    data layout) and calls an LLM to produce hex-encoded seeds that maximally
    cover timing-sensitive branches in the target operation.

    Lifecycle::

        operation = json.load(open("operation.json"))
        gen = LLMSeedGenerator(operation, output_dir, max_data=64)
        gen.run_once()   # one-shot
        # or
        gen.run(count=3) # multiple cycles, seeds deduplicated across runs

    Extension points — see the per-method docstrings below.
    """

    def __init__(self, operation, seed_output_dir,
                 max_data=None, context=None,
                 model=None, api_token=None,
                 print_prompt=False, llm_timeout=None):
        """
        Args:
            operation:        Parsed ``operation.json`` dict from the
                              harness-extraction stage (operation_name,
                              timing_risk, core_method, wrapper_method).
            seed_output_dir:  Directory where seed files are written.
            max_data:         ``MAX_DATA`` value for the operation.  When set,
                              the prompt and length validation use this value.
                              When ``None``, the LLM is instructed to infer it
                              from the layout.
            context:          Optional parsed ``context.json`` dict (fields,
                              constants, ins_byte) for extra prompt context.
            model:            Model name; when None, resolved from
                              env/llm_config.ini via pipeline.llm_config.
            api_token:        Bearer token.  Falls back to ``LLM_API_TOKEN``
                              env var when ``None``.
            print_prompt:     Print the prompt to stdout before each cycle.
            llm_timeout:      Seconds to wait for the LLM API response.
        """
        self.operation = operation
        self.context = context or {}
        self.op_name = operation.get("operation_name")
        self.max_data = max_data
        self.seed_output_dir = seed_output_dir
        # Resolve backend settings via env var > llm_config.ini > default.
        self.model = model or llm_config.model()
        self.api_token = api_token or llm_config.api_token()
        self.print_prompt = print_prompt
        self.llm_timeout = llm_timeout if llm_timeout is not None else llm_config.timeout()
        os.makedirs(seed_output_dir, exist_ok=True)

        # Deduplication: hashes of seeds already in the output directory so
        # restarts and multiple cycles don't re-write the same content.
        # Also find the highest existing llm_seed_NNNNNN id so the counter
        # starts above it and never overwrites an existing file.
        self._seen_hashes: set = set()
        max_existing_id = -1
        for fname in os.listdir(seed_output_dir):
            fpath = os.path.join(seed_output_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "rb") as f:
                        self._seen_hashes.add(hashlib.sha256(f.read()).digest())
                except OSError:
                    pass
                if fname.startswith("llm_seed_"):
                    try:
                        max_existing_id = max(max_existing_id,
                                              int(fname[len("llm_seed_"):]))
                    except ValueError:
                        pass
        self.seed_counter = max_existing_id + 1

    # ==================================================================
    # MUST implement — no sensible default is possible here.
    # ==================================================================

    def call_llm(self, prompt):
        """Send *prompt* to the configured LLM API and return the reply text.

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
                "(increase --timeout for slow models)") from e

        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError(f"LLM API returned no choices: {payload!r}")
        return choices[0]["message"]["content"]

    # ==================================================================
    # SHOULD consider overriding — the defaults work but are generic.
    # ==================================================================

    def build_prompt(self):
        """Build the LLM prompt from the harness-extraction JSON (self.operation).

        Uses the wrapper method (the exact byte->parameter unpacking), the core
        method (the timing-sensitive logic), and the data_layout_comment -- all
        already computed upstream, so no Java source is re-parsed here.

        CAN be overridden to tune wording, add extra constraints, or include
        previously generated seeds as negative examples.

        Returns:
            str: The prompt to send to the LLM.
        """
        wrapper = self.operation.get("wrapper_method", {}) or {}
        core = self.operation.get("core_method", {}) or {}
        data_layout = wrapper.get("data_layout_comment") or "(not specified)"
        wrapper_code = wrapper.get("code") or "(not available)"
        core_code = core.get("code") or "(not available)"
        timing_risk = self.operation.get("timing_risk") or "(not specified)"
        operation_name = self.op_name or "(unknown)"

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

        length_note = (
            f"{(6 + 2 * self.max_data) * 2} hex characters"
            if self.max_data is not None
            else "6 + 2*MAX_DATA bytes, expressed as 12 + 4*MAX_DATA hex chars"
        )

        return render_prompt(
            load_prompt("seed_generation.md"),
            operation_name=operation_name,
            timing_risk=timing_risk,
            input_format=input_format,
            seed_size_info=seed_size_info,
            input_mapping=input_mapping,
            data_layout=data_layout,
            wrapper_code=wrapper_code,
            core_code=core_code,
            length_note=length_note,
        )

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
        sidecar AFL++ generator, so both tools can write to the same
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
        """Run one generation cycle: build prompt from operation.json → call
        LLM → write seeds.

        Returns:
            int: Number of new seeds written in this cycle.
        """
        prompt = self.build_prompt()

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
        log.info("  Operation   : %s", self.op_name or "(unknown)")
        log.info("  MAX_DATA    : %s", self.max_data if self.max_data is not None else "(symbolic)")
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
