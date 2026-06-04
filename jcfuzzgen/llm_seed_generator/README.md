# LLM Seed Generator

## Purpose
A side-car process that augments an AFL++ fuzzing campaign with seeds produced by a large language model. It observes what AFL++ is doing, asks an LLM for new inputs likely to exercise unexplored paths, and feeds those inputs back to AFL++ via the foreign-sync (-F) mechanism.

## Data Flow

┌─────────────────────────────┐
│       AFL++  (-M main)      │
│   out/main/{queue,stats}    │
└──────────┬──────────────────┘
            │ reads
            ▼
┌──────────────────────────┐        ┌────────────────┐
│   LLMSeedGenerator       │──────▶│   LLM API      │
│   (run_loop every N s)   │◀──────│ (llm.ai.e-infra)│
└──────────┬───────────────┘        └────────────────┘
            │ writes seed files
            ▼
┌──────────────────────────┐
│   --seed-dir  ( -F )     │
└──────────┬───────────────┘
            │ foreign-synced
            ▼
AFL++ imports new files
into out/main/queue/...

Inputs the generator needs:

* `--source` — target applet .java file
* `--op-name` — operation Xxx (selects wrapXxx / coreXxx from source)
* `--afl-out` — AFL++'s -o directory (read)
* `--seed-dir` — AFL++'s -F directory (written to)
* `--model` — LLM name/alias on the e-INFRA CZ endpoint
* `LLM_API_TOKEN` env var — Bearer token

## Usage Examples

All commands must be run from the `jcfuzzgen/` directory so that `llm_seed_generator` is on the Python path:
```bash
cd jcfuzzgen
```

**List available models on the e-INFRA CZ endpoint:**
```bash
export LLM_API_TOKEN=<your-token>
python3 -m llm_seed_generator --list-models
```

**Basic run with the default model (`gpt-oss-120b`):**
```bash
export LLM_API_TOKEN=<your-token>
python3 -m llm_seed_generator \
    --source /path/to/MyApplet.java \
    --op-name VerifyPin \
    --afl-out /tmp/afl-out \
    --seed-dir /tmp/llm-seeds
```

**With a recommended coding-focused model and verbose logging:**
```bash
export LLM_API_TOKEN=<your-token>
python3 -m llm_seed_generator \
    --source /path/to/MyApplet.java \
    --op-name VerifyPin \
    --afl-out /tmp/afl-out \
    --seed-dir /tmp/llm-seeds \
    --model qwen3-coder-next \
    --verbose
```

**With a thinking/reasoning model and a longer generation interval:**
```bash
export LLM_API_TOKEN=<your-token>
python3 -m llm_seed_generator \
    --source /path/to/MyApplet.java \
    --op-name VerifyPin \
    --afl-out /tmp/afl-out \
    --seed-dir /tmp/llm-seeds \
    --model deepseek-v4-pro-thinking \
    --interval 120
```

AFL++ must be running with `-M main -F /tmp/llm-seeds` before or alongside the generator. Set `AFL_SYNC_TIME=1` for faster seed pickup (~30 s).

## One Generation Cycle

`LLMSeedGenerator.run_once()` does these steps in order:

1. **Read fuzzer state** — `AFLStatsReader.read_stats()` parses `fuzzer_stats`.
2. **Select interesting inputs** — `select_interesting_inputs()` pulls queue entries and ranks non-originals by `score_queue_entry()`. All originals are included unconditionally. Non-originals are sorted descending by: `+cov` flag → instruction count → wall-clock time → user-defined cost → A/B length delta → A/B parameter diff. Top 10 non-originals are kept.
3. **Read source context** — `read_source_context()` returns either the `wrapXxx` + `coreXxx` pair (if `--op-name` set) or the whole class.
4. **Build prompt** — `build_prompt()` assembles five sections:
   - Input byte layout and input-to-APDU mapping
   - Fuzzed source code
   - AFL++ fuzzer state (cycles done, edges found, bitmap coverage, corpus size, time since last new path, coverage-guided hint)
   - Selected queue inputs — for each: hex dump, length, instruction count, wall-clock time, user-defined cost, mutation operator, coverage flag, and A/B structural diff (p1/p2/len for both halves)
   - Instructions to the LLM — focused on constructing A/B pairs that enter opposite branches; includes per-cycle acceptance-rate feedback if available
5. **Call the LLM** — `call_llm()` uses the OpenAI-compatible endpoint with `Authorization: Bearer`. Raises `RuntimeError` on missing token, HTTP error, or empty response.
6. **Parse response** — `parse_seeds_from_response()` strips markdown fences, `0x` prefixes, and bullet markers; keeps only valid even-length hex strings; returns `list[bytes]`.
7. **Write seeds** — `write_seed()` computes a SHA-256 hash and skips duplicates (including seeds from previous runs, pre-loaded at startup). New seeds are written to `--seed-dir` as `llm_seed_%06d`.
8. **`run_loop()`** wraps the above in a `while True` with `time.sleep(--interval)` between iterations. At startup it calls `stats_reader.wait_for_fuzzer()` so the first cycle only runs after AFL++ has created `fuzzer_stats`. After each cycle it computes the per-cycle acceptance rate (fraction of written seeds AFL++ imported) and logs it alongside total written and accepted counts.

## AFL++ Integration Contract

* AFL must be launched with `-M <name>` so foreign sync is enabled.
* `-F` path (AFL side) and `--seed-dir` (generator side) must resolve to the same directory.
* The generator must not delete or modify seeds it already wrote — AFL's mtime cursor would either miss them or re-import stale copies.
* AFL's sync cadence is controlled by `AFL_SYNC_TIME` (minutes, default 20, halved for -M). Set AFL_SYNC_TIME=1 for ~30-second pickup.
* Seeds of size 0 or > 1 MiB are silently dropped by AFL; write_seed() relies on the caller producing reasonable sizes.
