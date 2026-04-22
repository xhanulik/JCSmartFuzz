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

## One Generation Cycle

LLMSeedGenerator.run_once() does these steps in order:

1. **Read fuzzer state** — `AFLStatsReader.read_stats()` parses fuzzer_stats.
2. **Select interesting inputs** — `select_interesting_inputs()` pulls queue entries, parses their filenames via `parse_queue_name()` (flags `+cov`, initial-seed vs. mutated, discovering operator), joins them with per-entry cost from path_costs.csv, sorts non-originals by `score_queue_entry()` = (`is_cov`, `instructions`). All originals included unconditionally.
3. **Read source context** — `read_source_context()` returns either the wrapXxx + coreXxx pair (if `--op-name` set) or the whole class.
4. **Build prompt** — `build_prompt()` assembles four sections: input byte layout, input-to-APDU mapping, source code, AFL++-selected inputs (hex-encoded). Ends with explicit instructions to emit hex-encoded inputs one per line.
5. **Call the LLM** — `call_llm()`  is OpenAI-compatible, with Authorization: Bearer. Raises RuntimeError on missing token / HTTP error / empty response.
6. **Parse response** — `parse_seeds_from_response()` strips markdown fences, 0x prefixes, bullets; keeps only valid hex pairs; yields `list[bytes]`.
7. **Write seeds** — `write_seed()` writes each parsed seed to `--seed-dir` as `llm_seed_%06d`. AFL++ imports by mtime, so unique filenames + fresh mtimes are what matters.
8. **`run_loop()`** wraps the above in a while True with time.sleep(--interval) between iterations. At startup it calls `stats_reader.wait_for_fuzzer()` so the first cycle only runs after AFL++ has created `fuzzer_stats`. Each iteration also logs how many of the generator's seeds AFL++ has actually imported, counted via `check_accepted_seeds()` (queue entries whose filename contains `sync:<seed-dir-basename>`).

## AFL++ Integration Contract

* AFL must be launched with `-M <name>` so foreign sync is enabled.
* `-F` path (AFL side) and `--seed-dir` (generator side) must resolve to the same directory.
* The generator must not delete or modify seeds it already wrote — AFL's mtime cursor would either miss them or re-import stale copies.
* AFL's sync cadence is controlled by `AFL_SYNC_TIME` (minutes, default 20, halved for -M). Set AFL_SYNC_TIME=1 for ~30-second pickup.
* Seeds of size 0 or > 1 MiB are silently dropped by AFL; write_seed() relies on the caller producing reasonable sizes.

## Features

* Basic functionality:
  * [x] Seed injection into fuzzing process
  * [x] New seeds based on `queue/` input
* LLM seed generation sources:
  * [x] Seeds with number of instructions reached
  * [ ] Seeds with user-defined cost
  * [x] Seeds with increased coverage
  * [ ] Already generated seeds
* AFL++:
  * [ ] More frequent sync with generated seeds
  * [ ] Rotate power schedule during fuzzing process
* Other:
  * [ ] Mutation strategies enhancement
  * [ ] Periodical minimization of generated seeds
  * [ ] Seed generation based on path exploration
  * [ ] Dictionary generation
  * [ ] Custom mutators via shared libraries
