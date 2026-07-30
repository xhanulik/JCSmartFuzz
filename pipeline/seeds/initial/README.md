# initial — Initial Seed Generator

Generates the initial corpus for JCSmartFuzz fuzzing campaigns.  Combines two
complementary strategies:

| Strategy | Module | When to use |
|----------|--------|-------------|
| **LLM-generated seeds** | `generator.py` (`LLMSeedGenerator`) | Targeted coverage of timing-sensitive branches, driven by the harness-extraction JSON |
| **Deterministic seeds** | `generate_seeds.py` | Fast, reproducible baseline — no API token, no network (identical/differential/boundary/random) |

The LLM strategy works entirely from the JSON the **harness-extraction stage
already produced** — `operation.json` (and optionally `context.json`) — instead
of re-parsing the FuzzApplet source. `operation.json` already contains the
wrapper method (the exact byte→parameter unpacking), the core method (the
timing-sensitive logic), and a `data_layout_comment`, which is precisely the
context the seed prompt needs.

Both strategies produce seeds in the fixed-offset layout consumed by every
generated `FuzzDriverXxx.java`:

```
Offset      Size        Field
──────      ─────────   ──────────────────
0           1           p1_A
1           1           p2_A
2           1           len_A
3           MAX_DATA    data_A slot
3+MAX_DATA  1           p1_B
4+MAX_DATA  1           p2_B
5+MAX_DATA  1           len_B
6+MAX_DATA  MAX_DATA    data_B slot
Total: 6 + 2 × MAX_DATA bytes
```

---

## Requirements

- Python 3.10+
- LLM backend configured (env vars or `llm_config.ini`) — **only for
  LLM-generated seeds**; `--no-llm` mode needs no token or network
- `operation.json` from the harness-extraction stage — the input for LLM mode
- `../../harness/drivergen/generate_drivers.py` present — only used to
  auto-detect MAX_DATA from the wrapper code (falls back gracefully if absent)

---

## Usage

### Deterministic seeds only — no LLM, no API token

**MAX_DATA known directly (no JSON needed):**

```bash
python -m initial --no-llm --max-data 64 --output-dir seeds/HmacSha160
```

**From operation.json (MAX_DATA auto-detected from the wrapper):**

```bash
python -m initial --no-llm --operation operation.json --output-dir seeds/HmacSha160
```

### LLM-generated seeds

```bash
export LLM_API_TOKEN=<token>          # or set it in llm_config.ini

python -m initial \
    --operation operation.json \
    --output-dir seeds/HmacSha160
```

Optionally pass the matching `context.json` for extra prompt context and/or
override MAX_DATA:

```bash
python -m initial \
    --operation operation.json \
    --context context.json \
    --max-data 64 \
    --output-dir seeds/HmacSha160
```

### Combined (default behaviour)

By default, `python -m initial --operation …` writes **both** LLM-generated and
deterministic seeds to the same output directory.

| Goal | Flags |
|------|-------|
| LLM + deterministic | *(default)* |
| LLM only | `--no-deterministic` |
| Deterministic only | `--no-llm` |

---

## CLI options

| Argument | Description |
|----------|-------------|
| `--operation PATH` | Path to `operation.json` (harness-extraction output). Required for LLM generation. |
| `--context PATH` | Optional `context.json` for extra prompt context (fields/constants/ins_byte). |
| `--max-data N` | `MAX_DATA` value. Auto-detected from `operation.json`'s wrapper when omitted; required for `--no-llm` without `--operation`. |
| `--output-dir DIR` | Output directory (default: `seeds/`). |
| `--no-llm` | **Skip LLM generation entirely; write only deterministic seeds.** No API token required. |
| `--count N` | LLM generation cycles (default: 1). Each cycle is one LLM call; seeds are deduplicated. Ignored with `--no-llm`. |
| `--model NAME` | Model name; overrides env (`LLM_MODEL`) / `llm_config.ini`. Ignored with `--no-llm`. |
| `--timeout N` | LLM API timeout in seconds; overrides env (`LLM_TIMEOUT`) / `llm_config.ini` (default 120). Ignored with `--no-llm`. |
| `--print-prompt` | Print the prompt to stdout before each LLM call. Ignored with `--no-llm`. |
| `--no-deterministic` | Skip deterministic seeds; write LLM seeds only. |
| `--p1-max N` | Max P1 value for P1-differential deterministic seeds (default: 32) |
| `--p2-max N` | Max P2 value for P2-differential deterministic seeds (default: 32) |
| `--random-count N` | Number of random deterministic seeds (default: 32) |
| `--verbose` | Enable debug logging |
| `--list-models` | List available models from the configured LLM API and exit |

---

## How the LLM generator works

`LLMSeedGenerator` (in `generator.py`) runs the following pipeline, once per
`--count` cycle:

```
operation.json  (harness-extraction output)
    │  wrapper_method.code, core_method.code, data_layout_comment,
    │  operation_name, timing_risk
    ▼
build_prompt()
    │  Assembles a structured text prompt (see below) directly from the JSON —
    │  no Java source is re-parsed.
    ▼
call_llm(prompt)          →  POST /v1/chat/completions  (configured LLM endpoint)
    │  Single user-role message; model from llm_config.ini / --model.
    ▼
parse_seeds_from_response(response)
    │  Tolerant hex parser: strips markdown fences, 0x prefixes,
    │  bullet markers. Skips comment lines. Discards odd-length or
    │  non-hex output. Returns list[bytes].
    ▼
write_seed(data)  ×N
    │  SHA-256 deduplication across cycles and restarts.
    │  Files named llm_seed_000000, llm_seed_000001, …
    ▼
seeds/
```

### What is sent to the LLM

The prompt (from [`prompts/seed_generation.md`](prompts/seed_generation.md)) has
these sections, all filled from `operation.json`:

1. **Fuzzing input format** — the fixed-offset layout + concrete seed size.
2. **Mapping of one input half to the APDU** — `buffer[OFFSET_P1/P2/LC/CDATA]`.
3. **Per-input-set data layout** — the wrapper's `data_layout_comment`.
4. **Wrapper method** — `wrapper_method.code`: the exact byte→parameter unpacking.
5. **Core method** — `core_method.code`: the timing-sensitive logic to drive.
6. **Instructions** — construct A/B halves that take opposite branches, cover
   edge values, use boundary data patterns, and return raw hex seeds only.

### MAX_DATA detection

When `--max-data` is omitted, MAX_DATA is resolved from `operation.json`'s
wrapper via `drivergen.resolve_max_data` — the **same helper `assemble_harness`
uses to set the driver's `MAX_DATA` constant**, so the seed size and the driver
always agree (each seed is `6 + 2*MAX_DATA` bytes = the driver's
`TOTAL_INPUT_SIZE`). It uses two strategies:

1. A Javadoc line `* MAX_DATA = N` on the wrapper.
2. A minimum-data guard `if (dataLen < (short) N)` inside the wrapper.

If the wrapper declares neither, both sides fall back to the shared default
(`DEFAULT_MAX_DATA = 64`) — so they still match. Pass `--max-data N` to override
(then also rebuild the driver with the same value).

### Response parsing and deduplication

The parser is deliberately tolerant: it strips markdown code fences (` ``` `),
`0x` prefixes, and bullet markers (`- `, `* `, `> `), then extracts the hex on
each line.  Odd-length / non-hex lines are silently skipped.  Each parsed seed
is SHA-256-hashed before writing; the hash set is pre-populated from files
already in the output directory, so re-running or increasing `--count` never
produces duplicate files.

## Deterministic seed strategies

When `--no-deterministic` is not set, these fixed seeds are also written:

| Seed name | What varies | Target |
|-----------|-------------|--------|
| `identical_*` | Nothing (A == B) | Sanity check — cost should be zero |
| `p1_*_vs_*` | P1 only | Loop bounds / key-length-dependent paths |
| `p2_*_vs_*` | P2 only | Message-length-dependent processing |
| `len_*_vs_*` | len_A vs len_B | Operations that scale with data length |
| `data_zeros_vs_ones` | Data content | Data-dependent branching |
| `data_msb_normal_vs_hardened` | First byte: 0x00 vs 0x80 | BIP32 normal vs hardened derivation |
| `random_*` | Everything | AFL++ starting diversity |

## Editing the prompt

The LLM prompt lives in
[`prompts/seed_generation.md`](prompts/seed_generation.md), not in the Python.
Edit that file to tune the wording or seed-construction guidance — no code
change needed. `{{marker}}` placeholders (e.g. `{{wrapper_code}}`,
`{{core_code}}`, `{{data_layout}}`, `{{length_note}}`) are filled by
`build_prompt()` in `generator.py`; keep them intact and don't add new ones
without a matching value in that method.
