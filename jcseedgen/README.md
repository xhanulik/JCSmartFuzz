# jcseedgen — Initial Seed Generator

Generates the initial corpus for JCSmartFuzz fuzzing campaigns.  Combines two
complementary strategies:

| Strategy | Module | When to use |
|----------|--------|-------------|
| **LLM-generated seeds** | `generator.py` (`LLMSeedGenerator`) | Targeted coverage of timing-sensitive branches identified from source code |
| **Deterministic seeds** | `generate_seeds.py` | Fast, reproducible baseline — no API token, no network (identical/differential/boundary/random) |

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
- `LLM_API_TOKEN` environment variable set — **only required for LLM-generated seeds**; `--no-llm` mode works without it
- `jcfuzzgen/llm_seed_generator/source_reader.py` present — only required for LLM mode
- `drivergen/generate_drivers.py` present — required for `--applet` multi-operation mode and for MAX_DATA auto-detection from a single source file

---

## Usage

### Deterministic seeds only — no LLM, no API token

**MAX_DATA known directly:**

```bash
python -m jcseedgen --no-llm --max-data 64 --output-dir seeds/HmacSha160
```

**Auto-detect MAX_DATA from an applet (all operations):**

```bash
python -m jcseedgen --no-llm \
    --applet path/to/XxxFuzzApplet.java \
    --output-dir seeds/
```

**Single operation with auto-detected MAX_DATA:**

```bash
python -m jcseedgen --no-llm \
    --source path/to/XxxFuzzApplet.java \
    --op-name HmacSha160 \
    --output-dir seeds/HmacSha160
```

You can also call `generate_seeds.py` directly (it has its own `main()`):

```bash
python jcseedgen/generate_seeds.py \
    --applet path/to/XxxFuzzApplet.java \
    --output-dir seeds/
```

### LLM-generated seeds

Requires `LLM_API_TOKEN` to be set.

**Single operation:**

```bash
export LLM_API_TOKEN=<token>

python -m jcseedgen \
    --source path/to/XxxFuzzApplet.java \
    --op-name HmacSha160 \
    --output-dir seeds/HmacSha160
```

**All operations from an applet (auto-detect MAX_DATA):**

```bash
python -m jcseedgen \
    --applet path/to/XxxFuzzApplet.java \
    --output-dir seeds/
```

### Combined (default behaviour)

By default, `python -m jcseedgen` writes **both** LLM-generated and
deterministic seeds to the same output directory.

| Goal | Flags |
|------|-------|
| LLM + deterministic | *(default)* |
| LLM only | `--no-deterministic` |
| Deterministic only | `--no-llm` |
| Neither (dry-run / validate args) | `--no-llm --no-deterministic` |

---

## CLI options

| Argument | Description |
|----------|-------------|
| `--source PATH` | Path to `*FuzzApplet.java` — single operation mode. Not required when `--no-llm --max-data N` is used. |
| `--applet PATH` | Path to `*FuzzApplet.java` — auto-detect all operations and MAX_DATA (requires `drivergen/`) |
| `--op-name NAME` | Operation name `Xxx` (used with `--source`). Prompt includes only `wrapXxx` and `coreXxx`. Omit for full-class extraction. |
| `--max-data N` | `MAX_DATA` value. Auto-detected from the wrapper source when `--source` + `--op-name` are given, or from `--applet`. Only required explicitly when using `--no-llm` without a source file. |
| `--output-dir DIR` | Root output directory (default: `seeds/`). One sub-directory per operation when `--applet` is used. |
| `--no-llm` | **Skip LLM generation entirely; write only deterministic seeds.** No API token required. |
| `--count N` | LLM generation cycles per operation (default: 1). Each cycle is one LLM call; seeds are deduplicated. Ignored with `--no-llm`. |
| `--model NAME` | e-INFRA CZ model (default: `gpt-oss-120b`). Ignored with `--no-llm`. |
| `--timeout N` | LLM API timeout in seconds (default: 120). Ignored with `--no-llm`. |
| `--print-prompt` | Print the prompt to stdout before each LLM call. Ignored with `--no-llm`. |
| `--no-deterministic` | Skip deterministic seeds; write LLM seeds only. |
| `--p1-max N` | Max P1 value for P1-differential deterministic seeds (default: 32) |
| `--p2-max N` | Max P2 value for P2-differential deterministic seeds (default: 32) |
| `--random-count N` | Number of random deterministic seeds (default: 32) |
| `--verbose` | Enable debug logging |
| `--list-models` | List available models from the e-INFRA CZ API and exit |

---

## How the LLM generator works

`LLMSeedGenerator` (in `generator.py`) runs the following pipeline for each
operation, once per `--count` cycle:

```
FuzzApplet.java
    │
    ▼
SourceReader.build_method_context(["wrapXxx", "coreXxx"])
    │  Extracts the two relevant methods from the source file.
    │  Falls back to full-class extraction when --op-name is omitted.
    ▼
build_prompt(source_context)
    │  Assembles a structured text prompt (see below).
    ▼
call_llm(prompt)          →  POST /v1/chat/completions  (e-INFRA CZ endpoint)
    │  Single user-role message, model gpt-oss-120b by default.
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
seeds/Xxx/
```

### Source extraction

`SourceReader` is imported from `jcfuzzgen/llm_seed_generator/source_reader.py`
(the same extractor the AFL++ live-fuzzing side-car uses).

- **With `--op-name Xxx`**: only `wrapXxx` and `coreXxx` are extracted and
  included in the prompt. This gives the LLM focused context — it sees exactly
  the unpacking logic and the timing-sensitive algorithm.
- **Without `--op-name`**: the full class body is included, subject to
  SourceReader's 16 000-character budget.

### What is sent to the LLM

The prompt is a plain-text message with four numbered sections:

```
=== 1. Fuzzing input format ===
[ p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA)
| p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA) ]
MAX_DATA = <N>  (each seed is exactly <6+2N> bytes = <12+4N> hex characters)
Byte-offset breakdown of each slot.
```

```
=== 2. Mapping of one input half to the actual APDU ===
buffer[ISO7816.OFFSET_P1]    = p1
buffer[ISO7816.OFFSET_P2]    = p2
buffer[ISO7816.OFFSET_LC]    = len
buffer[ISO7816.OFFSET_CDATA] = start of data
```

```
=== 3. Fuzzed source code ===
<wrapXxx() and coreXxx() method bodies, or the full class>
```

```
=== Instructions ===
Examine the conditional branches that depend on p1, p2, len, or data content.
Generate seeds that:
- Set A and B halves to enter OPPOSITE branches of timing-sensitive conditions.
- Cover edge values: p1/p2/len = 0 and max.
- Include data patterns: all-zeros, all-0xFF, MSB=0x00 vs MSB=0x80, 0x55/0xAA.
- Vary p1, p2, len, and data independently rather than all at once.
- Pair boundary values (e.g. p1_A=1, p1_B=max) to exercise loop-bound paths.

Return ONLY raw hex-encoded seeds, one per line. No prose, no fences.
Each line must be exactly <12+4N> hex characters.
```

When `--max-data` is not provided, the tool first tries to read MAX_DATA
automatically from the wrapper method in the source file using the same two
strategies that `drivergen` uses:

1. A Javadoc line `* MAX_DATA = N` on `wrapXxx`.
2. A minimum-data guard `if (dataLen < (short) N)` inside `wrapXxx`.

If neither is found, the seed-size constraint falls back to symbolic form
(`6 + 2*MAX_DATA bytes`) and the LLM is asked to infer MAX_DATA from the
source code in section 3. Deterministic seeds are skipped in that case.

To ensure MAX_DATA is always detected, add one of these to every wrapper:

```java
/** MAX_DATA = 64 */
private short wrapHmacSha160(APDU apdu, byte[] buffer) { ...

// or equivalently:
if (dataLen < (short) 64)
    return (short) 0;
```

### Response parsing and deduplication

The parser is deliberately tolerant: it strips markdown code fences (` ``` `),
`0x` prefixes, and bullet markers (`- `, `* `, `> `), then extracts the
longest contiguous hex run on each line.  Lines that produce an odd number of
hex nibbles or that decode to zero bytes are silently skipped.

Each parsed seed is hashed (SHA-256) before writing.  The hash set is
pre-populated from any files already present in the output directory, so
re-running or increasing `--count` never produces duplicate files.

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
