# jcseedgen — Initial Seed Generator

Generates the initial corpus for JCSmartFuzz fuzzing campaigns.  Combines two
complementary strategies:

| Strategy | Module | When to use |
|----------|--------|-------------|
| **LLM-generated seeds** | `generator.py` (`LLMSeedGenerator`) | Targeted coverage of timing-sensitive branches identified from source code |
| **Deterministic seeds** | `generate_seeds.py` | Fast, reproducible baseline (identical/differential/boundary/random) |

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
- `LLM_API_TOKEN` environment variable set (for LLM-generated seeds)
- `jcfuzzgen/llm_seed_generator/source_reader.py` present (reused for Java source extraction)
- `drivergen/generate_drivers.py` present (for `--applet` multi-operation mode)

---

## Usage

### LLM-generated seeds (recommended)

**Single operation:**

```bash
export LLM_API_TOKEN=<token>

python -m jcseedgen \
    --source path/to/XxxFuzzApplet.java \
    --op-name HmacSha160 \
    --output-dir /tmp/seeds/HmacSha160
```

**All operations from an applet (auto-detect MAX_DATA):**

```bash
python -m jcseedgen \
    --applet path/to/XxxFuzzApplet.java \
    --output-dir /tmp/seeds/
```

Creates one sub-directory per operation, e.g.:

```
/tmp/seeds/
├── HmacSha160/
│   ├── llm_seed_000000
│   ├── seed_identical_zeros.bin   ← also includes deterministic seeds
│   └── ...
├── HmacSha512/
│   └── ...
└── BIP32Derive/
    └── ...
```

### Deterministic seeds only (no LLM)

```bash
python jcseedgen/generate_seeds.py \
    --applet path/to/XxxFuzzApplet.java \
    --output-dir /tmp/seeds/
```

### Combined (default behaviour of `python -m jcseedgen`)

By default, `python -m jcseedgen` writes **both** LLM-generated and
deterministic seeds.  Use `--no-deterministic` to skip the deterministic seeds.

---

## CLI reference

```
python -m jcseedgen [--source PATH | --applet PATH]
                    [--op-name NAME]
                    [--max-data N]
                    [--output-dir DIR]
                    [--count N]
                    [--model NAME]
                    [--timeout N]
                    [--print-prompt]
                    [--no-deterministic]
                    [--p1-max N] [--p2-max N] [--random-count N]
                    [--verbose]
                    [--list-models]
```

| Argument | Description |
|----------|-------------|
| `--source PATH` | Path to `*FuzzApplet.java` — single operation mode |
| `--applet PATH` | Path to `*FuzzApplet.java` — auto-detect all operations (requires `drivergen/`) |
| `--op-name NAME` | Operation name `Xxx` (used with `--source`). Prompt includes only `wrapXxx` and `coreXxx`. Omit for full-class extraction. |
| `--max-data N` | `MAX_DATA` value. Auto-detected from `--applet`; improves prompt precision with `--source`. |
| `--output-dir DIR` | Root output directory (default: `seeds/`) |
| `--count N` | LLM generation cycles per operation (default: 1). Each cycle is one LLM call; seeds are deduplicated. |
| `--model NAME` | e-INFRA CZ model (default: `gpt-oss-120b`) |
| `--timeout N` | LLM API timeout in seconds (default: 120). Increase for slow/thinking models. |
| `--print-prompt` | Print the prompt to stdout before each LLM call |
| `--no-deterministic` | Skip deterministic seeds; write LLM seeds only |
| `--p1-max N` | Max P1 value for P1-differential deterministic seeds (default: 32) |
| `--p2-max N` | Max P2 value for P2-differential deterministic seeds (default: 32) |
| `--random-count N` | Number of random deterministic seeds (default: 32) |
| `--verbose` | Enable debug logging |
| `--list-models` | List available models from the e-INFRA CZ API and exit |

---

## Source extraction

`LLMSeedGenerator` reuses `SourceReader` from
`jcfuzzgen/llm_seed_generator/source_reader.py` — the same extractor used by the
AFL++ side-car during live fuzzing.  When `--op-name` is given, the prompt
includes only the `wrapXxx` and `coreXxx` methods.  Without `--op-name`, the
full class is included (subject to the 16 000-character budget).

---

## Relationship to jcfuzzgen/llm_seed_generator/

| Aspect | jcseedgen | jcfuzzgen/llm_seed_generator |
|--------|-----------|------------------------------|
| When it runs | Before fuzzing starts | During a live AFL++ campaign |
| AFL++ dependency | None | Required (`fuzzer_stats`, queue, `path_costs.csv`) |
| Prompt context | Source code only | Source code + fuzzer state + queue inputs |
| Seed naming | `llm_seed_XXXXXX` | `llm_seed_XXXXXX` (same, shareable directory) |
| Deduplication | SHA-256 across all cycles and restarts | SHA-256 across all cycles and restarts |
| Extension points | Same pattern (`build_prompt`, `call_llm`, `parse_seeds_from_response`, `write_seed`) | Same pattern |

---

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
