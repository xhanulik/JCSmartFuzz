# JCSmartFuzz

LLM-enhanced fuzzing framework for detecting timing side-channels in Java Card applets.

The framework combines differential fuzzing (AFL++ via Kelinci + diffuzz) with LLM-assisted code extraction and seed generation. It measures instruction-count differences between two inputs sent to the same cryptographic operation, revealing data-dependent execution paths that indicate timing leakage.

---

## Repository Layout

```
JCSmartFuzz/
├── pipeline/                    First-party pipeline: source → target → seeds → metrics
│   ├── analyze/
│   │   ├── ast_symtab/            parse applet → per-method records
│   │   └── candidate_narrowing/   prefilter + LLM verdict → security-relevant methods
│   ├── harness/
│   │   ├── harness_extraction/    chosen method → FuzzApplet*/FuzzDriver* pair
│   │   └── drivergen/             (re)generate FuzzDriver*.java from a FuzzApplet
│   ├── seeds/
│   │   ├── initial/               pre-campaign seeds (LLM + deterministic)
│   │   └── sidecar/               in-campaign LLM seed side-car for AFL++
│   └── eval/                      parse an AFL++ run into campaign metrics
├── automation/                  Orchestrate/evaluate the pipeline over the whole corpus
│   │                              (README.md covers running these tools + the fuzzer)
│   ├── harness_gen/               generate N harnesses for one repo (glue pipeline stages)
│   ├── corpus_info/               corpus statistics (usable repos, build systems, categories)
│   └── fuzz_build/                build a fuzzing target (applet + FuzzApplet/Driver) → .class
├── skeletons/                   Java templates and LLM prompts the harness fills
├── corpus/                      Applet corpus dataset (dataset.json)
└── engine/                      Differential fuzzer (submodules)
    ├── AFLplusplus/               AFL++ fuzzer (submodule)
    └── diffuzz/                   Differential fuzzing infrastructure (submodule)
```

The three top-level roles: **`pipeline/`** — raw-work scripts, each runnable
manually on a single input; **`engine/`** — vendored third-party fuzzer
(submodules); **`automation/`** — scripts that drive the pipeline across the
corpus and build/run/evaluate fuzzing (see [`automation/README.md`](automation/README.md)).

The end-to-end run of the four pipeline stages is documented in
[`pipeline/README.md`](pipeline/README.md); each stage's directory has its own
README with the details. The sections below summarize each component.

---

### skeletons/

Templates and prompts for creating a fuzzing target from a Java Card applet.

| File | Purpose |
|------|---------|
| `FuzzAppletSkeleton.java` | On-card applet scaffold. Fixed dual-invocation framing (Layers 1–2) runs the target operation twice per APDU and reports `Kelinci.addCost(\|costA − costB\|)`. Generated code fills in Layers 3–4 (wrappers + verbatim core methods). |
| `FuzzDriverSkeleton.java` | Host-side AFL++ driver template. Reads a fixed-offset fuzz input file, builds the dual-input APDU, and sends it to jCardSim. One driver is built per operation under test. |
| `fuzz_input_mapping_skeleton.yaml` | Machine-readable schema documenting how bytes in the fuzz input file map to APDU fields and operation parameters. |
| `llm_implementation_prompt.md` | Detailed LLM prompt for *implementing* the full fuzzing target: selects operations, writes `*FuzzApplet.java` and all `FuzzDriver*.java` files. |
| `llm_implementation_prompt_short.md` | Condensed single-screen version of the implementation prompt. |

### Fixed-offset fuzz input layout (per driver)

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

Every byte position is stable regardless of `len_A`/`len_B`, making the layout safe for AFL++ byte-level mutations.

---

### pipeline/analyze/

Finds the timing-sensitive methods worth building a harness for. `ast_symtab/`
parses the applet into per-method records; `candidate_narrowing/` ranks them
with a deterministic pre-filter and then asks an LLM for a structured
security verdict per surviving candidate.

```bash
python3 pipeline/analyze/ast_symtab/extract.py <src_dir> -o ast_out
python3 pipeline/analyze/candidate_narrowing/prefilter_rank_candidates.py ast_out/methods.jsonl -o candidates.jsonl
python3 pipeline/analyze/candidate_narrowing/llm_final_verdict.py ast_out/methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl
```

See [`pipeline/analyze/ast_symtab/README.md`](pipeline/analyze/ast_symtab/README.md)
and [`pipeline/analyze/candidate_narrowing/README.md`](pipeline/analyze/candidate_narrowing/README.md).

---

### pipeline/harness/

Turns one chosen method into a working `FuzzApplet*.java` / `FuzzDriver*.java`
pair. `harness_extraction/` does the source→target extraction (filling the
`skeletons/` templates); `drivergen/` (re)generates `FuzzDriverXxx.java` files
from a `*FuzzApplet.java` that conforms to `FuzzAppletSkeleton.java` — fully
mechanical boilerplate elimination, driven off `INS_*` constants, the
`dispatchOperation()` switch, and `MAX_DATA` per wrapper.

```bash
python3 pipeline/harness/harness_extraction/extract_context.py <src_dir> ast_out --verdicts verdicts.jsonl -o context.json
python3 pipeline/harness/harness_extraction/llm_extract_operation.py context.json -o operation.json
python3 pipeline/harness/harness_extraction/assemble_harness.py context.json operation.json --package com.example.fuzz -o generated/

# or just (re)generate drivers for an existing FuzzApplet:
python3 pipeline/harness/drivergen/generate_drivers.py --applet path/to/XxxFuzzApplet.java [--output-dir DIR] [--aid STRING]
```

See [`pipeline/harness/harness_extraction/README.md`](pipeline/harness/harness_extraction/README.md)
and [`pipeline/harness/drivergen/README.md`](pipeline/harness/drivergen/README.md).

---

### pipeline/seeds/

`initial/` builds the pre-campaign corpus (LLM-generated plus a deterministic
baseline), in the fixed-offset layout every driver consumes. `sidecar/` is a
side-car process that augments a *running* AFL++ campaign: it reads AFL++'s
queue and fuzzer stats, prompts an LLM with the fuzzed source and campaign
state, and injects the returned seeds via foreign-sync (`-F`).

```bash
# initial corpus (run from pipeline/seeds/ so the package is importable)
cd pipeline/seeds
export LLM_API_TOKEN=<token>
python3 -m initial --applet path/to/XxxFuzzApplet.java --output-dir seeds/

# in-campaign side-car (AFL++ running with -M main -F /tmp/llm-seeds; AFL_SYNC_TIME=1 for ~30s pickup)
python3 -m sidecar \
    --source path/to/XxxFuzzApplet.java \
    --op-name HmacSha160 \
    --afl-out /tmp/afl-out \
    --seed-dir /tmp/llm-seeds \
    --model qwen3-coder-next
```

See [`pipeline/seeds/initial/README.md`](pipeline/seeds/initial/README.md) and
[`pipeline/seeds/sidecar/README.md`](pipeline/seeds/sidecar/README.md).

---

### pipeline/eval/

`parse_afl_output.py` — Analyses a completed (or running) AFL++ campaign directory and reports fuzzer stats, queue breakdown, and timing side-channel quality signals:

- **CV** (coefficient of variation of instruction counts): values > 0.3 indicate meaningful timing variance across inputs.
- **Tail ratio** (p95 / median): values > 3 indicate worst-case inputs have been found.
- **Unique value percentage**: low values suggest the operation is not responding to input variation.

```bash
python3 pipeline/eval/parse_afl_output.py /tmp/afl-out [--json]
```

---

## Typical Workflow

```
1. Obtain target applet source (.java)
        │
        ▼
2. Analyze — find timing-sensitive operations
   └─ python3 pipeline/analyze/ast_symtab/extract.py <src> -o ast_out
      python3 pipeline/analyze/candidate_narrowing/... -> verdicts.jsonl
        │
        ▼
3. Harness — build the FuzzApplet + FuzzDriver pair
   └─ python3 pipeline/harness/harness_extraction/... -> generated/
      (or python3 pipeline/harness/drivergen/generate_drivers.py --applet *FuzzApplet.java)
        │
        ▼
4. Seeds — build the initial corpus
   └─ (cd pipeline/seeds && python3 -m initial --applet *FuzzApplet.java --output-dir seeds/)
        │
        ▼
5. Compile and run AFL++ with Kelinci + diffuzz
   └─ afl-fuzz -M main -F /tmp/llm-seeds -i seeds/ -o out/ -- ./FuzzDriverXxx @@
        │
        ▼ (in parallel)
6. Run the in-campaign LLM seed side-car
   └─ (cd pipeline/seeds && python3 -m sidecar --source *FuzzApplet.java ...)
        │
        ▼
7. Analyse results
   └─ python3 pipeline/eval/parse_afl_output.py out/
```

---

## Engine (submodules)

- **`engine/AFLplusplus/`** — Fork of [AFL++](https://github.com/AFLplusplus/AFLplusplus), coverage-guided fuzzer enhanced with WCA (Worst-Case Analysis) support.
- **`engine/diffuzz/`** — Differential fuzzing infrastructure (Kelinci integration, `path_costs.csv` output, `Mem.instrCost` measurement).

See [`engine/README.md`](engine/README.md) for build instructions.

## Features

### Fuzzing applet and driver generation
* Automatic extraction ofcustom crypto code
  * [x] LLM usage
  * [ ] AST usage
* Automatic generation of fuzzing applet
  * [x] LLM usage
  * [ ] LLM+AST usage
  * [ ] Verificator for validity of extracted code
* Automatic generation of fuzzing driver
  * [x] Python script for 

#### Verification of correct applet extraction
* [ ] TBD

### Initial seed corpus generation
* Generation script
  * [x] Basic prompt
  * [ ] Combination of LLM and randomly generated seeds

### Fuzzing loop seed injection
* Basic functionality:
  * [x] Seed injection into fuzzing process
  * [x] New seeds based on `queue/` input
* LLM seed generation sources:
  * [x] Seeds with number of instructions reached
  * [x] Seeds with user-defined cost
  * [x] Seeds with increased coverage
  * [x] Source code
  * [ ] Already generated seeds
  * [ ] Machine code (instructions, bytecode, CAP files)
* Input selection quality:
  * [x] A/B structural divergence signal (p1/p2/len diff between halves)
  * [x] Wall-clock time from `path_costs.csv` used in ranking
  * [x] Seed deduplication via SHA-256 (across runs)
* Prompt quality:
  * [x] Fuzzer state injected into prompt (coverage, cycles, last find)
  * [x] Per-cycle acceptance-rate feedback to LLM
  * [x] Differential/timing side-channel objective stated explicitly
* AFL++:
  * [ ] More frequent sync with generated seeds
  * [ ] Rotate power schedule during fuzzing process
* Other:
  * [ ] Mutation strategies enhancement
  * [ ] Periodical minimization of generated seeds
  * [ ] Seed generation based on path exploration
  * [ ] Dictionary generation
  * [ ] Custom mutators via shared libraries

### Fuzzing eveluation
* [x] Basic script for printing out fuzzing stats
* [ ] Human-readable and understandable report on fuzzing results
