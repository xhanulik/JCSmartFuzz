# JCSmartFuzz

LLM-enhanced fuzzing framework for detecting timing side-channels in Java Card applets.

The framework combines differential fuzzing (AFL++ via Kelinci + diffuzz) with LLM-assisted code extraction and seed generation. It measures instruction-count differences between two inputs sent to the same cryptographic operation, revealing data-dependent execution paths that indicate timing leakage.

---

## Repository Layout

```
JCSmartFuzz/
├── skeletons/          Java templates and LLM prompts for building fuzzing targets
├── drivergen/          Python script that generates FuzzDriver files from a FuzzApplet
├── jcfuzzgen/
│   ├── llm_seed_generator/   LLM-augmented AFL++ seed generation side-car
│   └── eval/                 Campaign metrics and side-channel quality analysis
├── jcseedgen/          (in development)
└── tools/
    ├── AFLplusplus/    AFL++ fuzzer (submodule)
    └── diffuzz/        Differential fuzzing infrastructure (submodule)
```

---

### skeletons/

Templates and prompts for creating a fuzzing target from a Java Card applet.

| File | Purpose |
|------|---------|
| `FuzzAppletSkeleton.java` | On-card applet scaffold. Fixed dual-invocation framing (Layers 1–2) runs the target operation twice per APDU and reports `Kelinci.addCost(\|costA − costB\|)`. Generated code fills in Layers 3–4 (wrappers + verbatim core methods). |
| `FuzzDriverSkeleton.java` | Host-side AFL++ driver template. Reads a fixed-offset fuzz input file, builds the dual-input APDU, and sends it to jCardSim. One driver is built per operation under test. |
| `fuzz_input_mapping_skeleton.yaml` | Machine-readable schema documenting how bytes in the fuzz input file map to APDU fields and operation parameters. |
| `llm_extraction_prompt.md` | Detailed LLM prompt for *analysing* an applet: identifies timing-sensitive operations and produces the `wrapXxx` / `coreXxx` method stubs. |
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

### drivergen/

Generates `FuzzDriverXxx.java` files automatically from a `*FuzzApplet.java` that conforms to `FuzzAppletSkeleton.java`. Writing drivers by hand after the applet is created is fully mechanical; this script eliminates the boilerplate.

```bash
python drivergen/generate_drivers.py \
    --applet path/to/XxxFuzzApplet.java \
    [--output-dir DIR] \
    [--aid STRING]
```

The script parses the applet for `INS_*` constants, the `dispatchOperation()` switch, and `MAX_DATA` per wrapper (from the Javadoc comment or the `dataLen` guard), then writes one driver per operation.

See [`drivergen/README.md`](drivergen/README.md) for full usage and conformance requirements.

---

### jcfuzzgen/

#### llm_seed_generator/

A side-car process that augments a running AFL++ campaign with seeds produced by an LLM. It reads AFL++'s queue and fuzzer stats, selects the most interesting inputs, builds a prompt with the fuzzed source code and campaign state, calls the LLM, and injects the returned seeds via AFL++'s foreign-sync (`-F`) mechanism.

```bash
cd jcfuzzgen
export LLM_API_TOKEN=<token>
python3 -m llm_seed_generator \
    --source path/to/XxxFuzzApplet.java \
    --op-name HmacSha160 \
    --afl-out /tmp/afl-out \
    --seed-dir /tmp/llm-seeds \
    --model qwen3-coder-next
```

AFL++ must be running with `-M main -F /tmp/llm-seeds`. Set `AFL_SYNC_TIME=1` for ~30-second seed pickup.

See [`jcfuzzgen/llm_seed_generator/README.md`](jcfuzzgen/llm_seed_generator/README.md) for the full data flow, scoring logic, and feature list.

#### eval/

`parse_afl_output.py` — Analyses a completed (or running) AFL++ campaign directory and reports fuzzer stats, queue breakdown, and timing side-channel quality signals:

- **CV** (coefficient of variation of instruction counts): values > 0.3 indicate meaningful timing variance across inputs.
- **Tail ratio** (p95 / median): values > 3 indicate worst-case inputs have been found.
- **Unique value percentage**: low values suggest the operation is not responding to input variation.

```bash
python jcfuzzgen/eval/parse_afl_output.py /tmp/afl-out [--json]
```

---

### jcseedgen/

Initial seed generation for fuzzing campaigns — in development.

---

## Typical Workflow

```
1. Obtain target applet source (.java)
        │
        ▼
2. Extract timing-sensitive operations
   └─ Use skeletons/llm_extraction_prompt.md with an LLM
        │
        ▼
3. Implement *FuzzApplet.java
   └─ Use skeletons/llm_implementation_prompt.md  or  llm_implementation_prompt_short.md
        │
        ▼
4. Generate FuzzDriver*.java files
   └─ python drivergen/generate_drivers.py --applet *FuzzApplet.java
        │
        ▼
5. Compile and run AFL++ with Kelinci + diffuzz
   └─ afl-fuzz -M main -F /tmp/llm-seeds -i seeds/ -o out/ -- ./FuzzDriverXxx @@
        │
        ▼ (in parallel)
6. Run LLM seed generator
   └─ python -m llm_seed_generator --source *FuzzApplet.java ...
        │
        ▼
7. Analyse results
   └─ python jcfuzzgen/eval/parse_afl_output.py out/
```

---

## Tools (submodules)

- **`tools/AFLplusplus/`** — Fork of [AFL++](https://github.com/AFLplusplus/AFLplusplus), coverage-guided fuzzer enhanced for usage with .
- **`tools/diffuzz/`** — Differential fuzzing infrastructure (Kelinci integration, `path_costs.csv` output, `Mem.instrCost` measurement).

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

### Initial seed corpus generation
* Generation script
  * [x] Basic prompt

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
