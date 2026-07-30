# automation

Scripts that orchestrate the [`pipeline/`](../pipeline/) over the
[applet corpus](../corpus/dataset.json). (`pipeline/` holds the raw per-input
scripts; `engine/` the vendored AFL++/diffuzz; `automation/` these orchestrators.)

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install javalang
export LLM_API_TOKEN=...     # for the LLM steps in harness_gen (see ../pipeline/llm_config.py)
```

## Tools

Per-repo order — **`harness_gen/` → `fuzz_build/` → run the fuzzer**:

- [`harness_gen/`](harness_gen/) — generate N harnesses for one repo
  `python3 harness_gen/generate_harnesses.py --entry "<repo>" -n 5`
- [`fuzz_build/`](fuzz_build/) — compile a harness to `.class`
  `python3 fuzz_build/build_target.py --entry "<repo>" --harness-out <dir>`
  (plus `discover_builds.py` to populate the per-repo build metadata)
- [`corpus_info/`](corpus_info/) — corpus statistics
  `python3 corpus_info/corpus_stats.py`

## Run the fuzzer (Part 2)

`build_target.py` prints this block with the paths filled in. Run it with
**JDK 8** — Kelinci's instrumentor fails on JDK 9+:

```bash
sudo apt-get install -y openjdk-8-jdk
export JAVA8=/usr/lib/jvm/java-8-openjdk-amd64
export CLASSES=<from build_target>   KELINCI=...   JCARDSIM=...   BC=...   DRIVER=FuzzDriver<Op>

$JAVA8/bin/java -cp "$KELINCI" edu.cmu.sv.kelinci.instrumentor.Instrumentor -i "$CLASSES" -o bin-instr -skipmain
mkdir -p in out && touch in/testcase
$JAVA8/bin/java -cp "bin-instr:$JCARDSIM" "$DRIVER" in/testcase
$JAVA8/bin/java -cp "bin-instr:$JCARDSIM:$BC" edu.cmu.sv.kelinci.Kelinci "$DRIVER" @@
.../engine/diffuzz/tool/afl-2.51b-wca/afl-fuzz -i in -o out .../engine/diffuzz/tool/fuzzerside/interface @@
```

Seeds for `in/` come from [`../pipeline/seeds/initial`](../pipeline/seeds/initial).

Planned: `fuzz_run/` (launch campaigns), `results/` (aggregate metrics).
