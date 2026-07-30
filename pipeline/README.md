# pipeline — applet source → fuzzing target → seeds → metrics

The first-party pipeline that turns a Java Card applet source tree into a
runnable differential-fuzzing target, generates its seed corpus, and reports
campaign metrics. The fuzzing engine itself lives in [`../engine/`](../engine/);
the Java templates and LLM prompts it fills live in
[`../skeletons/`](../skeletons/).

Each stage is a self-contained tool with its own README; the sections below are
the end-to-end run. Everything mechanical is deterministic Python — the LLM is
only asked to make the judgment calls that can't be derived from the source.

Every LLM prompt is an editable text template in a `prompts/` folder next to
its script (with `{{marker}}` placeholders the code fills in), so the wording
can be tuned without touching Python — see each stage's README.

```
pipeline/
├── analyze/                 Stage 1 — find the timing-sensitive methods
│   ├── ast_symtab/            parse applet → per-method records
│   └── candidate_narrowing/   prefilter + LLM verdict → security-relevant methods
├── harness/                 Stage 2 — build the fuzzing target
│   ├── harness_extraction/    chosen method → FuzzApplet*/FuzzDriver* pair
│   └── drivergen/             (re)generate FuzzDriver*.java from a FuzzApplet
├── seeds/                   Stage 3 — build the input corpus
│   ├── initial/               pre-campaign seeds (LLM + deterministic)
│   └── sidecar/               in-campaign LLM seed side-car for AFL++
└── eval/                    Stage 4 — parse an AFL++ run into metrics
```

## Prerequisites

- **Python 3** with [`javalang`](https://github.com/c2nes/javalang) — the only
  third-party dependency of stages 1–2 (the LLM steps and stages 3–4 use the
  standard library only).
- **LLM backend config** for every LLM step. All stages resolve the endpoint,
  model, timeout, and token through `pipeline/llm_config.py`, in this order:
  **environment variable > `llm_config.ini` > built-in default**. Set it up
  once by copying the template at the repo root:

  ```bash
  cp llm_config.ini.example llm_config.ini   # then edit endpoint / model / token
  ```

  `llm_config.ini` is git-ignored (never committed). Alternatively export
  `LLM_ENDPOINT`, `LLM_MODEL`, `LLM_TIMEOUT`, `LLM_API_TOKEN` — each overrides
  the file. The stage-1/2 LLM steps accept `--mock` for a canned local
  responder, so the analysis→harness chain can be exercised end-to-end with no
  config, token, or network.

### Python environment

Set up a virtual environment once and run every stage inside it:

```bash
# from the repo root
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install javalang

python3 -c "import javalang; print('env OK')"   # sanity check
```

`javalang` is the sole dependency, so there is no `requirements.txt` to
maintain — `pip install javalang` is the whole setup. Re-activate the env
(`source .venv/bin/activate`) in any new shell before running a stage.

On a minimal Debian/Ubuntu box `python3 -m venv` can fail with
`ensurepip is not available` and `pip` may be missing entirely; install the
OS packages first, then retry the block above:

```bash
sudo apt install python3-venv python3-pip
```

## Stage 1 — analyze  ([`analyze/`](analyze/))

```bash
cd pipeline

python3 analyze/ast_symtab/extract.py <src_dir> -o ast_out
#   -> ast_out/{methods.jsonl, symbol_table.json, call_graph.json}

python3 analyze/candidate_narrowing/prefilter_rank_candidates.py ast_out/methods.jsonl -o candidates.jsonl
python3 analyze/candidate_narrowing/llm_final_verdict.py ast_out/methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl
#   -> verdicts.jsonl  (per-method security verdicts; unparseable replies land in errors.jsonl)

python3 analyze/candidate_narrowing/filter_verdicts.py verdicts.jsonl -o filtered_verdicts.jsonl
#   -> filtered_verdicts.jsonl  (is_security_relevant only, ranked by severity/confidence, top N)
```

Skip the pre-filter (small codebases / the "no narrowing" ablation arm) by
omitting `--candidates`: every extracted method is then verdicted.
`filter_verdicts.py -n N` caps how many methods pass to Stage 2 (default 5).

## Stage 2 — harness  ([`harness/`](harness/))

**Each/each model:** one fuzzing applet + one driver per method. Every applet
wraps exactly one operation, so the INS byte is fixed (no dispatch), and each
shortlisted method gets its own `FuzzApplet<Op>`/`FuzzDriver<Op>` pair. The
three steps carry the whole shortlist through together — `context.json` and
`operation.json` are **JSON lists** (one element per method), and
`assemble_harness.py` writes one pair per method into its own sub-directory:

```bash
python3 harness/harness_extraction/extract_context.py <src_dir> ast_out --verdicts filtered_verdicts.jsonl -o context.json
#   -> context.json    (JSON list: one context object per security-relevant method)
python3 harness/harness_extraction/llm_extract_operation.py context.json -o operation.json
#   -> operation.json  (JSON list: one operation per method, tagged with its {class, method})
python3 harness/harness_extraction/assemble_harness.py context.json operation.json -o generated/
#   -> generated/<Class>.<method>/{FuzzApplet<Op>.java, FuzzDriver<Op>.java}   (one pair per method)
```

**Two harness modes** (chosen per method by `llm_extract_operation.py`, hinted
by `extract_context.py`'s `suggested_mode`):
- **`inline-core`** — copy the method body verbatim (minus declared removals:
  lifecycle/secure-channel/key-selection/…) into the applet as `coreXxx()`; the
  wrapper unpacks the APDU and calls it. For applet-level entry methods that
  bundle removable I/O setup around the secret-dependent core.
- **`invoke-instance`** — copy nothing; the wrapper constructs a **real**
  receiver + argument objects (via the class's real constructors, surfaced in
  `context.json`'s `construction_api`) and calls the real method, then
  serializes the result. For instance methods of rich domain classes
  (JCMathLib's `BigNat`/`Integer`/`ECPoint`) whose bodies rely on `this`/private
  state and can't be lifted into the applet. This reproduces the hand-written
  DifFuzz-applet style.

The harness package defaults to the target applet's **own** package, so each
pair drops straight into the applet source tree and same-package helper classes
need no import; helper classes are **referenced by import, not copied**. Pass
`--package` to override. `assemble_harness.py` fills the templates in
[`../skeletons/`](../skeletons/) (located by walking up to the repo root, so it
works from any cwd).

Each `FuzzApplet<Op>`/`FuzzDriver<Op>` pair is then compiled in the applet's own
source tree and run under the DifFuzz/Kelinci/AFL++ toolchain — handled by the
[`../automation/`](../automation/) tools (`build_target.py` to compile, then the
printed Part-2 commands to instrument + fuzz).

Per-method failures don't abort the batch: a method whose extraction fails the
gate is recorded (`operation_errors.json`) and skipped, and the commands exit
non-zero so the rest of the shortlist still produces harnesses.

Variations:
- **Target one method by hand** instead of the whole shortlist:
  `extract_context.py ... --method Class.method` (exactly one of `--method` /
  `--verdicts` is required). Then `context.json`/`operation.json` are single
  objects and `assemble_harness.py` writes one pair straight into `-o`; add
  `--class-name FuzzAppletXxx` to name it.
- **Offline dry run**: add `--mock` to both `llm_final_verdict.py` and
  `llm_extract_operation.py`.
- **Regenerate only the drivers** for an existing/hand-written FuzzApplet:
  `python3 harness/drivergen/generate_drivers.py --applet path/to/XxxFuzzApplet.java`.

Smoke test: [`harness/harness_extraction/fixture/`](harness/harness_extraction/)
ships a synthetic applet and a scripted `--mock` run of the whole stage — see
that tool's README ("Fixture").

## Stage 3 — seeds  ([`seeds/`](seeds/))

Build the initial corpus before launching AFL++ (run from `pipeline/seeds/` so
the package is importable):

```bash
cd pipeline/seeds
python3 -m initial --applet path/to/XxxFuzzApplet.java --output-dir seeds/
#   LLM + deterministic seeds in the fixed-offset layout every FuzzDriver consumes
python3 -m initial --no-llm --max-data 64 --output-dir seeds/HmacSha160   # deterministic-only baseline
```

Then, during a running campaign, `seeds/sidecar/` observes AFL++ and feeds it
fresh LLM-generated inputs via foreign-sync (`-F`) — see
[`seeds/sidecar/README.md`](seeds/sidecar/README.md).

## Stage 4 — eval  ([`eval/`](eval/))

After a campaign, summarize the AFL++ output directory:

```bash
python3 pipeline/eval/parse_afl_output.py <afl_out_dir> [--instance main] [--json]
```

The generated `FuzzApplet*`/`FuzzDriver*` pair plus seed corpus are handed to
the fuzzing engine in [`../engine/`](../engine/); this stage reads back what it
produced.
