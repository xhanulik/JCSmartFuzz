# automation/harness_gen

Generate ready-for-`fuzz_build` harnesses for one corpus repo by gluing the
`pipeline/` analyze + harness stages (clone → ast_symtab → prefilter → LLM
verdict → filter → extract_context → LLM operation → assemble). Stops before
compilation.

## Run

```bash
# from the repo root, once:
python3 -m venv .venv && source .venv/bin/activate && pip install javalang

export LLM_API_TOKEN=...          # the LLM steps run automatically (omit only with --mock)
python3 automation/harness_gen/generate_harnesses.py --entry "JCMathLib" -n 5
```

Run it inside the venv — it re-invokes the pipeline scripts with the same
interpreter, which needs `javalang`; `git` must be on `PATH`.

| flag | meaning |
|------|---------|
| `--entry` | corpus entry name or link substring (required) |
| `-n, --count` | desired number of harnesses (default 5) |
| `--out` | artifacts dir (default `./harness-out/<repo>/`) |
| `--work` | clone cache (default `~/.cache/jcsmartscan-builds`, shared with `build_target`) |
| `--ins` | INS byte for extract_context (default `0x10`) |
| `--mock` | run the LLM steps with a canned responder (no token; wiring test only) |
| `--dry-run` | print the command plan and exit |

If the pre-filtered + verdicted methods don't reach `-n`, it re-verdicts **all**
methods with the LLM (no pre-filter) and filters to N.

## Output

Under `--out`: `ast_out/`, the `*.jsonl` verdicts, `context.json`,
`operation.json`, and `generated/<Class>.<method>/{FuzzApplet*,FuzzDriver*}.java`
— one pair per method. It prints the build command for each; then:

```bash
python3 ../fuzz_build/build_target.py --entry "JCMathLib" \
    --harness-out harness-out/JCMathLib/generated/Integer.add/
```

> `--mock` only exercises the plumbing; the canned responder can't produce valid
> harnesses for real methods. Real output needs `LLM_API_TOKEN`.
