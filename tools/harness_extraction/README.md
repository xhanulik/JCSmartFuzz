# harness_extraction

Stage 3 of the pipeline: turns ONE chosen method into a working
`FuzzApplet*.java` / `FuzzDriver*.java` pair from `skeletons/`. Automates
what `skeletons/README.md` describes as a manual copy-paste-into-an-LLM-chat
step, following the same shape as `ast_symtab` → `candidate_narrowing`:
push everything mechanical into deterministic code, and shrink the LLM's
job down to exactly the part that needs judgment.

## Pipeline

```
py ../ast_symtab/extract.py <src_dir> -o ast_out                          # prereq
py extract_context.py <src_dir> ast_out --method Class.method -o context.json
export LLM_API_TOKEN=...
py llm_extract_operation.py context.json -o operation.json
py assemble_harness.py context.json operation.json --package com.example.fuzz -o generated/
```

Or, chained straight off `candidate_narrowing`'s output instead of naming a
method by hand:

```
py extract_context.py <src_dir> ast_out --verdicts ../candidate_narrowing/verdicts.jsonl -o context.json
```

## 1. `extract_context.py` (deterministic)

Resolves the target method (`--method Class.method`, or the top
`is_security_relevant` entry from `--verdicts` if `--method` is omitted)
and gathers everything the LLM step needs, entirely from data already on
disk:

- the method's exact source + its full transitive internal-call closure
  (both straight from `ast_symtab`'s `methods.jsonl` -- no re-deriving)
- every non-local field the method or its helpers touch, split into:
  - **constants** / **error codes** (`static final`, split by an `SW_`
    name-prefix check) -- verbatim declaration text
  - **fields** (real instance state) -- verbatim declaration text *and*
    the constructor's own init line for each, found by re-parsing just the
    constructor's snippet (already in `methods.jsonl` since the
    `ast_symtab` extension below)
- which other classes among the call closure need to be copied verbatim
  into the harness package (utility/helper classes -- per
  `llm_extraction_prompt.md` rule 7, these are assumed available as-is,
  not reproduced by the LLM)
- the next INS byte (`--ins` to pin it explicitly)

This required one small, additive change to `tools/ast_symtab/extract.py`:
it now also extracts `ConstructorDeclaration` nodes (recorded as
`"method": "<init>"`), reusing 100% of the existing per-method machinery
(`field_dataflow` on a constructor naturally reports every field it
initializes, `source` gives the verbatim init code).

Source file paths recorded in `methods.jsonl` are relative to whatever cwd
`ast_symtab/extract.py` happened to run from -- often not this script's
cwd. `extract_context.py` re-resolves every file path by basename under
the `--src-dir` you pass it rather than trusting the literal stored path.

## 2. `llm_extract_operation.py` (the one LLM call + gate)

The only step that needs judgment: deciding what to strip from the core
method (the fixed categories from `llm_extraction_prompt.md` --
`lifecycle guard | cache | state mutation | secure channel | key selection
| logging`) and writing the wrapper. One prompt, strict JSON response:

```json
{
  "operation_name": "VerifyPin",
  "ins_name": "INS_VERIFY_PIN",
  "timing_risk": "...",
  "core_method": {"name": "coreVerifyPin", "code": "...", "removed_lines": [...], "field_mapping": [...], "precondition": "..."},
  "wrapper_method": {"name": "wrapVerifyPin", "code": "...", "data_layout_comment": "..."}
}
```

**Two-layer gate**, both must pass or the call is re-queried with the
specific error appended (`--retries`, default 2):
1. **JSON-schema validation** -- required fields, types, the fixed
   `removed_lines[].category` enum.
2. **Fidelity diff** -- reconstructs the target method's original body
   with the LLM's *own declared* `removed_lines` stripped out, and diffs
   it against `core_method.code` (interior lines only -- the signature
   line is allowed to change since the core gets a new name; whitespace-
   insensitive). Any undeclared difference fails the gate. This
   automates the manual verification step
   `llm_extraction_prompt.md` calls for by hand ("diff each core method
   body against the original source... Only ALLOWED REMOVALS may
   differ").

Same LLM call settings as `tools/candidate_narrowing/llm_final_verdict.py`
(itself copied from `jcseedgen/generator.py`): e-INFRA CZ
`/v1/chat/completions`, `gpt-oss-120b` default, `LLM_API_TOKEN` bearer
auth, plain `urllib`. `--mock` exercises the gate without network/token --
it deliberately returns an undeclared-removal response on the first
attempt (fails the fidelity check) and the properly-declared version on
retry, so a `--mock` run demonstrates the gate actually catching a bad
response, not just rubber-stamping.

## 3. `assemble_harness.py` (deterministic)

Fills every `{{GENERATED: ...}}` / `/* GENERATED: ... */` marker in
`skeletons/FuzzAppletSkeleton.java` and `FuzzDriverSkeleton.java` by plain
string substitution (package/class names, imports, INS constant,
constants/error-codes/fields sections, constructor init lines, dispatcher
`case` entry, wrapper + core method bodies, core method's Javadoc --
assembled from `operation.json`'s structured fields, not left to the LLM
to format). Copies the helper-class files `extract_context.py` identified
verbatim into the output directory, rewriting only their `package` line.

**Final verification**: every assembled/copied `.java` file is parsed
with `javalang` and checked for zero leftover `GENERATED` markers --
fails loudly (non-zero exit, listing every problem) instead of emitting a
half-filled skeleton.

## Fixture (smoke test)

`fixture/src/FixtureApplet.java` + `PinHelper.java`: a synthetic
PIN-check operation with a lifecycle guard (removable), a state mutation
(removable), a call to a helper utility class, a constructor, an instance
field, and a constant only referenced by the constructor's init line (not
by the operation itself -- this specifically exercises pulling
constructor-only constants into context, a real bug caught and fixed
during development).

```
py ../ast_symtab/extract.py fixture/src -o fixture/ast_out
py extract_context.py fixture/src fixture/ast_out --method FixtureApplet.verifyPin -o fixture/context.json
py llm_extract_operation.py fixture/context.json -o fixture/operation.json --mock
py assemble_harness.py fixture/context.json fixture/operation.json --package fixture -o fixture/generated
```

Verified: all 3 output files parse cleanly with zero unresolved markers;
`PinHelper.java` is copied verbatim with its package line rewritten;
`MAX_PIN_LEN` (referenced only inside the constructor's init line) is
correctly pulled into the constants section; the driver's import is
package-qualified and its own class is correctly renamed (not left as
`FuzzDriverSkeleton`).
