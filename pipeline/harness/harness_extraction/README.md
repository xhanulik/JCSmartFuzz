# harness_extraction

The core of **Stage 2 (harness)** of the pipeline: turns ONE chosen method
into a working `FuzzApplet*.java` / `FuzzDriver*.java` pair from `skeletons/`.
Automates what `skeletons/README.md` describes as a manual
copy-paste-into-an-LLM-chat step, following the same shape as **Stage 1**
(`ast_symtab` → `candidate_narrowing`): push everything mechanical into
deterministic code, and shrink the LLM's job down to exactly the part that
needs judgment.

The harness contains **only the extracted core + wrapper methods plus the
context they need** (constants, error codes, fields and their constructor init
lines, and the wrapper's split of the fuzz input). It is meant to be dropped
into the applet's **own source directory** and compiled there, so helper
classes/methods the core calls are **not** copied or reproduced — the core
calls them as-is and the harness just `import`s any that live in a different
package.

## Pipeline

```
py ../../analyze/ast_symtab/extract.py <src_dir> -o ast_out                          # prereq
py extract_context.py <src_dir> ast_out --method Class.method -o context.json
export LLM_API_TOKEN=...
py llm_extract_operation.py context.json -o operation.json
py assemble_harness.py context.json operation.json -o generated/
```

`assemble_harness.py` defaults the harness package to the target applet's own
package (so it drops straight into the source tree); pass `--package` to
override.

Or, chained straight off `candidate_narrowing`'s output instead of naming a
method by hand. In the **each/each** model one applet+driver is built per
method, so `--verdicts` extracts a context for **every** `is_security_relevant`
method in the shortlist (not just the top one). All of them are carried in the
one `context.json` as a JSON list, and `llm_extract_operation.py` emits a
matching `operation.json` list (one operation per method, each tagged with its
`{class, method}` target):

```
py extract_context.py <src_dir> ast_out --verdicts ../../analyze/candidate_narrowing/filtered_verdicts.jsonl -o context.json
export LLM_API_TOKEN=...
py llm_extract_operation.py context.json -o operation.json     # list in -> list out
```

## 1. `extract_context.py` (deterministic)

Resolves the target method(s) — a single `--method Class.method` (context.json
is one object), or **every** `is_security_relevant` entry from `--verdicts`
(context.json is a JSON list, one object per method — the each/each default) —
and gathers everything the LLM step needs, entirely from data already on disk:

- the method's exact source + its full transitive internal-call closure
  (both straight from `ast_symtab`'s `methods.jsonl` -- no re-deriving)
- every non-local field the method or its helpers touch, split into:
  - **constants** / **error codes** (`static final`, split by an `SW_`
    name-prefix check) -- verbatim declaration text
  - **fields** (real instance state) -- verbatim declaration text *and*
    the constructor's own init line for each, found by re-parsing just the
    constructor's snippet (already in `methods.jsonl` since the
    `ast_symtab` extension below)
- the target applet's **package** and the set of **helper classes to import**
  (every other class among the call closure that owns a called method), each
  with its package so `assemble_harness.py` can emit an `import` for the ones
  outside the harness package -- these are *not* copied or reproduced, only
  referenced
- the next INS byte (`--ins` to pin it explicitly)
- a **`construction_api`**: the public constructor + method *signatures* (no
  bodies) of the target's own class, its parameter/return types that are project
  classes, and — transitively — the project classes appearing in those
  constructors' parameters (e.g. the `ResourceManager` an
  `Integer(byte[],off,len,rm)` needs). This is what an `invoke-instance` wrapper
  builds against, so the LLM uses real signatures instead of guessing.
- a **`suggested_mode`** heuristic: `inline-core` for applet-entry / static
  methods, `invoke-instance` for instance methods of non-applet classes (see §2).

This required one small, additive change to `pipeline/analyze/ast_symtab/extract.py`:
it now also extracts `ConstructorDeclaration` nodes (recorded as
`"method": "<init>"`), reusing 100% of the existing per-method machinery
(`field_dataflow` on a constructor naturally reports every field it
initializes, `source` gives the verbatim init code).

Source file paths recorded in `methods.jsonl` are relative to whatever cwd
`ast_symtab/extract.py` happened to run from -- often not this script's
cwd. `extract_context.py` re-resolves every file path by basename under
the `--src-dir` you pass it rather than trusting the literal stored path.

## 2. `llm_extract_operation.py` (the one LLM call + gate)

The judgment step. It first picks a **harness mode** (`suggested_mode` is the
default hint; the LLM may override):

- **`inline-core`** — copy the method body verbatim-minus-removals into the
  applet as `coreXxx()`; the wrapper unpacks the APDU and calls it. Removals are
  the fixed categories (`lifecycle guard | cache | state mutation | secure
  channel | key selection | logging`) and are **fidelity-checked** against the
  original body. For applet-level entry methods with removable I/O setup.
- **`invoke-instance`** — copy **nothing**. The wrapper constructs a real
  receiver + argument objects (using only the `construction_api` constructors),
  calls the real method, and serializes via a real public method (e.g.
  `toByteArray`). `core_method` is `null` and the fidelity check does not apply.
  For instance methods of rich domain classes (`BigNat`/`Integer`/`ECPoint`)
  whose bodies rely on `this`/private state and can't be lifted into the applet
  — the same pattern a hand-written DifFuzz applet uses.

One prompt, strict JSON response (shape shown for `inline-core`; in
`invoke-instance` mode `core_method` is `null` and there are no `removed_lines`):

```json
{
  "operation_name": "VerifyPin",
  "ins_name": "INS_VERIFY_PIN",
  "timing_risk": "...",
  "core_method": {"name": "coreVerifyPin", "code": "...", "removed_lines": [...], "field_mapping": [...], "precondition": "..."},
  "wrapper_method": {"name": "wrapOperation", "code": "...", "data_layout_comment": "..."}
}
```

`wrapper_method.name` is the fixed `wrapOperation` (the skeleton's `process()`
calls the wrapper by that name — each applet has one operation, no INS
dispatch); the gate rejects any other name. When `context.json` is a **list**
(the `--verdicts` flow) the script runs this call once per method and writes an
`operation.json` **list**, each element tagged with its `{class, method}` so
`assemble_harness.py` can pair it back; a method that fails the gate is recorded
in `operation_errors.json` and skipped, without aborting the rest.

**Two-layer gate**, both must pass or the call is re-queried with the
specific error appended (`--retries`, default 2):
1. **JSON-schema validation** -- required fields, types, the fixed
   `removed_lines[].category` enum.
2. **Fidelity diff** -- reconstructs the target method's original body
   with the LLM's *own declared* `removed_lines` stripped out, and diffs
   it against `core_method.code` (interior lines only -- the signature
   line is allowed to change since the core gets a new name; whitespace-
   insensitive). Any undeclared difference fails the gate. This
   automates the otherwise-manual verification step: diff each core
   method body against the original source, allowing only the declared
   ALLOWED REMOVALS to differ.

The LLM backend is resolved through the shared `pipeline/llm_config.py` loader
(endpoint/model/timeout/token via **env var > `llm_config.ini` > default**),
the same as every other LLM-calling stage — an OpenAI-compatible
`/v1/chat/completions` endpoint over plain `urllib`. `--mock` exercises the gate without network/token --
it deliberately returns an undeclared-removal response on the first
attempt (fails the fidelity check) and the properly-declared version on
retry, so a `--mock` run demonstrates the gate actually catching a bad
response, not just rubber-stamping.

## 3. `assemble_harness.py` (deterministic)

Fills every `{{GENERATED: ...}}` / `/* GENERATED: ... */` marker in
`skeletons/FuzzAppletSkeleton.java` and `FuzzDriverSkeleton.java` by plain
string substitution (package/class names, imports,
constants/error-codes/fields sections, constructor init lines, the single
wrapper call in `process()`, wrapper + core method bodies, core method's
Javadoc -- assembled from `operation.json`'s structured fields, not left to the
LLM to format). Each applet fuzzes exactly one operation, so there is no INS
dispatch: `process()` calls the generated wrapper directly (the driver still
sends a fixed `FUZZ_INS` for a well-formed APDU). The package defaults to the
target applet's own package
(`--package` overrides). Imports are the applet's own imports plus an
`import` for each helper class from `context.json` whose package differs from
the harness package; helper classes are **not** copied — the harness compiles
alongside them in the applet source tree.

It also fills by **mode**: for `invoke-instance` there is no `coreXxx` to insert
(the wrapper calls the real method), so the core marker becomes a one-line note,
the applet declares **no** generated constants/error-codes/fields (those live on
the constructed object, not the harness), and imports are added for any
`construction_api` class in a different package. For `inline-core` it fills the
copied core + re-declared fields as above.

It mirrors the shape of its inputs (each/each). Given **single** `context.json`
+ `operation.json` objects (`--method` flow) it writes one pair straight into
`-o`. Given **JSON lists** (`--verdicts` flow, several methods) it pairs each
operation to its context by the `{class, method}` tag and writes one
`FuzzApplet<Op>`/`FuzzDriver<Op>` pair per method into
`-o/<Class>.<method>/` (`--class-name`/`--driver-class-name` are single-input
only; the list case uses the `FuzzApplet<Op>`/`FuzzDriver<Op>` defaults). An
operation with no matching context is skipped and the run exits non-zero.

**Final verification**: every assembled `.java` file is parsed with `javalang`
and checked for zero leftover `GENERATED` markers -- fails loudly (non-zero
exit, listing every problem) instead of emitting a half-filled skeleton.

## Fixture (smoke test)

`fixture/src/FixtureApplet.java` + `PinHelper.java`: a synthetic
PIN-check operation with a lifecycle guard (removable), a state mutation
(removable), a call to a helper utility class, a constructor, an instance
field, and a constant only referenced by the constructor's init line (not
by the operation itself -- this specifically exercises pulling
constructor-only constants into context, a real bug caught and fixed
during development).

```
py ../../analyze/ast_symtab/extract.py fixture/src -o fixture/ast_out
py extract_context.py fixture/src fixture/ast_out --method FixtureApplet.verifyPin -o fixture/context.json
py llm_extract_operation.py fixture/context.json -o fixture/operation.json --mock
py assemble_harness.py fixture/context.json fixture/operation.json -o fixture/generated
```

Verified: exactly **two** files are produced (`FuzzAppletVerifyPin.java`,
`FuzzDriverVerifyPin.java`) and both parse cleanly with zero unresolved
markers; **`PinHelper.java` is NOT copied** — the core still calls
`PinHelper.foldChecksum(...)` as-is, and because `PinHelper` shares the
applet's `fixture` package (the harness default) no import is added (assembling
with `--package com.example.fuzz` instead adds `import fixture.PinHelper;`);
`MAX_PIN_LEN` (referenced only inside the constructor's init line) is correctly
pulled into the constants section; the driver's import is package-qualified and
its own class is correctly renamed (not left as `FuzzDriverSkeleton`).

## Editing the prompt

The extraction prompt lives in
[`prompts/extract_operation.md`](prompts/extract_operation.md), not in the
Python. Edit that file to tune the wording or the allowed-removal rules — no
code change needed. `{{marker}}` placeholders (e.g. `{{numbered_source}}`,
`{{removal_categories}}`) are filled by `build_prompt()` in
`llm_extract_operation.py`; keep them intact and don't add new ones without a
matching value in that function.
