# profile — single-invocation profiling inputs

The differential-fuzzing harness ([`../harness/`](../harness/)) runs an operation
**twice** (input sets A and B) and reports `|costA - costB|`. The **profiling**
variant, [`skeletons/ProfileAppletSkeleton.java`](../../skeletons/ProfileAppletSkeleton.java),
runs the operation **once** and reports the single instruction cost (worst-case
analysis — AFL++ drives inputs toward maximum cost).

A ProfileApplet input is therefore exactly **half** a FuzzApplet input: one
input set instead of two.

| | layout | size |
|---|--------|------|
| FuzzApplet input (fixed-offset, read by `FuzzDriver`) | `[p1_A|p2_A|len_A|data_A(MAX_DATA) | p1_B|p2_B|len_B|data_B(MAX_DATA)]` | `6 + 2*MAX_DATA` |
| ProfileApplet input (one slot) | `[p1|p2|len|data(MAX_DATA)]` | `3 + MAX_DATA` |

## `assemble_profile.py`

Fills `ProfileAppletSkeleton.java` with the extracted core + wrapper methods and
context, producing `ProfileApplet<Op>.java`. It **reuses the harness-extraction
data and code**: the same `context.json` (from `extract_context.py`) +
`operation.json` (from `llm_extract_operation.py`), and
[`../harness/harness_extraction/assemble_harness.py`](../harness/harness_extraction/)'s
own `fill_applet` — the ProfileApplet skeleton carries the identical
`{{GENERATED}}` markers, so the substitution is shared; only the fixed Layer-1
framing (single vs dual invocation) differs, and that lives in the skeleton.

```bash
python3 assemble_profile.py context.json operation.json [--package P] [--class-name N] -o generated/
```

Defaults: package = the target applet's own package; class name =
`ProfileApplet<OperationName>`. Ends with the same `javalang` verification pass
(parses cleanly, no unresolved markers). Drop the result into the applet source
tree and compile it like the FuzzApplet (see [`../../automation/fuzz_build/`](../../automation/fuzz_build/));
a dedicated ProfileDriver (single-slot input) is a small future addition.

## `split_inputs.py`

Reads a directory of FuzzApplet fuzzing inputs (e.g. an AFL++ `queue/` or the
seed corpus from [`../seeds/initial`](../seeds/initial)) and writes, for each,
the A slot and the B slot as two separate ProfileApplet inputs — mirroring the
`FuzzDriver`'s fixed-offset interpretation (short inputs zero-padded, longer
inputs truncated, to `6 + 2*MAX_DATA`).

```bash
python3 split_inputs.py <fuzz_input_dir> -o <profile_out_dir> \
    [--max-data 64] [--which both|A|B] [--recursive]
```

- `--max-data` **must match the FuzzDriver's `MAX_DATA`** for the operation
  (default 64); it determines the slot boundary.
- `--which` selects which slot(s) to emit (default `both` → `<name>_A` and
  `<name>_B`).

Each output file is `3 + MAX_DATA` bytes and is a ready ProfileApplet input.

> The ProfileApplet reuses the exact same `{{GENERATED}}` markers, core/wrapper
> methods, and context as the FuzzApplet — which is why `assemble_profile.py`
> can reuse `assemble_harness.py`'s `fill_applet` directly.
