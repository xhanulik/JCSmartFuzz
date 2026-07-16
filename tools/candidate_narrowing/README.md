# Candidate methods narrowing

Two-stage narrowing pipeline on top of the per-method records
`ast_symtab/extract.py` produces:

- **Stage 1 — deterministic pre-filter** (`prefilter_*.py`): three cheap,
  pure-Python signal sources merged and ranked into a shortlist
  (`candidates.jsonl`). This is what keeps the LLM off the whole repo, and
  doubles as a heuristic-only ablation baseline (LLM-with-narrowing vs.
  LLM-over-the-full-shortlist vs. no narrowing).
- **Stage 2 — LLM narrowing** (`llm_final_verdict.py`): one focused API
  call per surviving candidate, producing the pipeline's **ultimate,
  per-method output** — a structured, schema-validated security verdict.

## Pipeline

```
py ../ast_symtab/extract.py <src_dir> -o ast_out             # prereq: build methods.jsonl
py prefilter_rank_candidates.py ast_out/methods.jsonl -o candidates.jsonl   # stage 1
export LLM_API_TOKEN=...
py llm_final_verdict.py ast_out/methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl  # stage 2
```

Stage 2 can also run directly against `methods.jsonl` with stage 1 skipped
entirely — omit `--candidates` and every extracted method is verdicted:

```
py llm_final_verdict.py ast_out/methods.jsonl -o verdicts.jsonl
```

Useful for small codebases where pre-filtering isn't worth it, for
auditing what the deterministic stage discards (compare its verdicts
against the pre-filtered run), or as the "no narrowing" arm of the
narrowing-vs-no-narrowing ablation. `fired_rules` is simply empty for
these candidates and the prompt says so explicitly instead of referencing
a pre-filter that didn't run.

`candidates.jsonl` (stage 1 output) — one JSON object per flagged method,
sorted by score descending:
```json
{"file": "...", "class": "PinApplet", "method": "checkPin", "score": 12,
 "fired_rules": [
   {"rule_id": "early-return-array-compare", "source": "idiom", "weight": 3, "hit_count": 1, "lines": [4]},
   {"rule_id": "dataflow-branch-on-secret", "source": "dataflow", "weight": 4, "hit_count": 1, "lines": [13]},
   ...
 ], "rank": 1}
```

## Stage 1: the three signal sources

### A. Name matching

Script: `prefilter_idiom_signals.py`

AST-shape pattern matching for the
leaky idioms: early-return array/byte comparison, secret-length loop
bound (literal name match), branch-on-secret (literal name match),
branch-on-secret-in-loop (a two-way if/else nested inside a for/while/do
loop, whose condition references a secret-named variable/field --
distinct from plain branch-on-secret because it additionally requires an
`else` arm and loop nesting, i.e. a real per-iteration two-way choice
whose cost gets paid every iteration, amplifying any timing skew between
the branches), custom XOR loop, custom bit-rotate.

### B. Cheap interprocedural taint analysis

Script: `prefilter_dataflow_signals.py`**

A lightweight stand-in for a real
CPG dataflow tier, built entirely on the AST `ast_symtab` already
parsed (no external tool).

#### How it works
Per method, it:

1. re-parses the method's own source
snippet (already stored verbatim by `ast_symtab`) into a fresh AST;
2. seeds a "tainted" name set from parameters, locals, and instance fields
whose name matches a secret/crypto regex (fields only seed if
`ast_symtab`'s `field_dataflow` classified them `read_before_write`,
i.e. consumed from outside the method, not computed by it);
3. propagates that taint through up to 3 passes of *straight-line alias
assignment only* — `Assignment`/`LocalVariableDeclaration` nodes whose
right-hand side is a bare identifier already in the tainted set;
4. scans every `for` loop's condition and every `if`/`while`/`do` condition
for any identifier that intersects the final tainted set, emitting
`dataflow-secret-length-loop` / `dataflow-branch-on-secret` findings.

#### What it catches that a literal-name rule misses:

`byte[] p = pin;` followed by `for (i = 0; i < p.length; i++)` — the loop bound is
`p`, not `pin`, so a rule matching identifier names directly against
`pin|secret|key|...` never fires, but the one-hop alias propagation
here does, because `p` inherits the taint from `pin` before the loop
condition is scanned.

#### What it still misses

A taint through anything other than a bare-name assignment — a copy via
`Util.arrayCopyNonAtomic(pin, 0, buf, 0, len)`, a field chain
(`this.state.key`), an array element (`byte[] a = {pin[0]}`), or a
ternary — is invisible, since only direct `x = y` aliasing is
propagated; taint through a method call (`helper(pin)` branching
inside `helper`) is invisible, since each method is analyzed from its
own `methods.jsonl` record in isolation with no call-graph awareness;
and there's no real control-flow sensitivity — a field tainted on only
one branch of an `if` still counts everywhere afterward in this flat
AST walk, since branches aren't modeled as mutually exclusive paths.

### C. Name matching
Script: `prefilter_name_signals.py`

Cheapest tier: method/class/param/
local/field names matching a secret/crypto regex, with no parsing
beyond what `ast_symtab` already extracted. This is the floor of the
ablation: how much signal do you get from names alone, with zero
structural analysis?

All three "does this name look like secret material" checks (idiom's
loop-bound/branch name checks, dataflow's taint seeding, and name's own
top-level check) share one regex, `SECRET_RE` in `secret_keywords.py`
(plus `CRYPTO_METHOD_RE` for method-name matching) — a single place to
extend the keyword list instead of three copies drifting apart.

`prefilter_rank_candidates.py` merges the three sources and ranks: it sums
a fixed per-rule weight (`RULE_WEIGHTS`) over every distinct rule that
fired for a method (repeated hits of the same rule count once for the
score, but `hit_count`/`lines` record how many). Weights roughly reflect
specificity: the two dataflow rules (which require data to actually flow
from a secret into a branch/loop bound) outweigh the literal-name
idiom/name-only rules.

## Stage 2: per-candidate LLM verdict (`llm_final_verdict.py`)

The pipeline's final, ultimate-output step: for every surviving candidate,
one focused API call sends the method source + its immediate context
(direct, internally-resolved callees' source, pulled from
`methods.jsonl`) + the rule(s) that fired, and asks for a structured
verdict as strict JSON:

```json
{
  "is_custom_crypto": false,
  "is_security_relevant": true,
  "leak_mechanism": "timing-early-return-compare",
  "confidence": 0.9,
  "rationale": "checkPin exits the comparison loop as soon as the first byte differs from storedPin, so response time reveals the length of the matching prefix."
}
```

`leak_mechanism` is constrained to a fixed enum (see `LEAK_MECHANISMS` in
`llm_final_verdict.py`): `timing-early-return-compare`,
`timing-secret-length-loop`, `timing-branch-on-secret`,
`custom-crypto-primitive`, `none` (pre-filter false positive), `other`.

**Gate:** the reply is parsed (tolerant of code fences/prose wrapping) and
validated against the exact schema above (types, the `leak_mechanism`
enum, `confidence` in `[0,1]`, no missing/extra fields). A response that
fails validation is re-queried with the validation error appended to the
prompt (`--retries`, default 2); if it still doesn't validate, the
candidate is dropped from `verdicts.jsonl` into `errors.jsonl` instead —
never silently discarded from the run's accounting.

**LLM call settings are copied verbatim from `jcseedgen/generator.py`**
(`LLMSeedGenerator.call_llm`): the e-INFRA CZ OpenAI-compatible
`/v1/chat/completions` endpoint, `gpt-oss-120b` default model, bearer
token from `LLM_API_TOKEN`, 120s timeout, plain `urllib` (no extra HTTP
dependency) — so this stage uses the same backend/auth as the rest of the
pipeline rather than introducing a second LLM client.

```
export LLM_API_TOKEN=...
py llm_final_verdict.py methods.jsonl --candidates candidates.jsonl -o verdicts.jsonl
# or, skipping stage 1 entirely:
py llm_final_verdict.py methods.jsonl -o verdicts.jsonl
```

`--mock` runs a canned local responder instead of the real API — useful
for testing the schema/retry gate without network access or a token. It
also deliberately returns a malformed payload on every 3rd call, so a
`--mock` run demonstrates both the retry-then-recover path and the
retry-exhausted-then-drop path (`--retries 0`) without needing a live
failure from the real model. Verified against the fixture: `checkPin`,
`checkPinRenamed`, and `mix` validate on the first attempt;
`applyDiscount` (the 3rd candidate) gets the injected malformed reply,
fails validation, and recovers on the retry.
