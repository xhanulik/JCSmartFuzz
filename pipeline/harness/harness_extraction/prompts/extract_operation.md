You are turning ONE already-chosen timing-sensitive operation of a Java Card
applet into a differential-fuzzing harness method. Your job is only the
extraction below for the single method named here.
{{hint}}
=== Target method (line-numbered; line numbers are relative to THIS listing) ===
Class: {{target_class}}
Method: {{target_method}}
{{numbered_source}}

=== Internal helper methods this method calls (context only -- do NOT reproduce, inline, or copy these; the harness compiles inside the applet's own source tree so they are already available and imported. Call them exactly as the original does) ===
{{helpers_block}}

=== Non-local instance fields this method (or its helpers) touch, with how the original constructor initializes them ===
{{fields_block}}

=== Constants available (paste verbatim if referenced) ===
{{constants_block}}

=== Error codes available ===
{{error_codes_block}}

=== Public construction API (for invoke-instance mode) ===
Real public constructors + method signatures of the target's own class and the
classes needed to build/serialize it. Use these EXACT signatures -- do not
invent constructors or methods that are not listed here.
{{construction_api_block}}

=== Choose the harness mode ===
Suggested mode (heuristic -- override only if clearly wrong): {{suggested_mode}}

There are two mutually exclusive modes; pick the one that fits the target:

- "inline-core": the method body is COPIED (verbatim-minus-removals) into the
  fuzzing applet as a coreXxx() method, and a wrapper unpacks the APDU and calls
  it. Use this for an applet-level entry method (e.g. a process()/command
  handler) that bundles removable setup -- APDU/secure-channel decoding,
  lifecycle guards, key selection -- around the secret-dependent core, so that
  trimming isolates the timing-sensitive part.

- "invoke-instance": DO NOT copy the body. The wrapper constructs a REAL
  receiver object (and any argument objects) from the fuzz bytes using the
  constructors in the construction API above, calls the real method on it, and
  serializes the result with the real public API. Use this for an instance
  method of a normal (non-applet) class whose body relies on `this`, private
  fields, or sibling instance methods -- such a body CANNOT be lifted into the
  applet, and the real method already contains only the operation (nothing to
  trim). This mirrors a hand-written DifFuzz applet.

=== Task ===

Respond with STRICT JSON ONLY (no prose, no markdown fences). In BOTH modes the
wrapper's signature is fixed and MUST be exactly:

    private short wrapOperation(APDU apdu, byte[] buffer)

(the harness `process()` calls `wrapOperation(apdu, buffer)` directly -- each
applet fuzzes one operation, no INS dispatch; do NOT change the name, parameter
types, or their order). It reads P1/P2/CDATA from `buffer` (a `byte[]`; e.g.
`buffer[ISO7816.OFFSET_P1]`, data at `ISO7816.OFFSET_CDATA`), and measures cost
around the operation like this:

    Mem.clear();
    <the operation>;              // coreXxx(...) in inline-core; recv.method(args) in invoke-instance
    lastCoreCost = Mem.instrCost;

then formats output into `buffer[0..]` and returns the output size as `short`.

--- If mode == "inline-core", produce this shape: ---
{
  "mode": "inline-core",
  "operation_name": "VerifyPin",
  "ins_name": "INS_VERIFY_PIN",
  "timing_risk": "one-sentence description of the specific timing-vulnerable construct",
  "core_method": {
    "name": "coreVerifyPin",
    "code": "full java method source, verbatim-minus-declared-removals",
    "removed_lines": [{"start_line": 1, "end_line": 2, "category": "lifecycle guard", "description": "..."}],
    "field_mapping": ["referencePin"],
    "precondition": "referencePin loaded by wrapper before calling"
  },
  "wrapper_method": {
    "name": "wrapOperation",
    "code": "full java wrapper that unpacks the APDU, loads fields, and calls coreVerifyPin(...)",
    "data_layout_comment": "p1=... | p2=... | field(size) | ..."
  }
}
CORE METHOD rules (inline-core only):
- Keep ALL timing-sensitive logic verbatim: crypto API calls, comparisons on
  secret data, branches/loops/array-indexing depending on secret data, and the
  error throws that are part of that secret-dependent logic.
- You MAY remove lines ONLY in these categories, and EVERY removal must be
  declared in removed_lines: {{removal_categories}}
  ("lifecycle guard" = init/setup checks; "cache" = persistent lookup/store;
  "state mutation" = persistent counters/flags unrelated to timing; "secure
  channel" = APDU encryption/decryption wrapping; "key selection" = choosing
  among stored keys by id, replaced by the wrapper loading the one key;
  "logging" = audit/log writes.)
- Do NOT reformat or rename anything else: every line you don't declare as
  removed must appear in core_method.code EXACTLY as in the listing above (this
  is mechanically verified -- an undeclared change is rejected).
- Name it coreXxx; field_mapping lists the exact original field names it uses;
  precondition says what the wrapper sets up ("" if nothing).

--- If mode == "invoke-instance", produce this shape (NO core_method): ---
{
  "mode": "invoke-instance",
  "operation_name": "IntegerAdd",
  "ins_name": "INS_INTEGER_ADD",
  "timing_risk": "one-sentence description of the specific timing-vulnerable construct",
  "core_method": null,
  "wrapper_method": {
    "name": "wrapOperation",
    "code": "full java wrapper: build the ResourceManager + real receiver/argument objects from buffer using ONLY the construction-API constructors, then Mem.clear(); <recv>.<method>(<args>); lastCoreCost = Mem.instrCost; then serialize via a real public method (e.g. toByteArray) and return the size",
    "data_layout_comment": "p1=operand_len | p2=0x00 | operandA(p1) | operandB(p1) ..."
  }
}
WRAPPER rules (invoke-instance):
- Build every object with a constructor listed in the construction API; never
  invent one. Allocate a ResourceManager first if the constructors need it.
- Load operand bytes from `buffer` via the real deserialization method shown in
  the API (e.g. `fromByteArray`, or a `byte[]`-taking constructor). Read sizes
  from P1/P2 or a length prefix; document it in data_layout_comment.
- Call the REAL target method unchanged; do not access private fields.
- Serialize the result with a real public method (e.g. `toByteArray`).

WRAPPER rules (both modes):
- Entirely new code. data_layout_comment: one line describing the per-input-set
  layout. Every value the operation needs (keys, PINs, operands, seeds, config)
  must appear there as explicit fuzzable input -- nothing implicit.
