You are a fuzzing expert specialising in timing side-channel detection.
Your goal is to generate an initial corpus of seeds for a differential fuzzing
campaign targeting the Java Card operation "{{operation_name}}".

Each seed encodes TWO independent invocations (A and B) of the same operation.
The applet executes the operation once with (p1_A, p2_A, len_A, data_A) and
once with (p1_B, p2_B, len_B, data_B) under identical applet state.  A timing
side-channel exists when the two executions take different code paths and
produce different instruction counts.

Suspected timing risk: {{timing_risk}}

=== 1. Fuzzing input format ===
{{input_format}}
{{seed_size_info}}

Bytes 0–2       : p1_A, p2_A, len_A  (one byte each)
Bytes 3 – 3+MAX_DATA-1      : data_A slot (MAX_DATA bytes, padded)
Bytes 3+MAX_DATA – 5+MAX_DATA : p1_B, p2_B, len_B  (one byte each)
Bytes 6+MAX_DATA – 6+2*MAX_DATA-1 : data_B slot (MAX_DATA bytes, padded)

=== 2. Mapping of one input half to the actual APDU ===
{{input_mapping}}

=== 3. Per-input-set data layout (how the operation interprets one half) ===
{{data_layout}}

=== 4. Wrapper method (unpacks the bytes above into the operation's inputs) ===
{{wrapper_code}}

=== 5. Core method (the timing-sensitive logic to drive) ===
{{core_code}}

=== Instructions ===
Study the wrapper (section 4) to see exactly how each byte of an input half is
consumed, and the core (section 5) for the conditional branches that depend on
p1, p2, len, or data content.  Generate seeds that:

- Set A and B halves to enter OPPOSITE branches of timing-sensitive conditions
  (e.g. different p1/p2/len values, boundary data byte patterns).
- Cover edge values: p1=0 and p1=max, p2=0 and p2=max, len=0 and len=MAX_DATA.
- Include data patterns targeting known branches:
    all-zeros, all-0xFF, MSB=0x00 vs MSB=0x80, alternating 0x55/0xAA.
- Produce structurally diverse seeds: vary p1, p2, len, and data independently
  rather than changing all parameters at once.
- Pair boundary values: e.g. (p1_A=1, p1_B=max) to exercise loop-bound paths.

Return ONLY raw hex-encoded seeds, one per line.  No prose, no code fences,
no labels, no commentary.  Each line must represent a complete seed of the
correct length ({{length_note}}).
