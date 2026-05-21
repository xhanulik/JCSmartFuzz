# JCSmartFuzz: Generate Fuzzing Drivers for a Java Card Applet

Given the applet source below, produce `XxxFuzzApplet.java` and one `FuzzDriverOp.java` per operation.

## Select 2–4 operations with CUSTOM timing-sensitive logic:
- Data-dependent loop bounds (`for i < key_length`)
- Early-exit byte comparisons
- Secret-dependent branching (`if (msb & 0x80)`)
- Custom big-integer arithmetic with early exit

**Skip** methods that only call JavaCard API primitives (`signature.sign`, `cipher.doFinal`).

## Fuzz applet rules (follow `FuzzAppletSkeleton.java`):
- Layer 1 `process()`: copy verbatim from skeleton — runs operation twice (A and B), calls `Kelinci.addCost(|costA - costB|)`, sends **no response**
- Layer 3 `wrapXxx()`: new code — loads fuzz input + hardcoded secret into fields, then `Mem.clear(); coreXxx(); lastCoreCost = Mem.instrCost;`
- Layer 4 `coreXxx()`: **verbatim copy** from original; remove only: lifecycle guards, caching, state mutations, key-selection dispatch; keep all crypto, comparisons, branches on data
- Annotate each `coreXxx()` with `SOURCE`, `TIMING RISK`, `ALLOWED REMOVALS`, `FIELD MAPPING`, `PRECONDITION`
- Field names must match the original applet
- Hardcode fixed secrets as `private final static byte[]`; fuzzer varies the other side
- Static helpers needing `init(buf)`: call in constructor

## Driver rules (follow `FuzzDriverSkeleton.java`):
- One driver per operation; `FUZZ_INS` and `MAX_DATA` pinned per operation
- `simulator.transmitCommand(commandAPDU)` — **do not read or process the response**

## Do not modify any original applet file.

---

**Applet source:** *(paste here)*
**Package + directory:** *(paste here)*
