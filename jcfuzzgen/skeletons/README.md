# Fuzzing Skeletons

Code-generation templates for differential timing-leakage fuzzing of Java Card applets using [diffuzz](https://github.com/isstac/diffuzz) (AFL++ via Kelinci).

## Files

### FuzzAppletSkeleton.java

On-card applet skeleton that performs **dual-invocation differential fuzzing**. A single APDU carries two input sets (A and B). The applet runs the target operation twice — once per input set — and returns both results. Timing differences between the two runs reveal potential side-channel leaks.

The applet has four layers:
1. **process()** — fixed dual-invocation framing (splits APDU, runs A then B, assembles response)
2. **dispatchOperation()** — routing table (one `case` per operation)
3. **wrapXxx()** — generated wrappers that unpack inputs and call core methods
4. **coreXxx()** — verbatim copies of the original applet's cryptographic methods

### FuzzDriverSkeleton.java

Host-side diffuzz driver that feeds the applet via a Java Card simulator (e.g., jCardSim). It reads a fuzz input file produced by AFL++, constructs a `CommandAPDU`, sends it to the simulator, and reports execution cost via Kelinci's `Mem`/`Kelinci` API.

## Fuzz Input Layout (Fixed-Offset Scheme)

The input file uses a **fixed-offset layout** so that every byte has a stable semantic role regardless of the actual data lengths. This is critical for AFL++ effectiveness — mutations at any position don't shift the meaning of other positions.

```
Offset  Size       Field
──────  ─────────  ─────────────────────────────
0       1          ins (instruction byte)
1       1          p1_A
2       1          p2_A
3       1          len_A (clamped to MAX_DATA)
4       MAX_DATA   data_A slot (only first len_A bytes used)
4+MD    1          p1_B
5+MD    1          p2_B
6+MD    1          len_B (clamped to MAX_DATA)
7+MD    MAX_DATA   data_B slot (only first len_B bytes used)

Total: 7 + 2*MAX_DATA bytes  (MD = MAX_DATA)
```

`MAX_DATA` is a compile-time constant set per target applet (e.g., 32 or 64).

### Why fixed-offset?

- **Stable byte positions.** `data_B` always starts at the same file offset regardless of `len_A`. AFL++ can independently mutate each slot.
- **Safe length mutations.** Flipping bits in `len_A` only changes how many bytes of the fixed slot are *used* — nothing shifts.
- **Different lengths are natural.** `len_A=5` with `len_B=20` works — each slot has its own independent length byte.
- **Short inputs are fine.** If AFL++ produces a file shorter than the total size, missing bytes are treated as zero.

### APDU Wire Format

The driver translates the fixed-offset layout into the applet's CDATA framing:

```
CDATA = [size_A(2) | p1_A | p2_A | data_A(len_A) | p1_B | p2_B | data_B(len_B)]
```

This is wrapped in a `CommandAPDU` with `CLA=0xB1`, the fuzzed `ins` byte, and `P1=P2=0x00`.

## Code Generation

Both skeletons contain `{{GENERATED: ...}}` markers where LLM-extracted code is inserted for a specific target applet. The extraction process is described in `llm_extraction_prompt.md`.

**Driver-specific generated sections:**
- `MAX_DATA` — sized to the target operation's expected data
- `APPLET_AID` — AID of the fuzzing applet on the simulator
- Simulator initialization (install + select applet)
- `transmit()` — sends CommandAPDU to the simulator
