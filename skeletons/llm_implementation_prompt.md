# Prompt: Generate JCSmartFuzz Timing Side-Channel Fuzzing Drivers for a Java Card Applet

## Task

You are given the source code of a Java Card applet. Your job is to:
1. Identify the best candidate methods for timing side-channel fuzzing.
2. Implement a fuzzing applet (`XxxFuzzApplet.java`) and one driver per operation (`FuzzDriverYyy.java`) following the JCSmartFuzz skeleton architecture.

All output files go into the same package directory as the original applet. The original applet source files must **not be modified**.

---

## Selection Criteria: Which Methods to Target

**Target custom crypto/security implementations only.** Do NOT target methods that are thin wrappers around JavaCard API calls (e.g. a method whose only timing-sensitive line is `signature.sign(...)` or `cipher.doFinal(...)`).

**Good targets** have at least one of:
- **Data-dependent loop bounds** — a loop whose iteration count depends on a secret or fuzz input (e.g. `for (short i=0; i<key_length; i++)`).
- **Early-exit comparisons** — byte-by-byte comparison that returns as soon as a mismatch is found (e.g. custom MAC verification, PIN check in hand-written code).
- **Secret-dependent branching** — an `if`/`switch` whose outcome is determined by secret data (e.g. `if ((index & 0x80) != 0x80)` picking a hardened vs normal derivation path).
- **Variable-time arithmetic** — custom big-integer operations with early exit (e.g. `lessThan()`, `add_carry()` with conditional subtraction).
- **Variable-length encoding of secret-derived data** — output whose byte length leaks information about internal values (e.g. DER-encoded ECDSA signatures).

**Avoid** methods that only call opaque JavaCard API crypto primitives with no surrounding custom branching or looping logic.

Select **2–4 operations**. Prefer operations that cover different categories of timing risk.

---

## Architecture

Follow the 4-layer pattern from `FuzzAppletSkeleton.java`:

```
Layer 1 — process()           Fixed dual-invocation framing (copy verbatim from skeleton, never change)
Layer 2 — dispatchOperation() Routing switch; one case per operation
Layer 3 — wrapXxx()           NEW code: unpacks APDU data, sets up state, calls coreXxx()
Layer 4 — coreXxx()           VERBATIM copy of timing-sensitive code from the original applet
```

**Dual-invocation**: A single APDU carries two independent input sets (A and B). The applet runs the operation twice and reports `Kelinci.addCost(|costA - costB|)`. **No response is sent back to the driver.** The driver ignores the APDU response entirely.

**Timing measurement** around each core call (in the wrapper):
```java
Mem.clear();
coreXxx(...);
lastCoreCost = Mem.instrCost;
```

---

## APDU Framing (Layer 1 — copy verbatim from FuzzAppletSkeleton.java)

```
CLA: FUZZ_CLA (0xB1)
INS: operation code
CDATA: [size_A(2) | p1_A(1) | p2_A(1) | data_A(size_A-2) | p1_B(1) | p2_B(1) | data_B(remaining)]
```

Layer 1 parses this framing, runs each input set through `dispatchOperation()`, and calls `Kelinci.addCost`. Do not modify it.

---

## Fuzz Input File Layout (driver side — copy structure from FuzzDriverSkeleton.java)

```
Offset   Size       Field
──────   ─────────  ──────────────────
0        1          p1_A
1        1          p2_A
2        1          len_A
3        MAX_DATA   data_A
3+MD     1          p1_B
4+MD     1          p2_B
5+MD     1          len_B
6+MD     MAX_DATA   data_B
Total: 6 + 2*MAX_DATA bytes
```

`MAX_DATA` is the maximum number of meaningful data bytes for the operation. Short inputs are zero-padded.

---

## Rules for `coreXxx()` Methods

1. **Verbatim copy** of the timing-sensitive code from the original applet. The body must match the original line-for-line except for the removals listed below.

2. **Allowed removals** (must be listed in the Javadoc annotation):
   - Lifecycle guards: `if (!isInitialized) throw ...`, `if (!pin.isValidated()) throw ...`
   - Caching / persistent storage: object manager lookups, `createObject`, cache reads/writes
   - State mutations unrelated to timing: bitmask updates, audit log writes
   - Secure channel wrapping / APDU decryption
   - Key-selection dispatch (replaced by a single wrapper-supplied key)
   - Output signing or formatting unrelated to the timed operation

3. **Must keep**:
   - All crypto calls (HMAC, ECDH, hash, cipher, big-integer arithmetic)
   - All comparisons (`Util.arrayCompare`, `lessThan`, `equalZero`)
   - All branching and looping on secret or fuzz-input data
   - Variable-length output encoding (DER, VarInt)

4. Each `coreXxx()` must have a Javadoc block:
   ```java
   /**
    * SOURCE:           OriginalFile.java, methodName(), lines X-Y
    * TIMING RISK:      <one sentence per risk category>
    * ALLOWED REMOVALS: <list each removed line/block and its category>
    * FIELD MAPPING:    <original field name> → <fuzz applet field name>
    * PRECONDITION:     <what the wrapper sets up before calling>
    */
   ```

---

## Rules for `wrapXxx()` Methods

`wrapXxx()` is **new code** — not from the original applet. It must:
1. Read `P1` and `P2` from `buffer[ISO7816.OFFSET_P1]` / `buffer[ISO7816.OFFSET_P2]`.
2. Validate and clamp lengths.
3. Copy fuzz input data from `fuzzBuffer` into working buffers / instance fields.
4. For operations with a **fixed secret** (key, PIN, seed): load the hardcoded constant into the relevant field. The fuzzer varies the *other* side (the guess, the hash, the derivation index).
5. Measure:
   ```java
   Mem.clear();
   coreXxx(...);
   lastCoreCost = Mem.instrCost;
   ```
6. Return `void` — no output is written; the driver ignores the APDU response.

---

## Instance Fields

Declare only fields actually referenced by `coreXxx()` methods, using **the same names as in the original applet** so that core method bodies are true verbatim copies.

If static helper classes require `init(byte[] tmp)`, call them once in the constructor. Multiple helper classes may safely share the same transient buffer as scratch space since JavaCard is single-threaded.

---

## Fixed Secrets

When a core method operates on a secret value (private key, PIN, HMAC key, seed), hardcode it in the fuzz applet as a `private final static byte[]` constant. Use a well-known test vector where available. The fuzzer then varies only the non-secret side (the input that would come from a client).

---

## Driver Files

One driver per operation. Each driver is a fill-in of `FuzzDriverSkeleton.java` with:
- `FUZZ_INS` set to the operation's INS byte
- `MAX_DATA` set to the maximum meaningful data size
- The fuzz applet class imported and installed via jCardSim
- `simulator.transmitCommand(commandAPDU)` — **no response processing**

---

## Constraints Checklist

Before outputting, verify:
- [ ] No original applet file is modified
- [ ] Every `coreXxx()` body matches the original at the stated line range (only ALLOWED REMOVALS differ)
- [ ] `Kelinci.addCost(Math.abs(costA - costB))` is called exactly once in `process()`
- [ ] `apdu.setOutgoingAndSend()` is NOT called (no response sent)
- [ ] Each driver's `main()` does not read or process the `ResponseAPDU`
- [ ] `MAX_DATA` covers the full meaningful input for the operation
- [ ] Fixed secrets are `private final static byte[]` constants in the fuzz applet
- [ ] Static helper classes that require `init()` are initialized in the constructor
- [ ] All instance field names match the original applet so core methods are verbatim

---

## How to Distinguish Good vs Bad Targets

**Good** — custom loop with data-dependent bound:
```java
for (short i = 0; i < key_length; i++) {   // key_length iterations — leaks key length
    data[i] = (byte)(key[key_offset + i] ^ 0x36);
}
```

**Good** — custom early-exit comparison:
```java
for (short i = 0; i < size; i++) {
    if (x[offsetx+i] != y[offsety+i])
        return (x[offsetx+i] & 0xFF) < (y[offsety+i] & 0xFF); // exits at first differing byte
}
```

**Good** — secret-dependent branch:
```java
if ((index & 0x80) != 0x80) {   // MSB of index determines which code path runs
    // normal child: ECDH + HMAC with public key
} else {
    // hardened child: HMAC with private key directly
}
```

**Bad** — thin JavaCard API wrapper (no custom logic):
```java
sigECDSA.init(key, Signature.MODE_SIGN);
short len = sigECDSA.sign(buffer, offset, length, buffer, 0);
```
All timing is inside the opaque `sign()` call. Nothing to instrument.

---

## Output Format

Produce:

1. **Operation table** (fill before writing code):

| # | Operation | Source file:method:lines | INS | MAX_DATA | P1 | P2 | data layout | Timing risk |
|---|-----------|--------------------------|-----|----------|----|----|-------------|-------------|

2. **`XxxFuzzApplet.java`** — full implementation.

3. **`FuzzDriverOp1.java`**, **`FuzzDriverOp2.java`**, … — one per operation.

---

## Input Required

Provide:
1. Full source of the target applet (all `.java` files, or file paths if available in context).
2. Package name and directory.
3. Any operations to explicitly include or exclude.
