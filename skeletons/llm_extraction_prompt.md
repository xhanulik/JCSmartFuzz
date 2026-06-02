# LLM Prompt: Extract Timing-Sensitive Operations from a Java Card Applet for Differential Fuzzing

You are given the full source code of a Java Card applet. Your task is to identify operations that handle **private or secret data** and may be vulnerable to **timing side-channel attacks**, then extract them into **wrapper + core method pairs** that plug into a pre-built differential fuzzing applet scaffold.

---

## INPUT

The complete source code of the applet is provided below between the `<applet-source>` tags.

<applet-source>
{{PASTE THE FULL APPLET SOURCE CODE HERE}}
</applet-source>

---

## YOUR TASK

### Step 1 — Identify Timing-Sensitive Operations

Read the applet's `process()` method and its INS dispatch logic. For every INS handler, analyze whether it processes **secret or private data** in a way that may exhibit **data-dependent timing behavior**. Record each candidate with:

- The INS byte constant and its name
- The handler method name
- The line range of the handler method in the source
- A brief explanation of **why** this operation is timing-sensitive (what secret data it touches and what timing-variable construct it uses)

#### What is timing-sensitive/secret data

Use the following data description as definition of secret data in the code:

- symmetric/asymmetric keys
- PIN value
- intermediate crypto results

#### What makes an operation timing-sensitive

An operation is a candidate if it processes secret/private data **and** contains one or more of these constructs:

- **Secret-dependent branching**: `if`/`switch`/`?:` statements where the condition depends on secret data. Different branches may take different amounts of time.
- **Secret-dependent loop bounds**: Loops whose iteration count depends on secret data (e.g., scanning for a zero byte in a key, finding the length of a variable-length secret).
- **Early-exit comparisons**: Byte-by-byte comparisons (PIN checks, MAC verification, signature verification) that return as soon as a mismatch is found — leaking the position of the first difference.
- **Variable-time cryptographic operations**: Calls to crypto APIs whose execution time depends on the input value (e.g., modular exponentiation, scalar multiplication with non-constant-time implementations, BigInteger operations).
- **Table lookups indexed by secrets**: Array accesses where the index is derived from secret data — may leak via cache timing even in software simulators.
- **Variable-length encoding of secrets**: Operations that encode/decode secrets in formats where the output length depends on the secret value (e.g., DER encoding of ECDSA signatures, ASN.1 encoding of keys).
- **Conditional error handling on secret values**: Different exception types or error paths triggered by properties of the secret (e.g., "key is zero" vs "key is valid").
- **Data-dependent memory operations**: `arrayCopy` or `arrayFill` calls where the length or offset depends on a secret value.
- **Non-uniform access to the memory**: Reading from memory/arrays unevenly for different indexes

#### What to include

- **Custom security/cryptographic implementations**
- **Cryptographic operations**: signing, hashing, encryption/decryption, key derivation, key agreement, MAC computation — these inherently process secrets and often use variable-time algorithms.
- **Authentication handlers**: PIN verification, password checks, challenge-response protocols — these compare user input against stored secrets.
- **Key management**: key import, key generation, key derivation — these handle raw key material that may be processed in variable time.
- **Access control decisions**: operations that branch based on secret tokens, session keys, or privilege levels.
- **Any data processing** that touches secret fields (keys, PINs, seeds, internal state derived from secrets) and uses conditional logic, loops, or comparisons on that data.

#### What to skip

- Methods based only on standard Java Card API without custom security/cryptographic implementations
- Operations that only read/write **non-secret** metadata (labels, version info, free memory counters).
- Operations that return **public** information with no secret-dependent control flow.
- Operations where all code paths are demonstrably constant-time (no branching/looping on secrets, use of `Util.arrayCompare` is still a candidate since the JC implementation may not be constant-time).

### Step 2 — For Each Operation, Produce a Core Method

The core method contains the **timing-sensitive code copied verbatim** from the original handler. It must include all code where execution time could depend on the secret input. Follow these rules:

#### What to KEEP (copy verbatim, preserving original formatting):

- All calls to Java Card cryptographic APIs (`javacard.security.*`, `javacardx.crypto.*`): `Signature.sign()`, `Signature.signPreComputedHash()`, `Signature.verify()`, `MessageDigest.doFinal()`, `MessageDigest.update()`, `Cipher.init()`, `Cipher.doFinal()`, `Cipher.update()`, `KeyAgreement.init()`, `KeyAgreement.generateSecret()`, `RandomData.generateData()`, `OwnerPIN.check()`, and any other API calls that process secret data.
- All comparison and validation logic that operates on secret data: byte-by-byte comparisons, `Util.arrayCompare()`, equality checks on key material, PIN comparisons, MAC verification, signature verification result handling.
- All branching constructs (`if`, `switch`, `?:`) where the condition depends on secret data or on results derived from secret data.
- All loops whose behavior (iteration count, early termination) depends on secret data.
- All data manipulation that feeds into or processes the output of secret-dependent operations: `Util.arrayCopyNonAtomic()`, `Util.arrayFillNonAtomic()`, `Util.arrayCompare()`, `Util.getShort()`, `Util.setShort()`, direct array indexing, offset arithmetic.
- All mathematical operations on key material or cryptographic values: modular arithmetic, comparisons against group orders, overflow checks, zero-value checks.
- All array accesses where the index is derived from secret data.
- Error throws that are part of the secret-dependent logic (e.g., throwing when a PIN doesn't match, when a derived key is invalid, when a signature verification fails).

#### What to REMOVE (document each removal in the ALLOWED REMOVALS annotation):

These are **categories** of code to strip. Apply them to whatever forms they take in the specific applet:

- **Initialization / lifecycle guards**: Any code that checks whether the applet has been set up, whether a key has been imported, whether a seed has been loaded, whether a secure channel has been established, or any similar precondition that gates access to the operation. Remove the guard and its error throw. **Exception**: if the guard itself branches on secret data (e.g., checking whether a secret key is initialized by testing its bytes), keep it and annotate it.
- **Caching / persistent storage operations**: Any code that stores or retrieves intermediate results from persistent memory, object managers, or caches. This includes cache lookups, cache insertions, cache evictions, and any encryption/decryption of cached objects. Remove the cache logic; the core always recomputes from scratch.
- **Persistent state mutations**: Any code that writes to persistent applet state: setting flags (`initialized = true`), storing keys in persistent key objects, updating counters, writing to transaction logs, or updating cumulative values. The fuzzing applet is stateless. **Exception**: if the state mutation is itself timing-sensitive (e.g., conditional counter increment based on a secret comparison), keep it and annotate it.
- **Secure channel wrapping**: Any code that encrypts/decrypts the APDU payload as part of a secure channel protocol. The fuzzing applet receives plaintext.
- **Key-selection dispatch**: Any code that selects between multiple stored keys based on an index or identifier (e.g., `if (keyId == SPECIAL) use keyA else use keys[keyId]`). Remove the selection logic entirely. The wrapper will load the single correct key into the field the core references.
- **Logging / audit trail**: Any code that logs operations, writes audit records, or updates transaction counters for non-security purposes.

#### Field naming rule:

The core method must reference **the same instance field names** as the original applet source. Whatever the original code calls its `Signature`, `Cipher`, `MessageDigest`, `KeyAgreement`, `ECPrivateKey`, `AESKey`, `OwnerPIN`, `byte[]` working buffer, etc. — use that exact name. The fuzzing applet scaffold will declare fields with matching names.

If the original code references a field whose access falls entirely within a REMOVAL category (e.g., a cache manager, a log buffer), delete the line that accesses it. Do not replace it with anything.

#### Core method signature:

- **Name**: `coreXxx` where `Xxx` is a descriptive CamelCase name derived from the operation (e.g., `coreSignHash`, `coreVerifyPin`, `coreDeriveKey`, `coreCheckMac`, `coreDecryptData`).
- **Parameters**: Only values the core cannot obtain from instance fields or from `buffer`. Typical parameters: `byte[] buffer`, iteration counts, data lengths, offsets, mode flags. Keep the parameter list minimal.
- **Return type**: `short` (output size written to `buffer[0..]`) or `void` (if the core writes results to a working buffer and the wrapper handles output formatting).

#### Core method annotation (Javadoc):

```java
/**
 * SOURCE: <FileName>.java, <methodName>(), lines <start>-<end>
 * TIMING RISK: <brief description of the timing-sensitive construct>
 * ALLOWED REMOVALS:
 *   - lines <N>-<M>: <category> — <brief description>
 *   - lines <X>: <category> — <brief description>
 * FIELD MAPPING: <field1>, <field2>, ... (all same names as original)
 * PRECONDITION: <what the wrapper must set up before calling> (if any)
 */
```

Where `<category>` is one of: `lifecycle guard`, `cache`, `state mutation`, `secure channel`, `key selection`, `logging`.

The TIMING RISK line must identify the specific construct: e.g., "early-exit byte comparison on PIN data", "secret-dependent branch on key validity", "variable-time ECDSA signing with DER-encoded output length depending on signature value".

### Step 3 — For Each Operation, Produce a Wrapper Method

The wrapper method is **entirely new code** (nothing from the original). It bridges the APDU data layout to the context the core method expects.

The wrapper:

1. **Reads parameters** from the APDU buffer:
   - `buffer[ISO7816.OFFSET_P1]`, `buffer[ISO7816.OFFSET_P2]` for per-operation mode/size parameters.
   - `buffer[ISO7816.OFFSET_CDATA..]` for operation-specific data (keys, PINs, plaintext, hashes, etc.).

2. **Validates** input sizes and parameter ranges. Throws `ISOException` on invalid input.

3. **Populates context** that the core expects:
   - Loads key material from the APDU data into the appropriately-named instance fields. For asymmetric keys: call `.setS()` (EC private) or `.setW()` (EC public), then `.init()` on `KeyAgreement`/`Signature` objects. For symmetric keys: call `.setKey()` on `AESKey`/`DESKey` objects.
   - For PIN/password operations: load the reference PIN and the guess PIN into the positions the core expects.
   - If the core reads from a working buffer (e.g., `recvBuffer`) at specific offsets, copy the relevant APDU data into those positions.
   - If the core reads data from `buffer` at `ISO7816.OFFSET_CDATA`, shift the data within `buffer` so the core finds it at the expected position (after the wrapper has consumed the key/secret bytes from the front of CDATA).

4. **Calls the core method**.

5. **Formats the output** in `buffer[0..]` and returns the output size as `short`.

#### Wrapper method signature:

```java
private short wrapXxx(APDU apdu, byte[] buffer)
```

#### Wrapper header comment (documents the APDU data layout):

```java
// --- INS 0xNN: OPERATION_NAME ---
// Per-input-set: [p1=<meaning> | p2=<meaning> | <field1>(size) | <field2>(size) | ...]
// Result: [<output_field1>(size) | <output_field2>(size) | ...]
```

This documents the **per-input-set data layout**: what a fuzzer must provide in each input set's `operation_data` blob. Every piece of data that the original applet read from persistent card state (stored keys, PINs, seeds, configuration) must now appear as an explicit field in this layout.

### Step 4 — Produce Supporting Declarations

List all instance fields and constants that the core methods reference.

**Fields**: For each, give the type, the original field name, and how to initialize it in the constructor. Group them:
- Cryptographic engine objects (`Signature`, `Cipher`, `MessageDigest`, `KeyAgreement`, `RandomData`)
- Key objects (`ECPrivateKey`, `ECPublicKey`, `AESKey`, `DESKey`, etc.)
- Authentication objects (`OwnerPIN`, or byte arrays holding reference PINs/passwords)
- Working buffers (`byte[]` arrays used as scratch space)

**Constants**: Copy each constant declaration from the original source. Annotate with the original file and line number.

### Step 5 — Produce the Dispatcher Entries

Output the `case` entries for the dispatcher `switch` statement:

```java
case INS_XXX: return wrapXxx(apdu, buffer);
```

---

## OUTPUT FORMAT

Structure your output exactly as follows:

```
## 1. Operations Found

| # | INS  | Name | Original Method | Lines | Timing Risk |
|---|------|------|-----------------|-------|-------------|
| 1 | 0xNN | ...  | ...             | ...   | ...         |

## 2. Field Declarations

<java code block: field declarations with original names + constructor initialization lines>

## 3. Constants

<java code block: constant declarations, each annotated with source file and line>

## 4. Dispatcher Entries

<java code block: case statements for dispatchOperation()>

## 5. Wrapper + Core Pairs

### Operation 1: <NAME>

#### Wrapper: wrapXxx()
<complete java method with header comment>

#### Core: coreXxx()
<complete java method with Javadoc annotation>

### Operation 2: <NAME>
...

## 6. Notes

<any multi-APDU stateful operations, helper class dependencies, or caveats>
```

---

## EXAMPLES

These examples show the expected pattern for three cases: a **timing-sensitive comparison**, a **crypto operation**, and a **secret-dependent branch**. The examples use fictional names — adapt the pattern to the actual applet you are given.

### Example A: Early-Exit PIN Comparison

#### Wrapper

```java
// --- INS 0x20: VERIFY_PIN ---
// Per-input-set: [p1=pin_length(1-8) | p2=0x00 | reference_pin(8) | guess_pin(8)]
// Result: [match_result(1)]
private short wrapVerifyPin(APDU apdu, byte[] buffer) {
    byte pinLen = buffer[ISO7816.OFFSET_P1];
    if (pinLen < 1 || pinLen > MAX_PIN_LENGTH)
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    short off = ISO7816.OFFSET_CDATA;
    // Load reference PIN into working buffer where core expects it
    Util.arrayCopyNonAtomic(buffer, off, pinBuffer, (short) 0, MAX_PIN_LENGTH);
    off += MAX_PIN_LENGTH;
    // Shift guess to OFFSET_CDATA for core
    Util.arrayCopyNonAtomic(buffer, off, buffer, ISO7816.OFFSET_CDATA, MAX_PIN_LENGTH);

    byte result = coreVerifyPin(buffer, pinLen);
    buffer[0] = result;
    return (short) 1;
}
```

#### Core

```java
/**
 * SOURCE: OriginalApplet.java, verifyUserPIN(), lines 200-215
 * TIMING RISK: early-exit byte comparison — loop returns false at first mismatch,
 *   leaking the position of the first incorrect PIN byte via timing
 * ALLOWED REMOVALS:
 *   - lines 198-199: lifecycle guard — applet initialization check
 *   - lines 216-218: state mutation — PIN retry counter update
 * FIELD MAPPING: pinBuffer (same name as original)
 * PRECONDITION: pinBuffer[0..7] loaded with reference PIN by wrapper
 */
private byte coreVerifyPin(byte[] buffer, byte pinLen) {
    // VERBATIM from OriginalApplet.java lines 205-213:
    for (byte i = 0; i < pinLen; i++) {
        if (buffer[(short)(ISO7816.OFFSET_CDATA + i)] != pinBuffer[i]) {
            return (byte) 0x00;
        }
    }
    return (byte) 0x01;
}
```

### Example B: Variable-Time Crypto Operation

#### Wrapper

```java
// --- INS 0x30: SIGN_HASH ---
// Per-input-set: [p1=0x00 | p2=0x00 | privkey(32) | hash(32)]
// Result: [DER_signature(variable, up to ~72 bytes)]
private short wrapSignHash(APDU apdu, byte[] buffer) {
    short off = ISO7816.OFFSET_CDATA;
    // Load key from APDU — wrapper-only
    signingKey.setS(buffer, off, KEY_SIZE);
    off += KEY_SIZE;
    // Shift hash to OFFSET_CDATA so core reads it at the position the original expects
    Util.arrayCopyNonAtomic(buffer, off, buffer, ISO7816.OFFSET_CDATA, (short) 32);
    // Initialize signature engine — wrapper-only (original had key-selection dispatch here)
    ecdsaSig.init(signingKey, Signature.MODE_SIGN);
    return coreSignHash(buffer);
}
```

#### Core

```java
/**
 * SOURCE: OriginalApplet.java, handleSignTransaction(), line 850
 * TIMING RISK: ECDSA signing — scalar multiplication is variable-time in many
 *   Java Card implementations; DER output length depends on signature value
 * ALLOWED REMOVALS: none (single statement extracted)
 * FIELD MAPPING: ecdsaSig (same name as original)
 * PRECONDITION: ecdsaSig.init() called by wrapper with the correct key
 */
private short coreSignHash(byte[] buffer) {
    // VERBATIM from OriginalApplet.java line 850:
    short sign_size = ecdsaSig.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, (short) 32, buffer, (short) 0);
    return sign_size;
}
```

### Example C: Secret-Dependent Branching

#### Wrapper

```java
// --- INS 0x40: PROCESS_TOKEN ---
// Per-input-set: [p1=token_type | p2=0x00 | secret_token(16) | payload(32)]
// Result: [processed_output(32)]
private short wrapProcessToken(APDU apdu, byte[] buffer) {
    byte tokenType = buffer[ISO7816.OFFSET_P1];
    short off = ISO7816.OFFSET_CDATA;
    Util.arrayCopyNonAtomic(buffer, off, tokenBuffer, (short) 0, TOKEN_SIZE);
    off += TOKEN_SIZE;
    Util.arrayCopyNonAtomic(buffer, off, buffer, ISO7816.OFFSET_CDATA, PAYLOAD_SIZE);
    return coreProcessToken(buffer, tokenType);
}
```

#### Core

```java
/**
 * SOURCE: OriginalApplet.java, processSecureToken(), lines 300-340
 * TIMING RISK: secret-dependent branch — different processing paths chosen
 *   based on the high bit of tokenBuffer[0], leaking 1 bit of the token
 * ALLOWED REMOVALS:
 *   - lines 298-299: lifecycle guard — secure channel check
 *   - lines 335-340: state mutation — session counter increment
 * FIELD MAPPING: tokenBuffer, aesEngine (same names as original)
 * PRECONDITION: tokenBuffer[0..15] loaded with secret token by wrapper
 */
private short coreProcessToken(byte[] buffer, byte tokenType) {
    // VERBATIM from OriginalApplet.java lines 305-332:
    if ((tokenBuffer[0] & (byte) 0x80) != 0) {
        aesEngine.init(sessionKey, Cipher.MODE_ENCRYPT);
        return aesEngine.doFinal(buffer, ISO7816.OFFSET_CDATA, PAYLOAD_SIZE, buffer, (short) 0);
    } else {
        aesEngine.init(sessionKey, Cipher.MODE_DECRYPT);
        return aesEngine.doFinal(buffer, ISO7816.OFFSET_CDATA, PAYLOAD_SIZE, buffer, (short) 0);
    }
}
```

---

## IMPORTANT RULES

1. **Never mix wrapper and core logic in one method.** The wrapper handles ALL data unpacking, key/secret loading, and output formatting. The core handles ONLY the timing-sensitive algorithm.

2. **Core code must be diffable against the original.** Preserve the original's formatting, spacing, comments, and variable names. Do not reformat, rename variables, or "clean up" the code. The only changes allowed are the removals listed in the annotation.

3. **Every removal must be documented.** If you delete a line from the original when producing the core, it MUST appear in the ALLOWED REMOVALS list with its line number(s) and a reason category (`lifecycle guard` / `cache` / `state mutation` / `secure channel` / `key selection` / `logging`).

4. **Use original field names in the core.** Whatever the original applet calls its crypto objects, working buffers, PIN objects, etc. — use those exact names. The fuzzing applet scaffold will declare fields with matching names based on your Field Declarations output.

5. **The wrapper's data layout must externalize ALL card state.** Every piece of data that the original handler reads from persistent card state (stored keys, PINs, seeds, chain codes, counters, configuration flags) must be supplied as an explicit field in the wrapper's per-input-set data layout. Nothing can be implicit. This is critical: the fuzzer must control both the "secret" and the "public" input to detect timing differences.

6. **Every operation must have a TIMING RISK annotation.** The annotation must identify the specific timing-vulnerable construct — not just "uses crypto" but the precise mechanism (early-exit comparison, secret-dependent branch, variable-time algorithm, data-dependent loop bounds, etc.).

7. **Helper/utility classes** referenced by the original applet (custom HMAC, big-integer, curve parameter classes, protocol parsers, etc.) are assumed available in the same package. Reference them by their original names.

8. **Multi-APDU stateful operations** (e.g., operations that use INIT/PROCESS/FINALIZE phases across multiple APDUs) should be noted in section 6 (Notes) as requiring special handling — they cannot be dual-invoked in the standard fuzzing scaffold.

9. **When in doubt, keep more code in the core rather than less.** It is safer to include a borderline line in the core (and document it) than to accidentally omit a step that affects timing behavior. The removal whitelist exists specifically to make each omission explicit and auditable.

10. **Authentication operations are candidates, not removals.** Unlike a pure crypto-extraction prompt, PIN checks, password verification, and token validation are **primary targets** for timing analysis. Extract them as operations. Only remove authentication *guards* that gate access to a *different* operation (e.g., "must be authenticated before signing").
