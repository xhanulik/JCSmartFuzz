# drivergen — FuzzDriver Generator

Generates `FuzzDriverXxx.java` files from a fuzzing applet that conforms to
`FuzzAppletSkeleton.java` (`jcfuzzgen/skeletons/`).

After creating a fuzzing applet (manually or with the LLM prompts in
`jcfuzzgen/skeletons/`), run this script instead of writing each driver by hand.

## Requirements

Python 3.10+ (uses `int | None` union syntax in type hints).

## Usage

```
python generate_drivers.py --applet PATH [--output-dir DIR] [--aid STRING]
```

| Argument | Description |
|----------|-------------|
| `--applet PATH` | Path to the `*FuzzApplet.java` source file **(required)** |
| `--output-dir DIR` | Where to write generated files (default: same directory as the applet) |
| `--aid STRING` | AID string for jCardSim (default: class name minus `"Applet"` suffix) |

## Example

```
python generate_drivers.py \
    --applet ../SatochipApplet/src/org/satochip/applet/SatochipFuzzApplet.java \
    --output-dir ../SatochipApplet/src/org/satochip/applet/
```

Expected output:
```
Parsed applet : SatochipFuzzApplet  (package org.satochip.applet)
FUZZ_CLA      : 0xb1  AID: "SatochipFuzz"
Operations found:
  INS_BIP32_DERIVE       0x01  wrapBIP32Derive           MAX_DATA=4
  INS_HMAC_SHA160        0x02  wrapHmacSha160            MAX_DATA=64
  INS_HMAC_SHA512        0x03  wrapHmacSha512            MAX_DATA=64
Generated:
  FuzzDriverBIP32Derive.java               (14 bytes per fuzz input)
  FuzzDriverHmacSha160.java                (134 bytes per fuzz input)
  FuzzDriverHmacSha512.java                (134 bytes per fuzz input)
```

## What the Script Parses

The applet source is parsed for:

- **`FUZZ_CLA`** constant — embedded in each driver header
- **`INS_*` byte constants** — one driver is generated per constant
- **`dispatchOperation()` switch** — maps each `INS_*` name to its wrapper method
- **`MAX_DATA`** per wrapper — searched first in the wrapper's Javadoc comment
  (`MAX_DATA = N`), then in the `if (dataLen < (short) N)` guard inside the body

## How Driver Class Names Are Derived

The `wrap` prefix is stripped from the wrapper method name:

| Wrapper method | Generated driver class |
|----------------|------------------------|
| `wrapBIP32Derive` | `FuzzDriverBIP32Derive` |
| `wrapHmacSha160` | `FuzzDriverHmacSha160` |
| `wrapVerifyPin` | `FuzzDriverVerifyPin` |

## Conformance Requirements

The input applet must follow `FuzzAppletSkeleton.java`:

1. Declare INS constants as `private final static byte INS_XXX = (byte) 0xNN;`
2. Route operations in a `dispatchOperation()` switch: `case INS_XXX: wrapXxx(...)`
3. Document each `wrapXxx()` with either:
   - A Javadoc line containing `MAX_DATA = N`, **or**
   - A guard `if (dataLen < (short) N)` in the method body

## Fuzz Input Layout (reminder)

Each generated driver uses the fixed-offset scheme from `FuzzDriverSkeleton.java`:

```
Offset      Size        Field
──────      ─────────   ──────────────────
0           1           p1_A
1           1           p2_A
2           1           len_A  (clamped to MAX_DATA by driver)
3           MAX_DATA    data_A slot
3+MAX_DATA  1           p1_B
4+MAX_DATA  1           p2_B
5+MAX_DATA  1           len_B
6+MAX_DATA  MAX_DATA    data_B slot
Total: 6 + 2 × MAX_DATA bytes
```
