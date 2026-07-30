#!/usr/bin/env python3
"""
generate_drivers.py — Generates FuzzDriver Java files from a FuzzApplet Java file.

The input applet must conform to FuzzAppletSkeleton.java (skeletons/).
It parses INS constants, the dispatch table, and per-wrapper MAX_DATA values,
then writes one FuzzDriverXxx.java per operation.

Usage:
    python generate_drivers.py --applet PATH [--output-dir DIR] [--aid STRING]
"""

import re
import sys
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

RE_PACKAGE       = re.compile(r'^\s*package\s+([\w.]+)\s*;', re.MULTILINE)
RE_CLASS         = re.compile(r'public\s+class\s+(\w+)\s+extends')
RE_FUZZ_CLA      = re.compile(r'\bFUZZ_CLA\s*=\s*\(byte\)\s*(0x[0-9A-Fa-f]+)')
RE_INS_CONST     = re.compile(
    r'private\s+final\s+static\s+byte\s+(INS_\w+)\s*=\s*\(byte\)\s*(0x[0-9A-Fa-f]+)'
)
RE_DISPATCH_CASE = re.compile(r'case\s+(INS_\w+)\s*:\s*(\w+)\s*\(')
RE_MAX_DATA_DOC  = re.compile(r'MAX_DATA\s*=\s*(\d+)')          # Javadoc comment
RE_MAX_DATA_GUARD = re.compile(r'dataLen\s*<\s*\(short\)\s*(\d+)')  # guard in body


# ---------------------------------------------------------------------------
# Source-level helpers
# ---------------------------------------------------------------------------

def extract_method_region(source: str, method_name: str) -> str:
    """
    Return the substring of *source* that contains the Javadoc comment (if
    present) plus the full body of the first method named *method_name*.
    Uses brace-depth tracking so nested braces are handled correctly.
    """
    # Find the method declaration (not a call site).  The pattern anchors to the
    # start of a line so that a call like "wrapFoo(..." inside a switch/if body
    # is never mistaken for the declaration.
    sig_pattern = re.compile(
        r'(/\*\*.*?\*/\s*)?'          # optional Javadoc block
        r'^[ \t]*'                    # line start (MULTILINE anchor)
        r'(?:(?:public|private|protected|static|final|synchronized|'
        r'abstract|native|default|void|short|byte|int|boolean|long)'
        r'[ \t\w\[\]<>,]*[ \t]+)+'   # one or more modifier/return-type tokens
        r'\b' + re.escape(method_name) + r'\b'
        r'\s*\(',
        re.MULTILINE | re.DOTALL
    )
    m = sig_pattern.search(source)
    if m is None:
        return ''

    # Walk forward from the match to find the opening brace
    pos = m.start()
    start = m.start()
    brace_start = source.find('{', m.end())
    if brace_start == -1:
        return ''

    # Track brace depth to find the closing brace
    depth = 0
    i = brace_start
    while i < len(source):
        ch = source[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    return source[start:]  # unterminated — return rest


def extract_javadoc_before(source: str, method_name: str) -> str:
    """Return the Javadoc comment immediately preceding *method_name*, if any."""
    pattern = re.compile(
        r'(/\*\*.*?\*/)\s*'
        r'(?:[\w\[\]<>,\s@]+\s+)'
        r'\b' + re.escape(method_name) + r'\b',
        re.DOTALL
    )
    m = pattern.search(source)
    return m.group(1) if m else ''


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_applet(source: str) -> dict:
    """
    Parse a *FuzzApplet.java source string that conforms to FuzzAppletSkeleton.
    Returns a dict with keys: package, class_name, fuzz_cla, operations.
    Each operation: {ins_name, ins_value, wrapper_name, max_data}.
    Raises ValueError on fatal parse errors.
    """
    # Package
    m = RE_PACKAGE.search(source)
    if not m:
        raise ValueError("No package declaration found.")
    package = m.group(1)

    # Class name
    m = RE_CLASS.search(source)
    if not m:
        raise ValueError("No public class extending Applet found.")
    class_name = m.group(1)

    # FUZZ_CLA
    m = RE_FUZZ_CLA.search(source)
    if not m:
        raise ValueError("FUZZ_CLA constant not found.")
    fuzz_cla = m.group(1).lower()

    # INS constants  {name: hex_string}
    ins_constants = {
        name: value.lower()
        for name, value in RE_INS_CONST.findall(source)
    }
    if not ins_constants:
        raise ValueError(
            "No INS_* byte constants found. "
            "Does the applet conform to FuzzAppletSkeleton?"
        )

    # Dispatch table  {ins_name: wrapper_method_name}
    dispatch_body = extract_method_region(source, 'dispatchOperation')
    if not dispatch_body:
        raise ValueError("dispatchOperation() method not found.")
    dispatch_map = {
        ins: wrapper
        for ins, wrapper in RE_DISPATCH_CASE.findall(dispatch_body)
    }

    # Build per-operation records
    operations = []
    for ins_name, ins_value in sorted(ins_constants.items(),
                                      key=lambda kv: int(kv[1], 16)):
        wrapper_name = dispatch_map.get(ins_name)
        if wrapper_name is None:
            print(f"  WARNING: {ins_name} has no dispatch entry — skipped.",
                  file=sys.stderr)
            continue

        # Determine MAX_DATA for this wrapper
        max_data = _find_max_data(source, wrapper_name)
        if max_data is None:
            print(
                f"  WARNING: MAX_DATA not found for {wrapper_name} "
                f"({ins_name}) — skipped.",
                file=sys.stderr
            )
            continue

        operations.append({
            'ins_name':    ins_name,
            'ins_value':   ins_value,
            'wrapper_name': wrapper_name,
            'max_data':    max_data,
        })

    return {
        'package':    package,
        'class_name': class_name,
        'fuzz_cla':   fuzz_cla,
        'operations': operations,
    }


def _find_max_data(source: str, wrapper_name: str) -> int | None:
    """
    Try two strategies to find MAX_DATA for a wrapper method:
      1. Javadoc comment containing "MAX_DATA = N"
      2. Guard `if (dataLen < (short) N)` inside the method body
    Returns the integer value, or None if not found.
    """
    # Strategy 1: Javadoc
    doc = extract_javadoc_before(source, wrapper_name)
    m = RE_MAX_DATA_DOC.search(doc)
    if m:
        return int(m.group(1))

    # Strategy 2: guard inside method body
    body = extract_method_region(source, wrapper_name)
    m = RE_MAX_DATA_GUARD.search(body)
    if m:
        return int(m.group(1))

    return None


# MAX_DATA sizes the fuzz input (6 + 2*MAX_DATA bytes) and the B-slot offset
# (3 + MAX_DATA). The driver and the seed generator MUST agree on it, so both
# resolve it through resolve_max_data() below with this one shared default.
DEFAULT_MAX_DATA = 64


def resolve_max_data(operation, default: int = DEFAULT_MAX_DATA) -> int:
    """MAX_DATA for one operation.json entry -- the single source of truth shared
    by assemble_harness (the driver's `MAX_DATA` constant) and the seed generator
    (the fuzz-input size). Uses the value declared in the operation's wrapper (a
    Javadoc ``MAX_DATA = N`` or a ``dataLen < (short) N`` guard) and falls back to
    *default* when none is declared, so the two sides can never diverge."""
    wrapper = operation.get("wrapper_method") or {}
    code, name = wrapper.get("code") or "", wrapper.get("name") or ""
    md = _find_max_data(code, name) if code and name else None
    return md if md is not None else default


# ---------------------------------------------------------------------------
# Driver file generation
# ---------------------------------------------------------------------------

DRIVER_TEMPLATE = """\
/*
 * {driver_class}: AFL++ / diffuzz driver for {applet_class} {ins_name} ({ins_value}).
 *
 * Generated by generate_drivers.py from {applet_file}
 * Target operation: {wrapper_name}
 *
 * Fuzz input file layout (fixed-offset scheme, AFL++-friendly):
 *   [p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA={max_data}) |
 *    p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA={max_data})]
 *   Total: {total_size} bytes
 */

package {package};

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import java.io.FileInputStream;
import java.io.IOException;

public class {driver_class} {{

    // Must match {applet_class}.FUZZ_CLA
    private static final byte FUZZ_CLA = (byte) {cla_hex};

    // INS byte for {wrapper_name} ({ins_name})
    private static final byte FUZZ_INS = (byte) {ins_hex};

    // Maximum operation data size for one input set
    private static final int MAX_DATA = {max_data};

    // Derived constants — do not modify
    private static final int SLOT_B_OFFSET    = 3 + MAX_DATA;
    private static final int TOTAL_INPUT_SIZE = 3 + MAX_DATA + 3 + MAX_DATA;

    public static void main(String[] args) {{
        if (args.length != 1) {{
            System.out.println("Expects file name as parameter");
            return;
        }}

        // Step 1: Read raw fuzz input into fixed-size buffer; short inputs are zero-padded.
        byte[] input = new byte[TOTAL_INPUT_SIZE];
        try (FileInputStream fis = new FileInputStream(args[0])) {{
            int bytesRead = 0;
            int r;
            while (bytesRead < TOTAL_INPUT_SIZE &&
                   (r = fis.read(input, bytesRead, TOTAL_INPUT_SIZE - bytesRead)) != -1) {{
                bytesRead += r;
            }}
        }} catch (IOException e) {{
            e.printStackTrace();
            return;
        }}

        // Step 2: Parse fixed-offset layout
        byte p1A  = input[0];
        byte p2A  = input[1];
        int  lenA = Math.min(input[2] & 0xFF, MAX_DATA);

        byte p1B  = input[SLOT_B_OFFSET];
        byte p2B  = input[SLOT_B_OFFSET + 1];
        int  lenB = Math.min(input[SLOT_B_OFFSET + 2] & 0xFF, MAX_DATA);

        // Step 3: Build CDATA in the applet's framing format
        // CDATA = [size_A(2) | p1_A | p2_A | data_A(lenA) | p1_B | p2_B | data_B(lenB)]
        int    sizeA    = 2 + lenA;
        int    cdataLen = 2 + sizeA + 2 + lenB;
        byte[] cdata    = new byte[cdataLen];
        int    off      = 0;

        cdata[off++] = (byte)((sizeA >> 8) & 0xFF);
        cdata[off++] = (byte)(sizeA & 0xFF);
        cdata[off++] = p1A;
        cdata[off++] = p2A;
        System.arraycopy(input, 3, cdata, off, lenA);
        off += lenA;

        cdata[off++] = p1B;
        cdata[off++] = p2B;
        System.arraycopy(input, SLOT_B_OFFSET + 3, cdata, off, lenB);

        // Step 4: Construct CommandAPDU
        CommandAPDU commandAPDU = new CommandAPDU(
                FUZZ_CLA & 0xFF,
                FUZZ_INS & 0xFF,
                0x00,
                0x00,
                cdata);

        // Step 5: Send to simulator; response is not processed (timing cost is via Kelinci)
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("{aid_string}".getBytes());
        simulator.installApplet(appletAID, {applet_class}.class);
        simulator.selectApplet(appletAID);
        simulator.transmitCommand(commandAPDU);

        System.out.println("Done.");
    }}
}}
"""


def driver_class_name(wrapper_name: str) -> str:
    """wrapHmacSha160 -> FuzzDriverHmacSha160"""
    if wrapper_name.startswith('wrap'):
        return 'FuzzDriver' + wrapper_name[4:]
    return 'FuzzDriver' + wrapper_name


def derive_aid(class_name: str) -> str:
    """MyCardFuzzApplet -> 'MyCardFuzz'  (strip trailing 'Applet')"""
    if class_name.endswith('Applet'):
        return class_name[:-len('Applet')]
    return class_name


def generate_driver(op: dict, applet_info: dict,
                    applet_file: str, aid: str) -> tuple[str, str]:
    """
    Return (filename, java_source) for the driver of one operation.
    """
    d_class = driver_class_name(op['wrapper_name'])
    max_data = op['max_data']
    total_size = 6 + 2 * max_data

    source = DRIVER_TEMPLATE.format(
        driver_class  = d_class,
        applet_class  = applet_info['class_name'],
        ins_name      = op['ins_name'],
        ins_value     = op['ins_value'],
        wrapper_name  = op['wrapper_name'],
        applet_file   = applet_file,
        max_data      = max_data,
        total_size    = total_size,
        package       = applet_info['package'],
        cla_hex       = applet_info['fuzz_cla'],
        ins_hex       = op['ins_value'],
        aid_string    = aid,
    )
    return d_class + '.java', source


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Generate FuzzDriver Java files from a FuzzApplet Java source.'
    )
    parser.add_argument(
        '--applet', required=True, metavar='PATH',
        help='Path to the *FuzzApplet.java source file'
    )
    parser.add_argument(
        '--output-dir', metavar='DIR', default=None,
        help='Directory for generated files (default: same dir as applet)'
    )
    parser.add_argument(
        '--aid', metavar='STRING', default=None,
        help='AID string for jCardSim (default: class name minus "Applet" suffix)'
    )
    args = parser.parse_args()

    applet_path = Path(args.applet)
    if not applet_path.is_file():
        print(f"ERROR: {applet_path} does not exist or is not a file.", file=sys.stderr)
        sys.exit(1)

    source = applet_path.read_text(encoding='utf-8')

    # Parse
    try:
        info = parse_applet(source)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    # AID
    aid = args.aid if args.aid else derive_aid(info['class_name'])
    if len(aid.encode()) > 16:
        aid = aid[:16]
        print(f"  WARNING: AID truncated to 16 bytes: \"{aid}\"", file=sys.stderr)

    # Output directory
    out_dir = Path(args.output_dir) if args.output_dir else applet_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # Print parsed summary
    print(f"Parsed applet : {info['class_name']}  (package {info['package']})")
    print(f"FUZZ_CLA      : {info['fuzz_cla']}  AID: \"{aid}\"")
    print(f"Operations found:")
    for op in info['operations']:
        print(f"  {op['ins_name']:<22} {op['ins_value']}  "
              f"{op['wrapper_name']:<24} MAX_DATA={op['max_data']}")

    if not info['operations']:
        print("No operations to generate. Exiting.", file=sys.stderr)
        sys.exit(1)

    # Generate
    print("Generated:")
    for op in info['operations']:
        filename, java_src = generate_driver(
            op, info, applet_path.name, aid
        )
        out_path = out_dir / filename
        if out_path.exists():
            print(f"  WARNING: overwriting {out_path}", file=sys.stderr)
        out_path.write_text(java_src, encoding='utf-8')
        total = 6 + 2 * op['max_data']
        print(f"  {filename:<40} ({total} bytes per fuzz input)")


if __name__ == '__main__':
    main()
