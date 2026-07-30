/*
 * ProfileAppletSkeleton: Reusable scaffold for PROFILING a Java Card applet
 * operation (single-invocation worst-case cost), the counterpart to
 * FuzzAppletSkeleton.java (differential dual-invocation).
 *
 * Difference from FuzzAppletSkeleton:
 *   - FuzzApplet runs the operation TWICE (input sets A and B) and reports the
 *     cost *difference* |costA - costB| — for differential timing fuzzing.
 *   - ProfileApplet runs the operation ONCE and reports the single instruction
 *     cost — for profiling / worst-case analysis (AFL++ maximizes the cost).
 *   - Its input is therefore HALF of a FuzzApplet input: exactly one input set.
 *     pipeline/profile/ splits FuzzApplet inputs into ProfileApplet inputs.
 *
 * One ProfileApplet profiles exactly ONE operation, so (like FuzzApplet) there
 * is no INS dispatch: process() calls the single generated wrapper directly.
 *
 * Everything else is shared with FuzzAppletSkeleton: the Layer 2 wrapXxx() and
 * Layer 3 coreXxx() methods, the context (constants / error codes / fields +
 * init), and the GENERATED markers are identical, so the same harness pipeline
 * (pipeline/harness/harness_extraction/) fills them:
 *   - extract_context.py      -> context.json  (constants, error codes,
 *                                fields + their constructor init lines, ins_byte)
 *   - llm_extract_operation.py -> operation.json (core_method + wrapper_method)
 *   - assemble_profile.py      -> substitutes every marker below from those two
 *
 * Architecture:
 *   Layer 1 — process():         Fixed SINGLE-invocation framing (calls the wrapper once)
 *   Layer 2 — wrapXxx() method:  from operation.json wrapper_method — unpacks APDU, calls core
 *   Layer 3 — coreXxx() method:  from operation.json core_method — verbatim-minus-removals
 *
 * APDU format:
 *   CLA: configurable (FUZZ_CLA)
 *   INS: ignored by the applet (single operation); the driver sends a fixed FUZZ_INS
 *   P1/P2: unused at APDU level (per-input P1/P2 are inside the input set)
 *   CDATA: [p1(1) | p2(1) | operation_data]   (a single input set)
 */

package fixture;

import edu.cmu.sv.kelinci.Kelinci;
import edu.cmu.sv.kelinci.Mem;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;


public class ProfileAppletVerifyPin extends javacard.framework.Applet {

    /****************************************
     *  SCAFFOLD CONSTANTS (fixed)          *
     ****************************************/

    // CLA byte — change if needed to avoid collision with the original applet
    private final static byte FUZZ_CLA = (byte) 0xB1;

    // Fuzz buffer layout — holds the preserved input set during invocation
    private final static short FUZZ_BUFFER_SIZE = (short) 520;
    private final static short FUZZ_INPUT_OFFSET = (short) 0;       // preserved CDATA

    // Working buffer sizes — adjust if the original applet uses larger buffers
    private final static short RECV_BUFFER_SIZE = (short) 268;
    private final static short TMP_BUFFER_SIZE = (short) 256;

    /*=====================================================================*
     *  GENERATED SECTION: Constants from the original applet               *
     *  assemble_harness fills these from context.json's `constants`        *
     *  (extract_context.py) — verbatim declarations the core references.   *
     *=====================================================================*/

        private static final byte MAX_PIN_LEN = 8;

    /*=====================================================================*
     *  GENERATED SECTION: Error codes from the original applet             *
     *  assemble_harness fills these from context.json's `error_codes`      *
     *  (the SW_ constants the core throws).                               *
     *=====================================================================*/

        private static final short SW_NOT_INITIALIZED = (short) 0x6985;

    /****************************************
     *  SCAFFOLD INSTANCE VARIABLES (fixed) *
     ****************************************/

    // Fuzz buffer — preserves the input set during invocation
    private byte[] fuzzBuffer;
    // Carries the Mem.instrCost measured around the coreXxx() call out to process()
    private long lastCoreCost;

    /*=====================================================================*
     *  GENERATED SECTION: Instance fields                                  *
     *  assemble_harness fills these from context.json's `fields`           *
     *  (extract_context.py) — verbatim declarations, keeping the original  *
     *  applet's field names so the core methods remain verbatim copies.    *
     *  Typical: working buffers, crypto engines (Signature/MessageDigest/  *
     *  Cipher/KeyAgreement), key objects (ECPrivateKey, AESKey, …).        *
     *=====================================================================*/

        private boolean initialized;
    private byte[] referencePin;
    private byte triesLeft;

    /****************************************
     *  CONSTRUCTOR AND INSTALL             *
     ****************************************/

    private ProfileAppletVerifyPin(byte[] bArray, short bOffset, byte bLength) {
        // --- Fixed scaffold allocation ---
        fuzzBuffer = JCSystem.makeTransientByteArray(FUZZ_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);

        /*=================================================================*
         *  GENERATED SECTION: Field initialization                        *
         *  assemble_harness fills this from each context.json field's      *
         *  `init_line` (the original constructor's own init for that       *
         *  field) — buffer allocations, crypto-engine getInstance() calls, *
         *  key builds, curve/helper setup, etc.                            *
         *=================================================================*/

                initialized = true;
        referencePin = new byte[MAX_PIN_LEN];
        triesLeft = 3;

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ProfileAppletVerifyPin(bArray, bOffset, bLength);
    }

    /***************************************************************************
     *  LAYER 1 — process(): Fixed SINGLE-invocation framing                  *
     *                                                                         *
     *  DO NOT MODIFY. Runs the operation ONCE on a single input set and      *
     *  reports the instruction cost of that run to Kelinci (worst-case       *
     *  profiling — AFL++ drives inputs toward maximum cost).                 *
     ***************************************************************************/

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != FUZZ_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // INS is ignored: this applet profiles exactly one operation.

        short totalLen = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (totalLen != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // -------- SINGLE-INVOCATION PROFILING --------
        // CDATA is one input set: [p1(1) | p2(1) | operation_data]

        if (totalLen < (short) 2) // minimum: p1(1) + p2(1)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Preserve entire CDATA in fuzzBuffer, then lay it out for the wrapper
        // exactly as FuzzAppletSkeleton does per run (P1/P2 in the APDU header,
        // operation_data at OFFSET_CDATA) so wrapXxx() is byte-for-byte shared.
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA,
                fuzzBuffer, FUZZ_INPUT_OFFSET, totalLen);

        short dataLen = (short)(totalLen - 2);
        buffer[ISO7816.OFFSET_P1] = fuzzBuffer[FUZZ_INPUT_OFFSET];
        buffer[ISO7816.OFFSET_P2] = fuzzBuffer[(short)(FUZZ_INPUT_OFFSET + 1)];
        if (dataLen > 0)
            Util.arrayCopyNonAtomic(fuzzBuffer, (short)(FUZZ_INPUT_OFFSET + 2),
                    buffer, ISO7816.OFFSET_CDATA, dataLen);
        buffer[ISO7816.OFFSET_LC] = (byte)(dataLen & 0xFF);

        wrapOperation(apdu, buffer);

        Kelinci.addCost(lastCoreCost);
    }

    /***************************************************************************
     *                                                                         *
     *  LAYER 2 — WRAPPER METHOD                                              *
     *                                                                         *
     *  GENERATED: assemble_profile inserts the wrapXxx() from                 *
     *  operation.json's wrapper_method.code (llm_extract_operation.py) and    *
     *  wires the process() call above to it — identical to the FuzzApplet     *
     *  wrapper; there is no INS dispatch (single operation).                  *
     *                                                                         *
     *  Each wrapper:                                                          *
     *    1. Reads P1, P2, and operation_data from buffer                      *
     *    2. Validates input sizes                                             *
     *    3. Loads keys into instance fields, populates working buffers        *
     *    4. Measures instruction cost around the core call:                   *
     *         Mem.clear();                                                    *
     *         coreXxx();                                                      *
     *         lastCoreCost = Mem.instrCost;                                   *
     *    5. Formats output in buffer[0..] and returns the output size         *
     *                                                                         *
     ***************************************************************************/

    private short wrapOperation(APDU apdu, byte[] buffer) {
    byte pinLen = buffer[ISO7816.OFFSET_P1];
    boolean ok = coreVerifyPin(buffer, ISO7816.OFFSET_CDATA, pinLen);
    buffer[0] = ok ? (byte) 1 : (byte) 0;
    return (short) 1;
}

    /***************************************************************************
     *                                                                         *
     *  LAYER 3 — CORE METHOD (VERBATIM from original applet)                 *
     *                                                                         *
     *  GENERATED: assemble_profile inserts the coreXxx() from                 *
     *  operation.json's core_method.code — a verbatim-minus-removals copy    *
     *  of the original method (llm_extract_operation.py).                     *
     *                                                                         *
     *  assemble_harness prepends a Javadoc with:                             *
     *    SOURCE:           original file, method, line range                  *
     *    ALLOWED REMOVALS: the declared removed_lines + categories            *
     *    FIELD MAPPING:    instance fields referenced (original names)        *
     *    PRECONDITION:     what the wrapper sets up before calling             *
     *                                                                         *
     *  llm_extract_operation.py already fidelity-diffs the core body against  *
     *  the original; only the ALLOWED REMOVALS may differ.                    *
     *                                                                         *
     ***************************************************************************/

    /**
 * SOURCE: FixtureApplet.java, verifyPin(), starting at line 36
 * TIMING RISK: [mock] early-exit comparison on secret data
 * ALLOWED REMOVALS:
 *   - lines 2-4: lifecycle guard -- initialization guard, not timing-relevant
 * FIELD MAPPING: initialized, referencePin, triesLeft
 * PRECONDITION: [mock] fields loaded by wrapper before calling
 */
    private boolean coreVerifyPin(byte[] buffer, short offset, byte len) {

        byte checksum = PinHelper.foldChecksum(buffer, offset, len);

        for (short i = 0; i < len; i++) {
            if (buffer[(short) (offset + i)] != referencePin[i]) {
                triesLeft--;
                return false;
            }
        }

        triesLeft = 3;
        return true;
    }
}
