/*
 * FuzzAppletSkeleton: Reusable scaffold for differential fuzzing of Java Card applets.
 *
 * ONE fuzzing applet fuzzes exactly ONE operation of the target applet (the
 * each-method-a-harness model). There is therefore no INS dispatch: process()
 * calls the single generated wrapper directly.
 *
 * This file contains the fixed infrastructure (Layer 1) that never changes.
 * The GENERATED markers (Layers 2-3) are filled automatically by the
 * harness pipeline (pipeline/harness/harness_extraction/):
 *   - extract_context.py      -> context.json  (constants, error codes,
 *                                fields + their constructor init lines, ins_byte)
 *   - llm_extract_operation.py -> operation.json (core_method + wrapper_method)
 *   - assemble_harness.py      -> substitutes every marker below from those two
 *
 * Architecture:
 *   Layer 1 — process():         Fixed dual-invocation framing (calls the wrapper twice)
 *   Layer 2 — wrapXxx() method:  from operation.json wrapper_method — unpacks APDU, calls core
 *   Layer 3 — coreXxx() method:  from operation.json core_method — verbatim-minus-removals
 *
 * APDU format:
 *   CLA: configurable (FUZZ_CLA)
 *   INS: ignored by the applet (single operation); the driver sends a fixed FUZZ_INS
 *   P1/P2: unused at APDU level (per-input P1/P2 are inside each input set)
 *   CDATA: [size_A(2) | input_set_A(size_A) | input_set_B(remaining)]
 *     where input_set = [p1(1) | p2(1) | operation_data]
 */

package fixture;

import edu.cmu.sv.kelinci.Kelinci;
import edu.cmu.sv.kelinci.Mem;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;


public class FuzzAppletVerifyPin extends javacard.framework.Applet {

    /****************************************
     *  SCAFFOLD CONSTANTS (fixed)          *
     ****************************************/

    // CLA byte — change if needed to avoid collision with the original applet
    private final static byte FUZZ_CLA = (byte) 0xB1;

    // Fuzz buffer layout — holds preserved inputs and intermediate results
    private final static short FUZZ_BUFFER_SIZE = (short) 520;
    private final static short FUZZ_INPUT_OFFSET = (short) 0;       // preserved CDATA: bytes 0..255
    private final static short FUZZ_RESULT_A_OFFSET = (short) 256;  // result A storage
    private final static short FUZZ_RESULT_B_OFFSET = (short) 390;  // result B storage

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

    // Fuzz buffer — preserves dual inputs and stores intermediate results during dual-invocation
    private byte[] fuzzBuffer;
    // Carries the Mem.instrCost measured around the last coreXxx() call out to process()
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

    private FuzzAppletVerifyPin(byte[] bArray, short bOffset, byte bLength) {
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
        new FuzzAppletVerifyPin(bArray, bOffset, bLength);
    }

    /***************************************************************************
     *  LAYER 1 — process(): Fixed dual-invocation framing                    *
     *                                                                         *
     *  DO NOT MODIFY. This method is the same for every fuzzing applet.      *
     *  It splits the APDU into two input sets, calls the operation twice,    *
     *  and returns both results.                                              *
     ***************************************************************************/

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != FUZZ_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        // INS is ignored: this applet fuzzes exactly one operation.

        short totalLen = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (totalLen != apdu.setIncomingAndReceive())
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // -------- DIFFERENTIAL FUZZING DUAL-INVOCATION --------

        if (totalLen < (short) 4) // minimum: 2 (size_A) + 1 (p1) + 1 (p2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Preserve entire CDATA in fuzzBuffer
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA,
                fuzzBuffer, FUZZ_INPUT_OFFSET, totalLen);

        // Parse framing: [size_A(2) | input_set_A(size_A) | input_set_B(remaining)]
        short sizeA = Util.getShort(fuzzBuffer, FUZZ_INPUT_OFFSET);
        short setA_off = (short)(FUZZ_INPUT_OFFSET + 2);
        short setB_off = (short)(setA_off + sizeA);
        short sizeB = (short)(totalLen - 2 - sizeA);

        // Each input_set must have at least p1(1) + p2(1) = 2 bytes
        if (sizeA < 2 || sizeB < 2)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // ---- RUN A ----
        short dataLenA = (short)(sizeA - 2);
        buffer[ISO7816.OFFSET_P1] = fuzzBuffer[setA_off];
        buffer[ISO7816.OFFSET_P2] = fuzzBuffer[(short)(setA_off + 1)];
        if (dataLenA > 0)
            Util.arrayCopyNonAtomic(fuzzBuffer, (short)(setA_off + 2),
                    buffer, ISO7816.OFFSET_CDATA, dataLenA);
        buffer[ISO7816.OFFSET_LC] = (byte)(dataLenA & 0xFF);

        short lenA = wrapOperation(apdu, buffer);
        long costA = lastCoreCost;
        if (lenA > 0)
            Util.arrayCopyNonAtomic(buffer, (short) 0,
                    fuzzBuffer, FUZZ_RESULT_A_OFFSET, lenA);

        // ---- RUN B ----
        short dataLenB = (short)(sizeB - 2);
        buffer[ISO7816.OFFSET_P1] = fuzzBuffer[setB_off];
        buffer[ISO7816.OFFSET_P2] = fuzzBuffer[(short)(setB_off + 1)];
        if (dataLenB > 0)
            Util.arrayCopyNonAtomic(fuzzBuffer, (short)(setB_off + 2),
                    buffer, ISO7816.OFFSET_CDATA, dataLenB);
        buffer[ISO7816.OFFSET_LC] = (byte)(dataLenB & 0xFF);

        short lenB = wrapOperation(apdu, buffer);
        long costB = lastCoreCost;
        if (lenB > 0)
            Util.arrayCopyNonAtomic(buffer, (short) 0,
                    fuzzBuffer, FUZZ_RESULT_B_OFFSET, lenB);

        Kelinci.addCost(Math.abs(costA - costB));
    }

    /***************************************************************************
     *                                                                         *
     *  LAYER 2 — WRAPPER METHOD                                              *
     *                                                                         *
     *  GENERATED: assemble_harness inserts the wrapXxx() from                 *
     *  operation.json's wrapper_method.code (llm_extract_operation.py) and    *
     *  wires the two process() calls above to it. There is no INS dispatch —  *
     *  this applet has exactly one operation.                                 *
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
     *  GENERATED: assemble_harness inserts the coreXxx() from                 *
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
