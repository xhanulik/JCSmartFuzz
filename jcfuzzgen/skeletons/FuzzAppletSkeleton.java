/*
 * FuzzAppletSkeleton: Reusable scaffold for differential fuzzing of Java Card applets.
 *
 * This file contains the fixed infrastructure (Layers 1-2) that never changes.
 * To create a fuzzing applet for a specific target applet, fill in the marked
 * GENERATED sections (Layers 3-4) using the LLM extraction prompt.
 *
 * Architecture:
 *   Layer 1 — process():           Fixed dual-invocation framing
 *   Layer 2 — dispatchOperation(): Fixed routing (add case entries)
 *   Layer 3 — wrapXxx() methods:   GENERATED — new code, unpacks APDU, calls core
 *   Layer 4 — coreXxx() methods:   GENERATED — verbatim copies from original applet
 *
 * APDU format:
 *   CLA: configurable (FUZZ_CLA)
 *   INS: operation code
 *   P1/P2: unused at APDU level (per-input P1/P2 are inside each input set)
 *   CDATA: [size_A(2) | input_set_A(size_A) | input_set_B(remaining)]
 *     where input_set = [p1(1) | p2(1) | operation_data]
 *
 * Response format:
 *   [len_A(2) | result_A(len_A) | len_B(2) | result_B(len_B)]
 */

package /* GENERATED: set package name */;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
/* GENERATED: add imports required by core methods (javacard.security.*, javacardx.crypto.*, etc.) */

public class /* GENERATED: set class name */ extends javacard.framework.Applet {

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
     *  GENERATED SECTION: INS byte constants                              *
     *  Paste the INS constants from the LLM extraction output here.       *
     *  Example:                                                           *
     *    private final static byte INS_SIGN_HASH = (byte) 0x10;          *
     *    private final static byte INS_DERIVE_KEY = (byte) 0x11;         *
     *=====================================================================*/

    // {{GENERATED: INS constants go here}}

    /*=====================================================================*
     *  GENERATED SECTION: Constants from original applet                   *
     *  Paste the constants from LLM extraction output Section 3 here.     *
     *  These are verbatim copies of constants the core methods reference.  *
     *=====================================================================*/

    // {{GENERATED: applet-specific constants go here}}

    /*=====================================================================*
     *  GENERATED SECTION: Error codes from original applet                 *
     *  Paste any SW_ error codes that core methods throw.                 *
     *=====================================================================*/

    // {{GENERATED: error codes go here}}

    /****************************************
     *  SCAFFOLD INSTANCE VARIABLES (fixed) *
     ****************************************/

    // Fuzz buffer — preserves dual inputs and stores intermediate results during dual-invocation
    private byte[] fuzzBuffer;

    /*=====================================================================*
     *  GENERATED SECTION: Instance fields                                  *
     *  Paste the field declarations from LLM extraction output Section 2.  *
     *                                                                      *
     *  Fields MUST use the same names as the original applet so that       *
     *  core methods are verbatim copies.                                   *
     *                                                                      *
     *  Typical fields:                                                     *
     *    - Working buffers: byte[] recvBuffer, byte[] tmpBuffer            *
     *    - Crypto engines: Signature, MessageDigest, Cipher, KeyAgreement  *
     *    - Key objects: ECPrivateKey, AESKey, etc.                         *
     *=====================================================================*/

    // {{GENERATED: field declarations go here}}

    /****************************************
     *  CONSTRUCTOR AND INSTALL             *
     ****************************************/

    private /* GENERATED: class name */(byte[] bArray, short bOffset, byte bLength) {
        // --- Fixed scaffold allocation ---
        fuzzBuffer = JCSystem.makeTransientByteArray(FUZZ_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);

        /*=================================================================*
         *  GENERATED SECTION: Field initialization                        *
         *  Paste the constructor init lines from LLM extraction output.   *
         *                                                                  *
         *  Typical init:                                                   *
         *    recvBuffer = JCSystem.makeTransientByteArray(RECV_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);  *
         *    tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);    *
         *    sigEngine = Signature.getInstance(ALG_..., false);            *
         *    hashEngine = MessageDigest.getInstance(ALG_..., false);       *
         *    privKey = (ECPrivateKey) KeyBuilder.buildKey(...);             *
         *    CurveParams.setCommonCurveParameters(privKey);                *
         *    HelperClass.init(tmpBuffer);                                  *
         *=================================================================*/

        // {{GENERATED: field initialization goes here}}

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new /* GENERATED: class name */(bArray, bOffset, bLength);
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

        byte ins = buffer[ISO7816.OFFSET_INS];

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

        short lenA = dispatchOperation(ins, apdu, buffer);
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

        short lenB = dispatchOperation(ins, apdu, buffer);
        if (lenB > 0)
            Util.arrayCopyNonAtomic(buffer, (short) 0,
                    fuzzBuffer, FUZZ_RESULT_B_OFFSET, lenB);

        // ---- BUILD RESPONSE ----
        // Response = [len_A(2) | result_A(len_A) | len_B(2) | result_B(len_B)]
        short outOff = 0;
        Util.setShort(buffer, outOff, lenA); outOff += 2;
        if (lenA > 0) {
            Util.arrayCopyNonAtomic(fuzzBuffer, FUZZ_RESULT_A_OFFSET, buffer, outOff, lenA);
            outOff += lenA;
        }
        Util.setShort(buffer, outOff, lenB); outOff += 2;
        if (lenB > 0) {
            Util.arrayCopyNonAtomic(fuzzBuffer, FUZZ_RESULT_B_OFFSET, buffer, outOff, lenB);
            outOff += lenB;
        }

        apdu.setOutgoingAndSend((short) 0, outOff);
    }

    /***************************************************************************
     *  LAYER 2 — dispatchOperation(): Routing table                          *
     *                                                                         *
     *  Add one case per extracted operation. Each case calls the              *
     *  corresponding wrapXxx() method from Layer 3.                          *
     ***************************************************************************/

    private short dispatchOperation(byte ins, APDU apdu, byte[] buffer) {
        switch (ins) {

            /*=============================================================*
             *  GENERATED SECTION: Dispatcher case entries                  *
             *  Paste from LLM extraction output Section 4.                *
             *  Example:                                                    *
             *    case INS_SIGN_HASH:  return wrapSignHash(apdu, buffer);  *
             *    case INS_DERIVE_KEY: return wrapDeriveKey(apdu, buffer); *
             *=============================================================*/

            // {{GENERATED: case entries go here}}

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return (short) 0;
        }
    }

    /***************************************************************************
     *                                                                         *
     *  LAYER 3 — WRAPPER METHODS                                             *
     *                                                                         *
     *  GENERATED: Paste wrapXxx() methods from LLM extraction output          *
     *  Section 5 (the "Wrapper" part of each operation).                      *
     *                                                                         *
     *  Each wrapper:                                                          *
     *    1. Reads P1, P2, and operation_data from buffer                      *
     *    2. Validates input sizes                                             *
     *    3. Loads keys into instance fields, populates working buffers        *
     *    4. Calls the corresponding coreXxx() method                          *
     *    5. Formats output in buffer[0..] and returns the output size         *
     *                                                                         *
     ***************************************************************************/

    // {{GENERATED: wrapXxx() methods go here}}

    /***************************************************************************
     *                                                                         *
     *  LAYER 4 — CORE METHODS (VERBATIM from original applet)                *
     *                                                                         *
     *  GENERATED: Paste coreXxx() methods from LLM extraction output          *
     *  Section 5 (the "Core" part of each operation).                         *
     *                                                                         *
     *  Each core method must have a Javadoc annotation with:                  *
     *    SOURCE:           original file, method, line range                  *
     *    ALLOWED REMOVALS: whitelist of removed lines with categories         *
     *    FIELD MAPPING:    instance fields referenced (original names)        *
     *    PRECONDITION:     what the wrapper sets up before calling             *
     *                                                                         *
     *  Verification: diff each core method body against the original source   *
     *  at the annotated location. Only ALLOWED REMOVALS may differ.           *
     *                                                                         *
     ***************************************************************************/

    // {{GENERATED: coreXxx() methods go here}}
}
