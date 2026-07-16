package fixture;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Synthetic target applet for smoke-testing tools/harness_extraction/. Not a
 * real Java Card applet (no process()/install() wiring) -- just enough
 * structure (fields, constructor, constants, error codes, a helper-class
 * call, a lifecycle guard, a state mutation, and an early-exit PIN compare)
 * to exercise every deterministic extraction path plus the LLM removal gate.
 */
public class FixtureApplet {

    private static final byte MAX_PIN_LEN = 8;
    private static final short SW_NOT_INITIALIZED = (short) 0x6985;

    private byte[] referencePin;
    private byte triesLeft;
    private boolean initialized;

    public FixtureApplet() {
        referencePin = new byte[MAX_PIN_LEN];
        triesLeft = 3;
        initialized = true;
    }

    /**
     * Original handler: verifies a submitted PIN against the stored reference PIN.
     * Timing-sensitive: early-exit byte comparison leaks the position of the first
     * mismatching byte.
     */
    public boolean verifyPin(byte[] buffer, short offset, byte len) {
        if (!initialized) {
            ISOException.throwIt(SW_NOT_INITIALIZED);
        }

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
