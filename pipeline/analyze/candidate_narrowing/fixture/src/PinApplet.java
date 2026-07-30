package fixture;

/**
 * Synthetic fixture with intentionally planted leaky idioms, used to smoke-test
 * the candidate-narrowing pipeline (semgrep rules + dataflow heuristics + name
 * heuristics). Not a real applet.
 */
public class PinApplet {
    private byte[] storedPin;
    private byte triesLeft;

    // (1) early-return-array-compare + secret-length-loop-bound + name:secret-param
    boolean checkPin(byte[] pin) {
        for (short i = 0; i < pin.length; i++) {
            if (pin[i] != storedPin[i]) {
                return false;
            }
        }
        return true;
    }

    // (2) dataflow-secret-length-loop: secret renamed to `p` before the loop,
    // defeats a literal-name-only semgrep rule but not the taint propagation.
    boolean checkPinRenamed(byte[] pin) {
        byte[] p = pin;
        for (short i = 0; i < p.length; i++) {
            if (p[i] != storedPin[i]) {
                return false;
            }
        }
        return true;
    }

    // (3) branch-on-secret-value + dataflow-branch-on-secret
    void applyDiscount(byte[] secretCode) {
        if (secretCode[0] == 1) {
            grantAccess();
        } else {
            denyAccess();
        }
    }

    // (4) custom-xor-loop
    void mix(byte[] out, byte[] a, byte[] b) {
        for (short i = 0; i < out.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
    }

    // no leaky idiom -- should not be flagged (a negative control)
    void reset() {
        triesLeft = 3;
    }

    void grantAccess() {}
    void denyAccess() {}
}
