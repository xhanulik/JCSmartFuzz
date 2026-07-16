package fixture;

/**
 * Small utility class referenced by FixtureApplet.verifyPin() -- stands in for the
 * kind of helper/utility class (BigNat, ECPoint, custom HMAC, ...) that
 * llm_extraction_prompt.md rule 7 says must be copied into the fuzzing applet's
 * package verbatim, rather than reproduced by the LLM.
 */
public class PinHelper {

    public static byte foldChecksum(byte[] data, short offset, short len) {
        byte acc = 0;
        for (short i = 0; i < len; i++) {
            acc ^= data[(short) (offset + i)];
        }
        return acc;
    }
}
