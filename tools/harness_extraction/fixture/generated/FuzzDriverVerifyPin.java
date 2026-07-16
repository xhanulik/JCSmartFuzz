/*
 * FuzzDriverSkeleton: Diffuzz driver for differential fuzzing of Java Card applets.
 *
 * This driver is the host-side counterpart to FuzzAppletSkeleton.java.
 * It reads fuzz input from a file, constructs a CommandAPDU matching
 * the skeleton's dual-invocation APDU format, sends it to a Java Card
 * simulator, and reports the timing cost difference to diffuzz.
 *
 * APDU format sent to the FuzzAppletSkeleton:
 *   CLA: FUZZ_CLA (0xB1)
 *   INS: operation code
 *   P1/P2: 0x00
 *   CDATA: [size_A(2) | input_set_A(size_A) | input_set_B(remaining)]
 *     where input_set = [p1(1) | p2(1) | operation_data]
 *
 * Fuzz input file layout (fixed-offset scheme, AFL++-friendly):
 *   [p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA) | p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA)]
 *
 * The INS byte is NOT part of the fuzz input. It is pinned at build
 * time via the FUZZ_INS constant below — a given driver build fuzzes
 * exactly one operation of the target applet. To fuzz a different
 * operation, rebuild with a different FUZZ_INS value.
 *
 * Every byte has a stable position regardless of len_A/len_B values.
 * len_A and len_B are clamped to [0, MAX_DATA] and control how many
 * bytes from each fixed-size slot are actually used.
 *
 * Usage with diffuzz:
 *   Compile and run via Kelinci interface, providing the fuzz input file as args[0].
 */

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import fixture.FuzzAppletVerifyPin;

import java.io.FileInputStream;
import java.io.IOException;

public class FuzzDriverVerifyPin {

    // Must match FuzzAppletSkeleton.FUZZ_CLA
    private static final byte FUZZ_CLA = (byte) 0xB1;

    /*=====================================================================*
     *  GENERATED SECTION: FUZZ_INS                                        *
     *  Pin this driver to ONE operation of the target applet. The INS     *
     *  byte is NOT fuzzed — it is a build-time constant so that every     *
     *  seed AFL++ produces exercises the same handler.                    *
     *  Must match one of the INS_XXX constants in the fuzzing applet.     *
     *=====================================================================*/

    private static final byte FUZZ_INS = 0x10; // INS_VERIFYPIN

    /*=====================================================================*
     *  GENERATED SECTION: MAX_DATA                                        *
     *  Set this to the maximum operation data size for the target applet. *
     *  The total fuzz input file size will be:                            *
     *    HEADER_A(3) + MAX_DATA + HEADER_B(3) + MAX_DATA                  *
     *  Example: MAX_DATA=64 => 134 bytes per fuzz input                   *
     *=====================================================================*/

    private static final int MAX_DATA = 64; // default -- adjust to the operation's max data size if needed

    // Derived constants — do not modify
    private static final int SLOT_B_OFFSET = 3 + MAX_DATA;         // p1_B starts here
    private static final int TOTAL_INPUT_SIZE = 3 + MAX_DATA + 3 + MAX_DATA;


    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Expects file name as parameter");
            return;
        }

        // Step 1: Read raw fuzz input from file into fixed-size buffer
        byte[] input = new byte[TOTAL_INPUT_SIZE];
        int bytesRead = 0;
        try (FileInputStream fis = new FileInputStream(args[0])) {
            int r;
            while (bytesRead < TOTAL_INPUT_SIZE && (r = fis.read(input, bytesRead, TOTAL_INPUT_SIZE - bytesRead)) != -1) {
                bytesRead += r;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        // Pad with zeros if the file is shorter than TOTAL_INPUT_SIZE.
        // This is fine — AFL++ may produce shorter inputs, and zeros are
        // valid data. The fixed-offset layout remains consistent.

        // Step 2: Parse fixed-offset layout (INS is NOT in the input — it is FUZZ_INS)
        // Slot A: [p1_A(1) | p2_A(1) | len_A(1) | data_A(MAX_DATA)]
        byte p1A = input[0];
        byte p2A = input[1];
        int lenA = Math.min(input[2] & 0xFF, MAX_DATA);

        // Slot B: [p1_B(1) | p2_B(1) | len_B(1) | data_B(MAX_DATA)]
        byte p1B = input[SLOT_B_OFFSET];
        byte p2B = input[SLOT_B_OFFSET + 1];
        int lenB = Math.min(input[SLOT_B_OFFSET + 2] & 0xFF, MAX_DATA);

        // Step 3: Build CDATA in the applet's framing format
        // input_set_A = [p1_A | p2_A | data_A(lenA)]  => sizeA = 2 + lenA
        // input_set_B = [p1_B | p2_B | data_B(lenB)]
        // CDATA = [size_A(2) | input_set_A | input_set_B]
        int sizeA = 2 + lenA;
        int cdataLen = 2 + sizeA + 2 + lenB;
        byte[] cdata = new byte[cdataLen];
        int off = 0;

        // size_A as big-endian short
        cdata[off++] = (byte) ((sizeA >> 8) & 0xFF);
        cdata[off++] = (byte) (sizeA & 0xFF);

        // input_set_A: [p1_A | p2_A | data_A(lenA)]
        cdata[off++] = p1A;
        cdata[off++] = p2A;
        System.arraycopy(input, 3, cdata, off, lenA);
        off += lenA;

        // input_set_B: [p1_B | p2_B | data_B(lenB)]
        cdata[off++] = p1B;
        cdata[off++] = p2B;
        System.arraycopy(input, SLOT_B_OFFSET + 3, cdata, off, lenB);

        // Step 4: Construct CommandAPDU
        CommandAPDU commandAPDU = new CommandAPDU(
                FUZZ_CLA & 0xFF,  // CLA
                FUZZ_INS & 0xFF,  // INS (pinned at build time)
                0x00,             // P1 (unused at APDU level)
                0x00,             // P2 (unused at APDU level)
                cdata             // CDATA with framed dual inputs
        );

        // Step 5: Prepare and send to simulator
        // The applet internally runs both inputs and returns:
        //   [len_A(2) | result_A(len_A) | len_B(2) | result_B(len_B)]
                /* Prepare new simulator for each round */
        CardSimulator simulator = new CardSimulator();
        AID appletAID = AIDUtil.create("FuzzAppletVerifyPin".getBytes());
        simulator.installApplet(appletAID, FuzzAppletVerifyPin.class);
        simulator.selectApplet(appletAID);
        simulator.transmitCommand(commandAPDU);

        System.out.println("Done.");
    }
}
