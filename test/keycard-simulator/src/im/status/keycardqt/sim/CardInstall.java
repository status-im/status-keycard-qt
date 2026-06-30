// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.Applet;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.security.SecureRandom;

/**
 * Version-neutral applet-install helpers. The AIDs and install parameters are identical across applet
 * generations (from {@code im.status.keycard.applet.Identifiers}), and {@code install} depends only on
 * jcardsim + {@code javacard.framework.Applet} — never on a specific applet's bytecode — so this lives
 * in the core package and is reused by every version's {@link CardFactory}.
 */
public final class CardInstall {
    private CardInstall() {}

    private static final SecureRandom RNG = new SecureRandom();

    public static final byte[] KEYCARD_AID  = hex("A000000804000101");
    public static final byte[] KEYCARD_INST = hex("A00000080400010101"); // getKeycardInstanceAID()
    public static final byte[] NDEF_AID     = hex("A000000804000102");
    public static final byte[] NDEF_INST    = hex("D2760000850101");
    public static final byte[] CASH_AID     = hex("A000000804000103");
    public static final byte[] CASH_INST    = hex("A00000080400010301");
    public static final byte[] IDENT_AID    = hex("A000000804000104");
    public static final byte[] IDENT_INST   = hex("A00000080400010401");
    /** Control/applet-data bytes used by the non-keycard applets (verbatim from KeycardTest). */
    public static final byte[] SECONDARY_PARAMS = new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00};

    /** Install one applet at @p loadAid with the given instance AID and optional install params. */
    public static void install(CardSimulator sim, byte[] loadAid,
                               Class<? extends Applet> clazz, byte[] instanceAid, byte[] params) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(instanceAid.length);
        bos.write(instanceAid, 0, instanceAid.length);
        if (params != null) {
            bos.write(params, 0, params.length);
        }
        byte[] data = bos.toByteArray();
        sim.installApplet(AIDUtil.create(loadAid), clazz, data, (short) 0, (byte) data.length);
    }

    /**
     * Overwrite the keycard applet's instance UID with fresh random bytes, so each card is unique
     * like real hardware. jcardsim seeds its RNG deterministically, so the applet otherwise generates
     * the SAME instance UID for every card; that makes the lib's pairing storage (keyed by instance
     * UID) collide across cards/sessions, causing stale-pairing secure-channel failures (SW=6a86 ->
     * false "blocked-puk"). Call this right after installing the applets, before any APDU.
     */
    public static void assignUniqueInstanceUid(ExposedRuntime runtime) {
        try {
            Applet applet = runtime.appletAt(AIDUtil.create(KEYCARD_INST));
            if (applet == null) {
                throw new IllegalStateException("keycard applet not found after install");
            }
            Field uidField = applet.getClass().getDeclaredField("uid");
            uidField.setAccessible(true);
            byte[] uid = (byte[]) uidField.get(applet); // generated in the applet ctor; fixed length
            if (uid == null) {
                throw new IllegalStateException("keycard applet 'uid' field is null");
            }
            RNG.nextBytes(uid);
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new RuntimeException("failed to assign unique instance UID", e);
        }
    }

    public static byte[] hex(String s) {
        int len = s.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }
}
