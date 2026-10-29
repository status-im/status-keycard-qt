// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim;

import com.licel.jcardsim.smartcardio.CardSimulator;

import javacard.security.ECPrivateKey;

import java.lang.reflect.Field;
import java.util.function.Consumer;

/**
 * A simulated card that owns its identity certificate.
 *
 * <p>The applets (3.x and 4.x alike) keep the identity in {@code im.status.keycard.SharedMemory}, whose
 * fields are static, so every card in this JVM would share the identity of the card created last, and
 * installing an IdentApplet even clears it. So each card keeps its own copy, put back into SharedMemory
 * before the card handles an APDU. All cards share one lock, so no card sees another card's identity,
 * or a cleared one, mid-command. Reached by reflection, so this class stays version-neutral.
 */
public final class IdentityCardSimulator extends CardSimulator {
    /** Guards SharedMemory: held for every APDU and for the whole of card creation. */
    private static final Object IDENTITY_LOCK = new Object();
    private static IdentityCardSimulator active;

    private static final Field ID_CERT = appletField("SharedMemory", "idCert");
    private static final Field ID_PRIVATE = appletField("SharedMemory", "idPrivate");
    private static final byte CERT_VALID = certValid();

    /** STORE DATA payload (certificate || identity private key), or null before personalization. */
    private byte[] identity;

    private IdentityCardSimulator(ExposedRuntime runtime) {
        super(runtime);
    }

    /**
     * A card on @p runtime with the applets from @p installApplets, factory-personalized with
     * @p storeData (see {@link IdentCertificates#newStoreData}).
     */
    public static IdentityCardSimulator create(ExposedRuntime runtime, Consumer<CardSimulator> installApplets,
                                               byte[] storeData) {
        IdentityCardSimulator sim = new IdentityCardSimulator(runtime);
        synchronized (IDENTITY_LOCK) {
            installApplets.accept(sim);
            IdentCertificates.personalize(sim, storeData);
            sim.identity = storeData;
        }
        return sim;
    }

    /**
     * Swap the card's identity key for an unrelated one, keeping its certificate and all other state:
     * the card turns into a counterfeit that carries a genuine certificate it cannot sign for.
     */
    public void counterfeit() {
        synchronized (IDENTITY_LOCK) {
            identity = IdentCertificates.withForeignKey(identity);
            if (active == this) {
                active = null; // restored with the new key before the next APDU
            }
        }
    }

    @Override
    public byte[] transmitCommand(byte[] apdu) {
        synchronized (IDENTITY_LOCK) {
            if (active != this) {
                if (identity != null) {
                    restoreIdentity();
                }
                active = this;
            }
            return super.transmitCommand(apdu);
        }
    }

    private void restoreIdentity() {
        try {
            byte[] cert = (byte[]) ID_CERT.get(null);
            System.arraycopy(identity, 0, cert, 1, IdentCertificates.CERT_LEN);
            cert[0] = CERT_VALID;
            ((ECPrivateKey) ID_PRIVATE.get(null)).setS(identity, (short) IdentCertificates.CERT_LEN,
                    (short) (identity.length - IdentCertificates.CERT_LEN));
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("cannot restore the card identity", e);
        }
    }

    private static byte certValid() {
        try {
            return appletField("IdentApplet", "CERT_VALID").getByte(null);
        } catch (IllegalAccessException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private static Field appletField(String className, String name) {
        try {
            Field field = Class.forName("im.status.keycard." + className).getDeclaredField(name);
            field.setAccessible(true);
            return field;
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
