// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim.v40;

import com.licel.jcardsim.smartcardio.CardSimulator;

import im.status.keycard.KeycardApplet;
import im.status.keycard.NDEFApplet;
import im.status.keycard.CashApplet;
import im.status.keycard.IdentApplet;
import im.status.keycard.applet.Certificate;
import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import im.status.keycardqt.sim.CardFactory;
import im.status.keycardqt.sim.CardInstall;
import im.status.keycardqt.sim.ExposedRuntime;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Security;

/**
 * Card recipe for Status Keycard applet <b>4.0</b> (status-keycard tag {@code 4.0.1} = {@code 37393a2},
 * {@code SecureChannelV2} / certificate-based). The 4.0 keycard applet rejects every APDU (even SELECT,
 * SW {@code 6985}) until the IdentApplet holds a CA-signed identity certificate (factory
 * personalization), so {@code newCard()} installs the applets and stores one.
 *
 * <p>The certificate is signed by one of two <b>fixed</b> test CAs (so a client can pin the trusted one);
 * each card's identity key is random. The card is otherwise blank (no PIN, no key) — only the factory
 * identity cert is provisioned.
 */
public final class Card40Factory implements CardFactory {

    /** CA the client should trust: private key = SHA256(UTF-8 "keycard-qt simulator test CA"). */
    public static final KeyPair TEST_CA;
    /** CA the client must reject: private key = SHA256(UTF-8 "keycard-qt simulator untrusted CA"). */
    public static final KeyPair UNTRUSTED_CA;
    static {
        Security.addProvider(new BouncyCastleProvider());
        TEST_CA = keyPairFromLabel("keycard-qt simulator test CA");
        UNTRUSTED_CA = keyPairFromLabel("keycard-qt simulator untrusted CA");
    }

    @Override
    public String appletVersion() {
        return "4.0";
    }

    @Override
    public CardSimulator newCard(boolean untrusted) {
        KeyPair ca = untrusted ? UNTRUSTED_CA : TEST_CA;
        return newCard(new ExposedRuntime(), newCertificate(ca));
    }

    /** STORE DATA payload: cert (pub 33 || r 32 || s 32 || recId 1) || identity private key 32. */
    public static final int STORE_DATA_LEN = 98 + 32;

    /**
     * A certificate for a fresh random identity, signed by @p ca. The SDK strips leading zero bytes
     * from r/s/private key without left-padding, so ~1 in 100 draws comes out short and the applet
     * would reject it (SW 6A80); draw again until every field is full width.
     */
    public static Certificate newCertificate(KeyPair ca) {
        while (true) {
            Certificate cert = Certificate.generateNewCertificate(ca);
            if (cert.toStoreData().length == STORE_DATA_LEN) {
                return cert;
            }
        }
    }

    /** A card personalized with @p cert (identity key + CA signature), on the given runtime. */
    public static CardSimulator newCard(ExposedRuntime runtime, Certificate cert) {
        CardSimulator sim = new CardSimulator(runtime);
        CardInstall.install(sim, CardInstall.KEYCARD_AID, KeycardApplet.class, CardInstall.KEYCARD_INST, null);
        CardInstall.install(sim, CardInstall.NDEF_AID, NDEFApplet.class, CardInstall.NDEF_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.install(sim, CardInstall.CASH_AID, CashApplet.class, CardInstall.CASH_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.install(sim, CardInstall.IDENT_AID, IdentApplet.class, CardInstall.IDENT_INST, CardInstall.SECONDARY_PARAMS);
        // No assignUniqueInstanceUid(): the 4.x applet dropped the instance UID (SELECT has no 0x8F and
        // there is no pairing to key by it); the card's random identity key is what makes it unique.
        personalize(sim, cert);
        return sim;
    }

    /** Deterministic secp256k1 keypair whose private key is SHA256(UTF-8 @p label). */
    public static KeyPair keyPairFromLabel(String label) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8));
            ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
            BigInteger s = new BigInteger(1, d);
            KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
            return new KeyPair(
                    kf.generatePublic(new ECPublicKeySpec(spec.getG().multiply(s).normalize(), spec)),
                    kf.generatePrivate(new ECPrivateKeySpec(s, spec)));
        } catch (Exception e) {
            throw new RuntimeException("failed to derive keypair for '" + label + "'", e);
        }
    }

    /** Factory personalization: store a CA-signed identity certificate in the IdentApplet. */
    private static void personalize(CardSimulator sim, Certificate cert) {
        CardChannel ch = new CardChannel() {
            @Override
            public APDUResponse send(APDUCommand cmd) throws java.io.IOException {
                synchronized (sim) {
                    return new APDUResponse(sim.transmitCommand(cmd.serialize()));
                }
            }
            @Override
            public boolean isConnected() {
                return true;
            }
        };
        try {
            IdentCommandSet ident = new IdentCommandSet(ch);
            ident.select().checkOK();
            ident.storeData(cert.toStoreData()).checkOK();
        } catch (Exception e) {
            throw new RuntimeException("IdentApplet personalization failed", e);
        }
    }
}
