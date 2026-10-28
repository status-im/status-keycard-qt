// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim;

import com.licel.jcardsim.smartcardio.CardSimulator;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Identity certificates for simulated cards, version-neutral (BouncyCastle only, no applet or SDK
 * classes). Both applet generations keep the certificate in the IdentApplet: 3.x hands it out via
 * IDENTIFY, 4.x in SELECT.
 *
 * <p>Certificate: identityPublicKey(33, compressed) || r(32) || s(32) || recId(1), a CA signature over
 * SHA256(identityPublicKey). Cards are signed by one of two <b>fixed</b> CAs, so a client can pin the
 * trusted one.
 */
public final class IdentCertificates {
    private IdentCertificates() {}

    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());
    private static final SecureRandom RNG = new SecureRandom();

    /** CA the client should trust: private key = SHA256(UTF-8 "keycard-qt simulator test CA"). */
    public static final BigInteger TEST_CA = privateKeyFromLabel("keycard-qt simulator test CA");
    /** CA the client should not trust: private key = SHA256(UTF-8 "keycard-qt simulator untrusted CA"). */
    public static final BigInteger UNTRUSTED_CA = privateKeyFromLabel("keycard-qt simulator untrusted CA");

    public static final int CERT_LEN = 98;
    private static final int KEY_LEN = 32;

    public static BigInteger privateKeyFromLabel(String label) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, d);
        } catch (Exception e) {
            throw new RuntimeException("failed to derive key for '" + label + "'", e);
        }
    }

    /**
     * IdentApplet STORE DATA payload for a fresh random identity: certificate (signed by @p caPrivateKey)
     * || identity private key(32).
     */
    public static byte[] newStoreData(BigInteger caPrivateKey) {
        BigInteger identity;
        do {
            identity = new BigInteger(256, RNG);
        } while (identity.signum() == 0 || identity.compareTo(DOMAIN.getN()) >= 0);

        byte[] identityPublic = DOMAIN.getG().multiply(identity).normalize().getEncoded(true);
        byte[] cert = certificate(caPrivateKey, identityPublic);
        byte[] out = Arrays.copyOf(cert, CERT_LEN + KEY_LEN);
        System.arraycopy(fixed32(identity), 0, out, CERT_LEN, KEY_LEN);
        return out;
    }

    /** CA signature over SHA256(identityPublic), with the recovery id the client uses to find the CA. */
    static byte[] certificate(BigInteger caPrivateKey, byte[] identityPublic) {
        byte[] hash = sha256(identityPublic);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(caPrivateKey, DOMAIN));
        BigInteger[] rs = signer.generateSignature(hash);

        ECPoint caPublic = DOMAIN.getG().multiply(caPrivateKey).normalize();
        int recId = -1;
        for (int i = 0; i < 4 && recId < 0; i++) {
            ECPoint recovered = recover(hash, rs[0], rs[1], i);
            if (recovered != null && recovered.equals(caPublic)) {
                recId = i;
            }
        }
        if (recId < 0) {
            throw new IllegalStateException("no recovery id reproduces the CA key");
        }

        byte[] cert = new byte[CERT_LEN];
        System.arraycopy(identityPublic, 0, cert, 0, 33);
        System.arraycopy(fixed32(rs[0]), 0, cert, 33, 32);
        System.arraycopy(fixed32(rs[1]), 0, cert, 65, 32);
        cert[97] = (byte) recId;
        return cert;
    }

    /** SEC 1, 4.1.6: the public key that produced (r, s) over @p hash for recovery id @p recId. */
    private static ECPoint recover(byte[] hash, BigInteger r, BigInteger s, int recId) {
        BigInteger n = DOMAIN.getN();
        BigInteger x = r.add(BigInteger.valueOf(recId / 2).multiply(n));
        if (x.compareTo(CURVE.getCurve().getField().getCharacteristic()) >= 0) {
            return null;
        }
        byte[] encoded = new byte[33];
        encoded[0] = (byte) ((recId & 1) == 1 ? 0x03 : 0x02);
        System.arraycopy(fixed32(x), 0, encoded, 1, 32);
        ECPoint bigR = CURVE.getCurve().decodePoint(encoded);
        BigInteger e = new BigInteger(1, hash);
        BigInteger rInv = r.modInverse(n);
        BigInteger u1 = n.subtract(e).multiply(rInv).mod(n);
        BigInteger u2 = s.multiply(rInv).mod(n);
        return ECAlgorithms.sumOfTwoMultiplies(DOMAIN.getG(), u1, bigR, u2).normalize();
    }

    /** Factory personalization: store @p storeData (see newStoreData) in the card's IdentApplet. */
    public static void personalize(CardSimulator sim, byte[] storeData) {
        byte[] aid = CardInstall.IDENT_INST;
        byte[] select = new byte[5 + aid.length];
        select[1] = (byte) 0xA4;
        select[2] = 0x04;
        select[4] = (byte) aid.length;
        System.arraycopy(aid, 0, select, 5, aid.length);

        byte[] store = new byte[5 + storeData.length];
        store[0] = (byte) 0x80;
        store[1] = (byte) 0xE2;
        store[4] = (byte) storeData.length;
        System.arraycopy(storeData, 0, store, 5, storeData.length);

        synchronized (sim) {
            expectOk(sim.transmitCommand(select), "SELECT IdentApplet");
            expectOk(sim.transmitCommand(store), "STORE DATA");
        }
    }

    private static void expectOk(byte[] response, String what) {
        int n = response.length;
        if (n < 2 || response[n - 2] != (byte) 0x90 || response[n - 1] != 0x00) {
            throw new RuntimeException("IdentApplet personalization failed at " + what);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Unsigned big-endian, left-padded to 32 bytes. */
    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
    }
}
