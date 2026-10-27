// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim.tools;

import com.licel.jcardsim.smartcardio.CardSimulator;

import im.status.keycard.applet.Certificate;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.applet.SecureChannelV2;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import im.status.keycardqt.sim.CardInstall;
import im.status.keycardqt.sim.ExposedRuntime;
import im.status.keycardqt.sim.v40.Card40Factory;

import javacard.framework.Applet;
import javacard.security.CryptoException;
import javacard.security.RandomData;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Generates known-answer vectors for the SecureChannelV2 client in keycard-qt by driving the REAL 4.x
 * applet (jcardsim) against the REAL host SDK (status-keycard-java), with the randomness pinned:
 *
 * <ul>
 *   <li>card identity key + cert: SDK {@code Certificate.createCertificate} under the fixed test CA;</li>
 *   <li>card ephemeral key: the applet's {@code Crypto.random} is swapped (reflection) for a source
 *       that returns SHA256("card eph") for the next 32-byte draw (the ephemeral private key);</li>
 *   <li>host salt + ephemeral key: fed to the SDK's {@code processHandshakeResponse} (reflection).</li>
 * </ul>
 *
 * Every derived value is recomputed independently with BouncyCastle lightweight primitives
 * (ECDH, HKDF, AES-CCM, ECDSA, pubkey recovery) and the run aborts on any mismatch. Prints JSON.
 */
public final class GenScv2Vectors {

    private static final byte[] LABEL = "sc_v2_ccm".getBytes(StandardCharsets.US_ASCII);
    private static final X9ECParameters CURVE = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH());

    private static final String PIN = "000000";
    private static final String PUK = "123456789012";

    public static void main(String[] args) throws Exception {
        KeyPair ca = Card40Factory.TEST_CA;
        KeyPair untrustedCa = Card40Factory.UNTRUSTED_CA;
        KeyPair identity = Card40Factory.keyPairFromLabel("keycard-qt vector identity");
        byte[] hostEphPriv = sha256("host eph");
        byte[] cardEphPriv = sha256("card eph");
        byte[] salt = new byte[32];
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) (i + 1);
        }

        // ---- a. certificate ------------------------------------------------------------------
        Certificate cert;
        do { // the SDK doesn't left-pad r/s; draw until full width (see Card40Factory.newCertificate)
            cert = Certificate.createCertificate(ca, identity);
        } while (cert.toStoreData().length != Card40Factory.STORE_DATA_LEN);
        byte[] storeData = cert.toStoreData();
        byte[] certBytes = Arrays.copyOf(storeData, 98);
        byte[] identPub = Arrays.copyOf(certBytes, 33);
        byte[] certR = Arrays.copyOfRange(certBytes, 33, 65);
        byte[] certS = Arrays.copyOfRange(certBytes, 65, 97);
        int v = certBytes[97];
        byte[] certHash = sha256(identPub);
        byte[] caPub = compressed(ca);
        check(Arrays.equals(identPub, compressed(identity)), "cert pub != identity pub");
        check(v >= 0 && v <= 3, "v outside 0..3: " + v);
        check(Arrays.equals(recover(v, certHash, certR, certS), caPub), "raw recId does not recover CA");
        check(recover(v + 27, certHash, certR, certS) == null, "v+27 unexpectedly recovers a key");
        check(Arrays.equals(Certificate.fromTLV(certBytes).getPublicKey(), caPub), "SDK fromTLV != CA");
        check(ecdsaVerify(ca, certHash, certR, certS), "cert signature does not verify");

        // ---- card: personalize with the fixed identity, INIT so GET STATUS has a body ----------
        ExposedRuntime runtime = new ExposedRuntime();
        CardSimulator sim = Card40Factory.newCard(runtime, cert);
        CardChannel ch = channel(sim);
        KeycardCommandSet setup = new KeycardCommandSet(ch, Collections.singletonList(caPub), Collections.emptyList());
        setup.select().checkOK();
        setup.init(PIN, null, PUK, new byte[0], (byte) 0, (byte) 0).checkOK();

        // ---- b. handshake --------------------------------------------------------------------
        byte[] selectCmd = new APDUCommand(0x00, 0xA4, 4, 0, CardInstall.KEYCARD_INST).serialize();
        byte[] selectResp = sim.transmitCommand(selectCmd);
        check(sw(selectResp) == 0x9000, "SELECT failed");

        SecureChannelV2 host = new SecureChannelV2(Collections.singletonList(caPub), Collections.emptyList());
        host.setCardCertificate(tlvValue(selectResp, (byte) 0x8A));

        byte[] hostEphPub = DOMAIN.getG().multiply(new BigInteger(1, hostEphPriv)).normalize().getEncoded(false);
        byte[] openCmd = new APDUCommand(0x80, 0x10, 0, 0, concat(salt, hostEphPub)).serialize();

        pinNextRandom(runtime, cardEphPriv);
        byte[] openResp = sim.transmitCommand(openCmd);
        check(sw(openResp) == 0x9000, "OPEN SECURE CHANNEL failed: " + hex(openResp));
        byte[] openData = Arrays.copyOf(openResp, openResp.length - 2);
        byte[] cardEphPub = Arrays.copyOf(openData, 65);
        byte[] cardSig = Arrays.copyOfRange(openData, 65, openData.length);
        check(Arrays.equals(cardEphPub,
                DOMAIN.getG().multiply(new BigInteger(1, cardEphPriv)).normalize().getEncoded(false)),
                "card did not use the pinned ephemeral key");

        setField(host, "clientEphPub", hostEphPub);
        Method process = SecureChannelV2.class.getDeclaredMethod("processHandshakeResponse",
                byte[].class, PrivateKey.class, byte[].class);
        process.setAccessible(true);
        process.invoke(host, salt, privateKey(hostEphPriv), openData); // verifies the card signature

        byte[] sharedX = DOMAIN.getCurve().decodePoint(cardEphPub).multiply(new BigInteger(1, hostEphPriv))
                .normalize().getAffineXCoord().getEncoded();
        byte[] sharedXCard = DOMAIN.getCurve().decodePoint(hostEphPub).multiply(new BigInteger(1, cardEphPriv))
                .normalize().getAffineXCoord().getEncoded();
        check(Arrays.equals(sharedX, sharedXCard), "ECDH asymmetric");
        byte[] okm = new byte[32];
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedX, salt, LABEL));
        hkdf.generateBytes(okm, 0, okm.length);
        byte[] keyH2C = Arrays.copyOf(okm, 16);
        byte[] keyC2H = Arrays.copyOfRange(okm, 16, 32);
        check(Arrays.equals(keyH2C, sdkKey(host, "keyH2C")), "SDK keyH2C != HKDF");
        check(Arrays.equals(keyC2H, sdkKey(host, "keyC2H")), "SDK keyC2H != HKDF");

        byte[] transcript = concat(LABEL, salt, hostEphPub, cardEphPub);
        byte[] transcriptHash = sha256(transcript);
        BigInteger[] rs = derToRs(cardSig);
        check(ecdsaVerify(identity, transcriptHash, unsigned32(rs[0]), unsigned32(rs[1])),
                "card transcript signature does not verify");

        // ---- c. CCM: two round trips (nonce 0, nonce 1), wrapped by the SDK, answered by the applet
        Map<String, Object> ccm = new LinkedHashMap<>();
        byte[] getStatus = {(byte) 0x80, (byte) 0xF2, 0x00, 0x00, 0x00};
        for (int nonce = 0; nonce < 2; nonce++) {
            byte[] outer = host.protectedCommand(0x80, 0xF2, 0x00, 0x00, new byte[0]).serialize();
            byte[] expectedCt = ccm(true, keyH2C, nonce, getStatus);
            check(Arrays.equals(outer, concat(new byte[] {(byte) 0x80, 0x18, 0x00, 0x00, (byte) expectedCt.length},
                    expectedCt)), "SDK command != BC CCM at nonce " + nonce);
            byte[] cardResp = sim.transmitCommand(outer);
            check(sw(cardResp) == 0x9000, "outer SW != 9000");
            byte[] respCt = Arrays.copyOf(cardResp, cardResp.length - 2);
            byte[] respPlain = ccm(false, keyC2H, nonce, respCt);
            APDUResponse sdkPlain = host.transmit(new CardChannel() {
                @Override public APDUResponse send(APDUCommand c) { return new APDUResponse(cardResp); }
                @Override public boolean isConnected() { return true; }
            }, null);
            check(Arrays.equals(respPlain, sdkPlain.getBytes()), "SDK response != BC CCM at nonce " + nonce);
            check(sw(respPlain) == 0x9000 && respPlain[0] == (byte) 0xA3, "unexpected GET STATUS reply");
            check(Arrays.equals(ccm(true, keyC2H, nonce, respPlain), respCt), "CCM re-encrypt mismatch");

            Map<String, Object> rt = new LinkedHashMap<>();
            rt.put("nonce", hex(nonceBytes(nonce)));
            rt.put("inner_command", hex(getStatus));
            rt.put("outer_command", hex(outer));
            rt.put("response_plaintext", hex(respPlain));
            rt.put("response_outer", hex(cardResp));
            ccm.put("nonce_" + nonce, rt);
        }

        // ---- JSON ----------------------------------------------------------------------------
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("notes", new String[] {
            "Generated by tools/gen-scv2-vectors.sh: real status-keycard applet 4.0.1 (37393a2) in jcardsim"
                + " driven by the real host SDK status-keycard-java lib:4.0.0; randomness pinned, every value"
                + " cross-checked with BouncyCastle lightweight primitives.",
            "Regenerating changes only certificate.cert (r,s,v: the SDK's CA signature uses a random k) and"
                + " handshake.card_signature_der (applet ECDSA uses a random k); all other values are fixed.",
            "Keys are secp256k1; private key of a label = SHA256(UTF-8 label). Public keys: 33-byte compressed"
                + " or 65-byte uncompressed (04||X||Y).",
            "certificate.cert = identity_pub(33) || r(32) || s(32) || v(1) = 98 bytes, CA signature over"
                + " SHA256(identity_pub). v is the RAW recovery id 0..3 (not +27): recovering with v yields the"
                + " CA key; v+27 is invalid. The SDK left-strips zero bytes of r/s/priv without padding, so"
                + " fields with a leading 0x00 would be short; the simulator redraws until full width.",
            "Handshake: OPEN SECURE CHANNEL = 80 10 00 00 61 || salt(32) || host_eph_pub(65); response ="
                + " card_eph_pub(65) || DER ECDSA signature || 9000. shared_x = X of ECDH (32 bytes);"
                + " OKM = HKDF-SHA256(salt=salt, ikm=shared_x, info='sc_v2_ccm', L=32); key_h2c = OKM[0..16),"
                + " key_c2h = OKM[16..32). transcript = 'sc_v2_ccm' || salt || host_eph_pub || card_eph_pub,"
                + " signed (SHA256 prehash) with the card identity key from the cert.",
            "CCM: AES-128-CCM, 8-byte tag, 13-byte nonce = big-endian message counter, no AAD (the outer header"
                + " is not authenticated). Command: CT = CCM(key_h2c, nonce, CLA INS P1 P2 Lc data) (Lc always"
                + " present), sent as 80 18 00 00 len(CT) CT. Response: CCM(key_c2h, same nonce, data || inner SW)"
                + " || outer 9000. The counter starts at 0 after OPEN SECURE CHANNEL and increments once per"
                + " command/response pair (the response reuses the command's nonce).",
            "Card state for the CCM round trips: INIT with PIN " + PIN + ", PUK " + PUK + ", default retry"
                + " counters, no key loaded; inner command is GET STATUS (application)."
        });
        Map<String, Object> keys = new LinkedHashMap<>();
        keys.put("test_ca_label", "keycard-qt simulator test CA");
        keys.put("test_ca_priv", hex(priv(ca)));
        keys.put("test_ca_pub", hex(caPub));
        keys.put("untrusted_ca_label", "keycard-qt simulator untrusted CA");
        keys.put("untrusted_ca_priv", hex(priv(untrustedCa)));
        keys.put("untrusted_ca_pub", hex(compressed(untrustedCa)));
        keys.put("identity_label", "keycard-qt vector identity");
        keys.put("identity_priv", hex(priv(identity)));
        keys.put("identity_pub", hex(identPub));
        root.put("keys", keys);

        Map<String, Object> c = new LinkedHashMap<>();
        c.put("cert", hex(certBytes));
        c.put("signed_hash", hex(certHash));
        c.put("r", hex(certR));
        c.put("s", hex(certS));
        c.put("v", v);
        c.put("v_encoding", "raw recovery id 0..3");
        c.put("select_command", hex(selectCmd));
        c.put("select_response", hex(selectResp));
        root.put("certificate", c);

        Map<String, Object> h = new LinkedHashMap<>();
        h.put("salt", hex(salt));
        h.put("host_eph_label", "host eph");
        h.put("host_eph_priv", hex(hostEphPriv));
        h.put("host_eph_pub", hex(hostEphPub));
        h.put("card_eph_label", "card eph");
        h.put("card_eph_priv", hex(cardEphPriv));
        h.put("card_eph_pub", hex(cardEphPub));
        h.put("open_command", hex(openCmd));
        h.put("open_response", hex(openResp));
        h.put("shared_x", hex(sharedX));
        h.put("okm", hex(okm));
        h.put("key_h2c", hex(keyH2C));
        h.put("key_c2h", hex(keyC2H));
        h.put("transcript", hex(transcript));
        h.put("transcript_hash", hex(transcriptHash));
        h.put("card_signature_der", hex(cardSig));
        root.put("handshake", h);
        root.put("ccm", ccm);

        StringBuilder sb = new StringBuilder();
        json(sb, root, 0);
        System.out.println(sb);
    }

    // ---- applet / SDK plumbing ---------------------------------------------------------------

    private static CardChannel channel(CardSimulator sim) {
        return new CardChannel() {
            @Override
            public APDUResponse send(APDUCommand cmd) throws java.io.IOException {
                return new APDUResponse(sim.transmitCommand(cmd.serialize()));
            }
            @Override
            public boolean isConnected() {
                return true;
            }
        };
    }

    /** Make the keycard applet's next 32-byte random draw return @p value (then fall back). */
    private static void pinNextRandom(ExposedRuntime runtime, byte[] value) throws Exception {
        Applet applet = runtime.appletAt(com.licel.jcardsim.utils.AIDUtil.create(CardInstall.KEYCARD_INST));
        Object crypto = getField(applet, "crypto");
        RandomData real = (RandomData) getField(crypto, "random");
        setField(crypto, "random", new RandomData() {
            private byte[] pending = value.clone();
            @Override
            public void generateData(byte[] buf, short off, short len) throws CryptoException {
                if (pending != null && len == pending.length) {
                    System.arraycopy(pending, 0, buf, off, len);
                    pending = null;
                } else {
                    real.generateData(buf, off, len);
                }
            }
            @Override
            public short nextBytes(byte[] buf, short off, short len) throws CryptoException {
                return real.nextBytes(buf, off, len);
            }
            @Override
            public void setSeed(byte[] buf, short off, short len) {
                real.setSeed(buf, off, len);
            }
            @Override
            public byte getAlgorithm() {
                return real.getAlgorithm();
            }
        });
    }

    private static byte[] sdkKey(SecureChannelV2 host, String name) throws Exception {
        return ((javax.crypto.spec.SecretKeySpec) getField(host, name)).getEncoded();
    }

    private static Object getField(Object o, String name) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(o);
    }

    private static void setField(Object o, String name, Object value) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(o, value);
    }

    private static PrivateKey privateKey(byte[] d) throws Exception {
        org.bouncycastle.jce.spec.ECParameterSpec spec =
                org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
        return java.security.KeyFactory.getInstance("EC", "BC")
                .generatePrivate(new org.bouncycastle.jce.spec.ECPrivateKeySpec(new BigInteger(1, d), spec));
    }

    // ---- independent BouncyCastle checks -----------------------------------------------------

    private static byte[] ccm(boolean encrypt, byte[] key, int nonce, byte[] in) throws Exception {
        CCMBlockCipher c = new CCMBlockCipher(new AESEngine());
        c.init(encrypt, new AEADParameters(new KeyParameter(key), 64, nonceBytes(nonce)));
        byte[] out = new byte[c.getOutputSize(in.length)];
        int n = c.processBytes(in, 0, in.length, out, 0);
        n += c.doFinal(out, n);
        return Arrays.copyOf(out, n);
    }

    private static byte[] nonceBytes(long counter) {
        byte[] n = new byte[13];
        for (int i = 12; i >= 0 && counter != 0; i--, counter >>>= 8) {
            n[i] = (byte) counter;
        }
        return n;
    }

    private static boolean ecdsaVerify(KeyPair kp, byte[] hash, byte[] r, byte[] s) {
        ECDSASigner v = new ECDSASigner();
        v.init(false, new ECPublicKeyParameters(DOMAIN.getCurve().decodePoint(compressed(kp)), DOMAIN));
        return v.verifySignature(hash, new BigInteger(1, r), new BigInteger(1, s));
    }

    /** SEC1 4.1.6 public key recovery; null if @p recId does not yield a point. */
    private static byte[] recover(int recId, byte[] hash, byte[] r, byte[] s) {
        BigInteger n = DOMAIN.getN();
        BigInteger br = new BigInteger(1, r);
        BigInteger x = br.add(BigInteger.valueOf(recId / 2).multiply(n));
        BigInteger p = CURVE.getCurve().getField().getCharacteristic();
        if (recId < 0 || x.compareTo(p) >= 0) {
            return null;
        }
        byte[] enc = new byte[33];
        enc[0] = (byte) ((recId & 1) == 1 ? 0x03 : 0x02);
        System.arraycopy(unsigned32(x), 0, enc, 1, 32);
        ECPoint bigR;
        try {
            bigR = DOMAIN.getCurve().decodePoint(enc);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!bigR.multiply(n).isInfinity()) {
            return null;
        }
        BigInteger e = new BigInteger(1, hash);
        BigInteger rInv = br.modInverse(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(DOMAIN.getG(), e.negate().mod(n).multiply(rInv).mod(n),
                bigR, new BigInteger(1, s).multiply(rInv).mod(n));
        return q.normalize().getEncoded(true);
    }

    private static BigInteger[] derToRs(byte[] der) {
        ASN1Sequence seq = ASN1Sequence.getInstance(der);
        return new BigInteger[] {
            ASN1Integer.getInstance(seq.getObjectAt(0)).getValue(),
            ASN1Integer.getInstance(seq.getObjectAt(1)).getValue()};
    }

    // ---- small helpers -----------------------------------------------------------------------

    private static void check(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException("vector self-check failed: " + what);
        }
    }

    private static byte[] compressed(KeyPair kp) {
        return ((ECPublicKey) kp.getPublic()).getQ().getEncoded(true);
    }

    private static byte[] priv(KeyPair kp) {
        return unsigned32(((ECPrivateKey) kp.getPrivate()).getD());
    }

    private static byte[] unsigned32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(b.length, 32);
        System.arraycopy(b, b.length - n, out, 32 - n, n);
        return out;
    }

    private static byte[] sha256(String s) throws Exception {
        return sha256(s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] sha256(byte[] b) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(b);
    }

    private static int sw(byte[] resp) {
        return ((resp[resp.length - 2] & 0xFF) << 8) | (resp[resp.length - 1] & 0xFF);
    }

    /** Value of the first @p tag inside the SELECT response's A4 template. */
    private static byte[] tlvValue(byte[] resp, byte tag) {
        int i = 1;
        if (resp[i] == (byte) 0x81) {
            i++;
        }
        i++; // template length
        while (i < resp.length - 2) {
            byte t = resp[i];
            int len = resp[i + 1] & 0xFF;
            if (t == tag) {
                return Arrays.copyOfRange(resp, i + 2, i + 2 + len);
            }
            i += 2 + len;
        }
        throw new IllegalStateException("tag " + tag + " not in SELECT response");
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.write(p, 0, p.length);
        }
        return out.toByteArray();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte value : b) {
            sb.append(Character.forDigit((value >> 4) & 0xF, 16)).append(Character.forDigit(value & 0xF, 16));
        }
        return sb.toString();
    }

    private static void json(StringBuilder sb, Object v, int indent) {
        String pad = "  ".repeat(indent + 1);
        if (v instanceof Map) {
            sb.append("{\n");
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!first) {
                    sb.append(",\n");
                }
                first = false;
                sb.append(pad).append('"').append(e.getKey()).append("\": ");
                json(sb, e.getValue(), indent + 1);
            }
            sb.append('\n').append("  ".repeat(indent)).append('}');
        } else if (v instanceof String[]) {
            sb.append("[\n");
            String[] a = (String[]) v;
            for (int i = 0; i < a.length; i++) {
                sb.append(pad);
                json(sb, a[i], indent + 1);
                sb.append(i + 1 < a.length ? ",\n" : "\n");
            }
            sb.append("  ".repeat(indent)).append(']');
        } else if (v instanceof Number) {
            sb.append(v);
        } else {
            sb.append('"').append(v.toString().replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
        }
    }
}
