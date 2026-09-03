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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.Security;

/**
 * Card recipe for Status Keycard applet <b>4.0</b> (status-keycard {@code 9973c3d}, {@code
 * SecureChannelV2} / certificate-based). The 4.0 keycard applet rejects every APDU (even SELECT, SW
 * {@code 6985}) until the IdentApplet holds a CA-signed identity certificate (factory
 * personalization), so {@code newCard()} installs the applets and stores one using a test CA.
 *
 * <p><b>Not wired to the app yet:</b> keycard-qt (introduced in commit {@code df00b931}) speaks classic password pairing
 * ({@code INS_PAIR 0x12}), which SecureChannelV2 dropped — so this version is kept as a ready scaffold
 * and only becomes drivable once keycard-qt gains SecureChannelV2 support (the future "Use tag 4.0"
 * switch). The card is still blank (no key) — only the factory identity cert is provisioned.
 */
public final class Card40Factory implements CardFactory {

    // One test CA for all simulated cards (its identity is not verified by keycard-qt).
    private static final KeyPair CA;
    static {
        Security.addProvider(new BouncyCastleProvider());
        CA = Certificate.generateIdentKeyPair();
    }

    @Override
    public CardSimulator newCard() {
        ExposedRuntime runtime = new ExposedRuntime();
        CardSimulator sim = new CardSimulator(runtime);
        CardInstall.install(sim, CardInstall.KEYCARD_AID, KeycardApplet.class, CardInstall.KEYCARD_INST, null);
        CardInstall.install(sim, CardInstall.NDEF_AID, NDEFApplet.class, CardInstall.NDEF_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.install(sim, CardInstall.CASH_AID, CashApplet.class, CardInstall.CASH_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.install(sim, CardInstall.IDENT_AID, IdentApplet.class, CardInstall.IDENT_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.assignUniqueInstanceUid(runtime); // unique UID per card, like real hardware
        personalize(sim);
        return sim;
    }

    /** Factory personalization: store a CA-signed identity certificate in the IdentApplet. */
    private static void personalize(CardSimulator sim) {
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
            ident.storeData(Certificate.generateNewCertificate(CA).toStoreData()).checkOK();
        } catch (Exception e) {
            throw new RuntimeException("IdentApplet personalization failed", e);
        }
    }
}
