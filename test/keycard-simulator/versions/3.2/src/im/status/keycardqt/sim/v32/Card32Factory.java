// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim.v32;

import com.licel.jcardsim.smartcardio.CardSimulator;

import im.status.keycard.KeycardApplet;
import im.status.keycard.NDEFApplet;
import im.status.keycard.CashApplet;
import im.status.keycard.IdentApplet;

import im.status.keycardqt.sim.CardFactory;
import im.status.keycardqt.sim.CardInstall;
import im.status.keycardqt.sim.ExposedRuntime;
import im.status.keycardqt.sim.IdentCertificates;
import im.status.keycardqt.sim.IdentityCardSimulator;

/**
 * Card recipe for Status Keycard applet <b>3.2</b> (status-keycard {@code 72e9574}, {@code
 * SecureChannel} v1 / classic password pairing) — the generation introduced in the keycard-qt
 * commit {@code df00b931} (which sends {@code INS_PAIR 0x12}).
 *
 * <p>{@code newCard()} installs the applets — already the post-FactoryReset / blank state (no PIN/PUK,
 * no pairing, no key), the app's "empty keycard" — and stores a factory identity certificate, which
 * 3.x hands out via IDENTIFY. It is signed by the trusted test CA, or by the untrusted CA for an
 * UNTRUSTED card (see {@link IdentCertificates}). The card's real state then evolves through the app's
 * own APDUs (INIT, pair, load key, factory reset), persisted by jcardsim for the card's lifetime.
 */
public final class Card32Factory implements CardFactory {

    @Override
    public String appletVersion() {
        return "3.2";
    }

    @Override
    public CardSimulator newCard(boolean untrusted) {
        ExposedRuntime runtime = new ExposedRuntime();
        byte[] identity = IdentCertificates.newStoreData(
                untrusted ? IdentCertificates.UNTRUSTED_CA : IdentCertificates.TEST_CA);
        return IdentityCardSimulator.create(runtime, sim -> {
            CardInstall.install(sim, CardInstall.KEYCARD_AID, KeycardApplet.class, CardInstall.KEYCARD_INST, null);
            CardInstall.install(sim, CardInstall.NDEF_AID, NDEFApplet.class, CardInstall.NDEF_INST, CardInstall.SECONDARY_PARAMS);
            CardInstall.install(sim, CardInstall.CASH_AID, CashApplet.class, CardInstall.CASH_INST, CardInstall.SECONDARY_PARAMS);
            CardInstall.install(sim, CardInstall.IDENT_AID, IdentApplet.class, CardInstall.IDENT_INST, CardInstall.SECONDARY_PARAMS);
            CardInstall.assignUniqueInstanceUid(runtime); // unique UID per card, like real hardware
        }, identity); // blank / factory-reset state — no INIT, no pairing, no key
    }
}
