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

/**
 * Card recipe for Status Keycard applet <b>3.2</b> (status-keycard {@code 72e9574}, {@code
 * SecureChannel} v1 / classic password pairing) — the generation that matches keycard-qt {@code
 * df00b931} (which sends {@code INS_PAIR 0x12}).
 *
 * <p>{@code newCard()} is <b>install-only</b>: a freshly installed applet is already in the
 * post-FactoryReset / blank state (no PIN/PUK, no pairing, no key) — the app's "empty keycard". 3.2
 * has no Ident-cert gate (unlike 4.0), so no personalization is needed and the SDK/BouncyCastle are
 * not on the 3.2 path. The card's real state then evolves through the app's own APDUs (INIT, pair,
 * load key, factory reset), persisted by jcardsim for the card's lifetime.
 */
public final class Card32Factory implements CardFactory {

    @Override
    public CardSimulator newCard() {
        ExposedRuntime runtime = new ExposedRuntime();
        CardSimulator sim = new CardSimulator(runtime);
        CardInstall.install(sim, CardInstall.KEYCARD_AID, KeycardApplet.class, CardInstall.KEYCARD_INST, null);
        CardInstall.install(sim, CardInstall.NDEF_AID, NDEFApplet.class, CardInstall.NDEF_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.install(sim, CardInstall.CASH_AID, CashApplet.class, CardInstall.CASH_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.install(sim, CardInstall.IDENT_AID, IdentApplet.class, CardInstall.IDENT_INST, CardInstall.SECONDARY_PARAMS);
        CardInstall.assignUniqueInstanceUid(runtime); // unique UID per card, like real hardware
        return sim; // blank / factory-reset state — no INIT, no personalization
    }
}
