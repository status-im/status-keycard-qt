// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim;

import com.licel.jcardsim.smartcardio.CardSimulator;

/**
 * Creates a fresh jcardsim card with the Status Keycard applet(s) installed (and, for applet
 * generations that require it, factory-personalized).
 *
 * Implementations are <b>version-specific</b> — the applet jars and host SDK for 3.2 and 4.0 share
 * the same class names with different bytecode/APIs, so each version's recipe is compiled and loaded
 * against only its own libs (see versions/&lt;v&gt;/). {@link SimProtocolServer} is version-neutral and
 * depends only on this interface, never on {@code im.status.keycard.*}.
 */
public interface CardFactory {
    /** The applet generation this factory produces, e.g. {@code "3.2"} or {@code "4.0"}. */
    String appletVersion();

    /**
     * A brand-new card (one fresh CardSimulator per call). With @p untrusted, the card's identity
     * certificate is signed by a CA the client is not expected to trust; versions without an identity
     * certificate throw {@link UnsupportedOperationException} for it.
     */
    CardSimulator newCard(boolean untrusted);
}
