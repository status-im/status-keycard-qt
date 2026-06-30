// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim;

import com.licel.jcardsim.base.SimulatorRuntime;
import javacard.framework.AID;
import javacard.framework.Applet;

/**
 * A {@link SimulatorRuntime} that exposes the installed applet instance.
 *
 * jcardsim's {@code getApplet(AID)} is {@code protected}; we need the live applet instance so the
 * card factory can give each card a unique instance UID after install (see
 * {@link CardInstall#assignUniqueInstanceUid}). Pass an instance of this to
 * {@code new CardSimulator(runtime)}.
 */
public final class ExposedRuntime extends SimulatorRuntime {
    /** The applet instance registered under @p aid (its instance AID), or null if absent. */
    public Applet appletAt(AID aid) {
        return getApplet(aid);
    }
}
