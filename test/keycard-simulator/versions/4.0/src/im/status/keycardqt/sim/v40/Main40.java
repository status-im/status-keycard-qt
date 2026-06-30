// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim.v40;

import im.status.keycardqt.sim.SimProtocolServer;

/** Entry point for the applet-4.0 simulator. Runs the version-neutral server with the 4.0 recipe. */
public final class Main40 {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9025;
        new SimProtocolServer(new Card40Factory()).serve(port);
    }
}
