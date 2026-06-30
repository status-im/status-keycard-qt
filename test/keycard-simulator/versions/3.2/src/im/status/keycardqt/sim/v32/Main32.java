// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim.v32;

import im.status.keycardqt.sim.SimProtocolServer;

/** Entry point for the applet-3.2 simulator. Runs the version-neutral server with the 3.2 recipe. */
public final class Main32 {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 9025;
        new SimProtocolServer(new Card32Factory()).serve(port);
    }
}
