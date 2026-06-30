// Copyright (C) 2026 Status Research & Development GmbH
// SPDX-License-Identifier: MIT
package im.status.keycardqt.sim;

import com.licel.jcardsim.smartcardio.CardSimulator;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal APDU-over-TCP server backed by jcardsim running the REAL Status Keycard applet.
 *
 * It exists so the C++ {@code SimulatedChannelBackend} in status-keycard-qt (built with
 * USE_SIMULATED_KEYCARD) can drive a real applet instead of a physical reader.
 *
 * This class is <b>version-neutral</b>: it owns the TCP protocol and the per-id card map, and
 * delegates card creation to a {@link CardFactory} supplied by a per-version entry point (see
 * versions/&lt;v&gt;/src/.../Main*.java). It has no {@code im.status.keycard.*} dependency, so the same
 * protocol code serves any applet generation.
 *
 * Text line protocol (UTF-8, one request and one response per line, space separated):
 *   CREATE &lt;cardId&gt;             -&gt; OK &lt;atrHex&gt;       create card if absent (no-op if present)
 *   RESET  &lt;cardId&gt;             -&gt; OK                 recreate card fresh / blank
 *   ATR    &lt;cardId&gt;             -&gt; OK &lt;atrHex&gt;
 *   APDU   &lt;cardId&gt; &lt;apduHex&gt;    -&gt; OK &lt;responseHex&gt;
 *   PING                          -&gt; OK
 *   &lt;anything else&gt;               -&gt; ERR &lt;message&gt;
 *
 * Card EEPROM state persists for the life of a CardSimulator instance (across the client-side
 * "remove/insert") until RESET recreates it. Cards are independent (e.g. "A", "B") for multi-card
 * flows such as authorize-on-A then load-onto-blank-B.
 */
public final class SimProtocolServer {

    private final CardFactory factory;
    private final Map<String, CardSimulator> cards = new ConcurrentHashMap<>();

    public SimProtocolServer(CardFactory factory) {
        this.factory = factory;
    }

    public void serve(int port) throws Exception {
        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("KeycardSimServer listening on port " + port);
            while (true) {
                final Socket socket = server.accept();
                Thread t = new Thread(() -> handle(socket), "kc-sim-conn");
                t.setDaemon(true);
                t.start();
            }
        }
    }

    private void handle(Socket socket) {
        try (Socket s = socket;
             BufferedReader in = new BufferedReader(
                     new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8))) {
            OutputStream out = s.getOutputStream();
            String line;
            while ((line = in.readLine()) != null) {
                String response;
                try {
                    response = process(line.trim());
                } catch (Throwable e) { // includes jcardsim Errors so they surface as ERR, not a dead socket
                    response = "ERR " + safe(e.toString());
                }
                out.write((response + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (Exception ignored) {
            // connection closed
        }
    }

    private String process(String line) {
        if (line.isEmpty()) {
            return "ERR empty";
        }
        String[] parts = line.split("\\s+");
        String op = parts[0].toUpperCase();
        switch (op) {
            case "PING":
                return "OK";
            case "CREATE": {
                String id = arg(parts, 1);
                CardSimulator sim = cards.computeIfAbsent(id, k -> factory.newCard());
                return "OK " + bytesToHex(sim.getATR());
            }
            case "RESET": {
                String id = arg(parts, 1);
                cards.put(id, factory.newCard());
                return "OK";
            }
            case "ATR": {
                CardSimulator sim = require(arg(parts, 1));
                return "OK " + bytesToHex(sim.getATR());
            }
            case "APDU": {
                CardSimulator sim = require(arg(parts, 1));
                byte[] apdu = hex(arg(parts, 2));
                byte[] resp;
                synchronized (sim) {
                    resp = sim.transmitCommand(apdu);
                }
                return "OK " + bytesToHex(resp);
            }
            default:
                return "ERR unknown op: " + op;
        }
    }

    private CardSimulator require(String id) {
        CardSimulator sim = cards.get(id);
        if (sim == null) {
            throw new IllegalArgumentException("no such card: " + id);
        }
        return sim;
    }

    // ---- helpers ----------------------------------------------------------

    private static String arg(String[] parts, int i) {
        if (i >= parts.length) {
            throw new IllegalArgumentException("missing argument #" + i);
        }
        return parts[i];
    }

    private static String safe(String s) {
        return s == null ? "error" : s.replace('\n', ' ').replace('\r', ' ');
    }

    private static byte[] hex(String s) {
        int len = s.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("odd-length hex");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }

    private static String bytesToHex(byte[] b) {
        if (b == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte value : b) {
            sb.append(Character.forDigit((value >> 4) & 0xF, 16));
            sb.append(Character.forDigit(value & 0xF, 16));
        }
        return sb.toString();
    }
}
