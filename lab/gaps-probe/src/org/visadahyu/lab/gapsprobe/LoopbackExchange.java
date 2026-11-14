package org.visadahyu.lab.gapsprobe;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * loopback: two apps exchange a fixed payload over 127.0.0.1 and ::1. The probe runs "listen" and
 * answers one connection on each address; the same code built as a second app (build.sh --peer, its
 * own UID) runs "connect". The run checks Watch's flows and the emulator's capture for the payload.
 */
final class LoopbackExchange {
    static final int PORT_V4 = 8794;
    static final int PORT_V6 = 8795;
    private static final String ASK = "gaps-loopback-ask";
    private static final String ANSWER = "gaps-loopback-answer";

    private LoopbackExchange() {}

    static void run(String step) throws Exception {
        if (step.equals("listen")) {
            try (ServerSocket v4 = new ServerSocket(PORT_V4, 1, InetAddress.getByName("127.0.0.1"));
                 ServerSocket v6 = new ServerSocket(PORT_V6, 1, InetAddress.getByName("::1"))) {
                v4.setSoTimeout(60_000);
                v6.setSoTimeout(60_000);
                GapsProbe.out("loopback", step, "ready");
                answer(step, "v4", v4);
                answer(step, "v6", v6);
            }
        } else if (step.equals("connect")) {
            ask(step, "v4", "127.0.0.1", PORT_V4);
            ask(step, "v6", "::1", PORT_V6);
        }
    }

    private static void answer(String step, String family, ServerSocket server) {
        try (Socket socket = server.accept()) {
            socket.setSoTimeout(10_000);
            String line = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine();
            OutputStream out = socket.getOutputStream();
            out.write((ANSWER + "\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            GapsProbe.out("loopback", step, family + " accepted=yes ask=" + (ASK.equals(line) ? "match" : "other"));
        } catch (Exception e) {
            GapsProbe.out("loopback", step, family + " accepted=no error=" + e.getClass().getSimpleName());
        }
    }

    private static void ask(String step, String family, String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName(host), port), 10_000);
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write((ASK + "\n").getBytes(StandardCharsets.US_ASCII));
            String line = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII)).readLine();
            GapsProbe.out("loopback", step, family + " answer=" + (ANSWER.equals(line) ? "match" : "other"));
        } catch (Exception e) {
            GapsProbe.out("loopback", step, family + " answer=none error=" + e.getClass().getSimpleName());
        }
    }
}
