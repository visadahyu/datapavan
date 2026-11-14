package org.visadahyu.lab.gapsfixture;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * loopback: whether this app, which holds no INTERNET permission, can open a socket to the probe's
 * loopback port at all. It sends nothing: the connection is closed as soon as it opens.
 */
final class FixtureNoSocket {
    private FixtureNoSocket() {}

    static void attempt() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 8794), 5_000);
            GapsFixture.out("socket v4 answer=opened");
        } catch (Exception e) {
            String message = String.valueOf(e.getMessage()).replaceAll("\\s+", "_");
            GapsFixture.out("socket v4 answer=refused error=" + e.getClass().getSimpleName() + ":"
                    + (message.length() > 120 ? message.substring(0, 120) : message));
        }
    }
}
