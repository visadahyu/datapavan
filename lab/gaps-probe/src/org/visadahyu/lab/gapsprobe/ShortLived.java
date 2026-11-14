package org.visadahyu.lab.gapsprobe;

import java.io.Closeable;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * short-lived: sockets to the lab's server that close at once, against sockets kept open (the
 * control). Steps: "udp-closed", "udp-open", "tcp-closed", "tcp-open". Each trial records its local
 * port, by which the run finds the flow Watch recorded and the owner Android named for it.
 */
final class ShortLived {
    private static final byte[] PAYLOAD = "gaps-short-lived".getBytes(StandardCharsets.US_ASCII);

    private ShortLived() {}

    static void run(String step, int trials) throws Exception {
        boolean udp = step.startsWith("udp");
        boolean closed = step.endsWith("closed");
        InetAddress host = InetAddress.getByName(GapsProbe.LAB_HOST);
        List<Closeable> open = new ArrayList<>();
        for (int i = 0; i < trials; i++) {
            int port;
            if (udp) {
                DatagramSocket socket = new DatagramSocket();
                port = socket.getLocalPort();
                socket.send(new DatagramPacket(PAYLOAD, PAYLOAD.length, host, 8796));
                if (closed) socket.close(); else open.add(socket);
            } else {
                SocketChannel channel = SocketChannel.open();
                channel.configureBlocking(false);
                channel.connect(new InetSocketAddress(host, 8792));
                port = channel.socket().getLocalPort();
                if (closed) channel.close(); else open.add(channel);
            }
            GapsProbe.out("short-lived", step, "trial=" + i + " local=" + port);
            Thread.sleep(100);
        }
        Thread.sleep(3_000);
        for (Closeable socket : open) socket.close();
    }
}
