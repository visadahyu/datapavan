package org.visadahyu.datapavan.blockfixture;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * W8 part 3a's blocking fixture (scripts/verify-blocking.sh, ADR 0053): one action per start, by the extra "action",
 * to the extras "name", "host" and "port". Each logs "ACTION RESULT" under the tag DatapavanBlockingFixture, then
 * "done":
 *
 * <ul>
 *   <li>{@code lookup}: the name looked up through Android's resolver: "lookup ok ADDRESS" or "lookup none";</li>
 *   <li>{@code hello}: a TLS hello for the name to host:port, sent in two segments 150 ms apart, as a post-quantum
 *       hello spans two: "hello ok N" with the bytes the lab echoed, or "hello reset", "hello closed",
 *       "hello refused";</li>
 *   <li>{@code http}: a plain GET whose Host is the name, sent in two segments: the same results;</li>
 *   <li>{@code quic}: the two datagrams of a QUIC Initial whose hello names the name, given in hex as the extras
 *       "first" and "second" (written by the engine's own test helper, scripts/blocking-fixture/quic-hello.hex), to
 *       host:port: "quic unreachable" when an ICMP port unreachable came back, "quic ok N" for the lab's echo, or
 *       "quic silent".</li>
 * </ul>
 */
public class BlockActivity extends Activity {
    private static final String TAG = "DatapavanBlockingFixture";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        final String action = String.valueOf(getIntent().getStringExtra("action"));
        new Thread(() -> {
            String result;
            try {
                result = run(action);
            } catch (Exception e) {
                result = "failed " + e.getClass().getSimpleName();
            }
            Log.i(TAG, action + " " + result);
            Log.i(TAG, "done");
            runOnUiThread(this::finish);
        }).start();
    }

    private String extra(String name) {
        String value = getIntent().getStringExtra(name);
        return value == null ? "" : value;
    }

    private String run(String action) throws Exception {
        switch (action) {
            case "lookup": return lookup();
            case "hello": return stream(clientHello(extra("name")));
            case "http":
                return stream(("GET /collect HTTP/1.1\r\nHost: " + extra("name") + "\r\nUser-Agent: fixture\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            case "quic": return quic();
            default: return "failed unknown";
        }
    }

    private String lookup() {
        try {
            InetAddress[] all = InetAddress.getAllByName(extra("name"));
            StringBuilder out = new StringBuilder("ok");
            for (InetAddress address : all) out.append(' ').append(address.getHostAddress());
            return out.toString();
        } catch (UnknownHostException e) {
            return "none";
        }
    }

    /** Sends [bytes] in two segments 150 ms apart, then reads the lab's echo for up to 3 s. */
    private String stream(byte[] bytes) throws IOException {
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(extra("host"), Integer.parseInt(extra("port"))), 10_000);
        } catch (IOException e) {
            return "refused";
        }
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(3_000);
        try {
            OutputStream out = socket.getOutputStream();
            int half = bytes.length / 2;
            out.write(bytes, 0, half);
            out.flush();
            Thread.sleep(150);
            out.write(bytes, half, bytes.length - half);
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[bytes.length + 64];
            int got = 0;
            while (got < bytes.length) {
                int n = in.read(buffer, got, buffer.length - got);
                if (n < 0) return got == 0 ? "closed" : "ok " + got;
                got += n;
            }
            return "ok " + got;
        } catch (SocketTimeoutException e) {
            return "silent";
        } catch (IOException e) {
            return "reset";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "interrupted";
        } finally {
            socket.close();
        }
    }

    private String quic() throws IOException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(extra("host"), Integer.parseInt(extra("port"))));
            socket.setSoTimeout(3_000);
            for (String part : new String[] {extra("first"), extra("second")}) {
                byte[] datagram = hex(part);
                socket.send(new DatagramPacket(datagram, datagram.length));
                sleep(100);
            }
            byte[] buffer = new byte[2048];
            try {
                DatagramPacket answer = new DatagramPacket(buffer, buffer.length);
                socket.receive(answer);
                return "ok " + answer.getLength();
            } catch (PortUnreachableException e) {
                return "unreachable";
            } catch (SocketTimeoutException e) {
                return "silent";
            }
        } catch (PortUnreachableException e) {
            return "unreachable";
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static byte[] hex(String text) {
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    /** A TLS 1.3 ClientHello for [name], as scripts/proxy-fixture's, padded past 1,500 bytes as a post-quantum one. */
    static byte[] clientHello(String name) throws IOException {
        byte[] host = name.getBytes(StandardCharsets.US_ASCII);
        byte[] random = new byte[32];
        RANDOM.nextBytes(random);
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        extensions.write(new byte[] {0, 0});
        writeShort(extensions, host.length + 5);
        writeShort(extensions, host.length + 3);
        extensions.write(0);
        writeShort(extensions, host.length);
        extensions.write(host);
        extensions.write(new byte[] {0, 43, 0, 3, 2, 3, 4});
        // A padding extension (RFC 7685) the size of a post-quantum key share, so the hello spans two segments.
        extensions.write(new byte[] {0, 21});
        writeShort(extensions, 1_216);
        extensions.write(new byte[1_216]);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(new byte[] {3, 3});
        body.write(random);
        body.write(0);
        body.write(new byte[] {0, 2, 0x13, 0x01, 1, 0});
        writeShort(body, extensions.size());
        body.write(extensions.toByteArray());
        ByteArrayOutputStream record = new ByteArrayOutputStream();
        record.write(new byte[] {0x16, 3, 1});
        writeShort(record, body.size() + 4);
        record.write(1);
        record.write(0);
        writeShort(record, body.size());
        record.write(body.toByteArray());
        return record.toByteArray();
    }

    private static void writeShort(ByteArrayOutputStream out, int value) {
        out.write((value >> 8) & 0xff);
        out.write(value & 0xff);
    }
}
