package org.visadahyu.datapavan.workload;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Does what the extras ask, in this app's own process and so under its own UID, then finishes:
 * "name" is looked up through Android's resolver, "tcp" (host:port) gets an HTTP request for /ping,
 * "udp" (host:port) gets a datagram and waits for its echo, and "stun" (first,second:port) resolves two
 * names, then sends a STUN Binding request to each on one port back to back, from one socket, and waits
 * for both responses, each from the name's own address with its own transaction ID (ADR 0044, unit 9b). Each
 * result is one line of logcat under the tag DatapavanWorkload, and "done" ends them.
 */
public final class WorkActivity extends Activity {
    private static final String TAG = "DatapavanWorkload";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String name = getIntent().getStringExtra("name");
        String tcp = getIntent().getStringExtra("tcp");
        String udp = getIntent().getStringExtra("udp");
        String stun = getIntent().getStringExtra("stun");
        new Thread(() -> {
            if (name != null) resolve(name);
            if (tcp != null) tcp(tcp);
            if (udp != null) udp(udp);
            if (stun != null) stun(stun);
            Log.i(TAG, "done");
            runOnUiThread(this::finish);
        }, "workload").start();
    }

    private static void resolve(String name) {
        try {
            Log.i(TAG, "resolved " + name + " " + InetAddress.getByName(name).getHostAddress());
        } catch (Exception e) {
            Log.i(TAG, "resolve " + name + " failed: " + e);
        }
    }

    private static void tcp(String target) {
        String[] hostPort = target.split(":", 2);
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(hostPort[0], Integer.parseInt(hostPort[1])), 8000);
            socket.setSoTimeout(8000);
            socket.getOutputStream().write("GET /ping HTTP/1.0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream answer = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            for (int n; (n = in.read(buffer)) > 0; ) answer.write(buffer, 0, n);
            boolean pong = answer.toString("US-ASCII").contains("pong");
            Log.i(TAG, "tcp " + target + (pong ? " pong" : " no pong"));
        } catch (Exception e) {
            Log.i(TAG, "tcp " + target + " failed: " + e);
        }
    }

    /**
     * Sends a STUN Binding request (RFC 8489) to each of the two names in [target], "first,second:port",
     * from one socket, back to back once both names are resolved, so that both stand-ins wait on the
     * port when the first answer comes back; logs "stun TARGET both" once each name's address answered
     * with a Binding success response carrying the transaction ID sent to it, or "stun TARGET got N"
     * with how many did within five seconds.
     */
    private static void stun(String target) {
        String[] namesPort = target.split(":", 2);
        String[] names = namesPort[0].split(",", 2);
        int port = Integer.parseInt(namesPort[1]);
        java.util.Map<InetSocketAddress, byte[]> asked = new java.util.LinkedHashMap<>();
        java.util.Set<InetSocketAddress> answered = new java.util.HashSet<>();
        java.security.SecureRandom random = new java.security.SecureRandom();
        try (DatagramSocket socket = new DatagramSocket()) {
            // Both names first: a lookup between the two requests would let the first answer come back
            // before the second stand-in waited, which unit 9 handled too.
            for (String name : names) {
                byte[] id = new byte[12];
                random.nextBytes(id);
                asked.put(new InetSocketAddress(InetAddress.getByName(name), port), id);
            }
            java.util.List<DatagramPacket> requests = new java.util.ArrayList<>();
            for (java.util.Map.Entry<InetSocketAddress, byte[]> entry : asked.entrySet()) {
                byte[] request = new byte[20];
                request[1] = 0x01;
                request[4] = 0x21;
                request[5] = 0x12;
                request[6] = (byte) 0xa4;
                request[7] = 0x42;
                System.arraycopy(entry.getValue(), 0, request, 8, 12);
                requests.add(new DatagramPacket(request, request.length, entry.getKey()));
            }
            for (DatagramPacket request : requests) socket.send(request);
            long until = System.currentTimeMillis() + 5000;
            byte[] in = new byte[1500];
            while (answered.size() < asked.size() && System.currentTimeMillis() < until) {
                socket.setSoTimeout((int) Math.max(1, until - System.currentTimeMillis()));
                DatagramPacket reply = new DatagramPacket(in, in.length);
                try {
                    socket.receive(reply);
                } catch (java.net.SocketTimeoutException e) {
                    break;
                }
                InetSocketAddress from = (InetSocketAddress) reply.getSocketAddress();
                byte[] id = asked.get(from);
                boolean success = reply.getLength() >= 20 && in[0] == 0x01 && in[1] == 0x01;
                if (id != null && success && java.util.Arrays.equals(java.util.Arrays.copyOfRange(in, 8, 20), id)) {
                    answered.add(from);
                }
            }
            Log.i(TAG, "stun " + target + (answered.size() == names.length ? " both" : " got " + answered.size()));
        } catch (Exception e) {
            Log.i(TAG, "stun " + target + " failed: " + e);
        }
    }

    private static void udp(String target) {
        String[] hostPort = target.split(":", 2);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            byte[] out = "workload-udp".getBytes(StandardCharsets.US_ASCII);
            InetAddress host = InetAddress.getByName(hostPort[0]);
            socket.send(new DatagramPacket(out, out.length, host, Integer.parseInt(hostPort[1])));
            byte[] in = new byte[512];
            DatagramPacket reply = new DatagramPacket(in, in.length);
            socket.receive(reply);
            boolean echo = new String(in, 0, reply.getLength(), StandardCharsets.US_ASCII).contains("workload-udp");
            Log.i(TAG, "udp " + target + (echo ? " echo" : " no echo"));
        } catch (Exception e) {
            Log.i(TAG, "udp " + target + " failed: " + e);
        }
    }
}
