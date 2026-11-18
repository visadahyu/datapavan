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
 * names, then sends a STUN Binding request to each on one port back to back, from one socket, sending each
 * again as a STUN client does until it is answered, and waits for both responses, each from the name's own
 * address with its own transaction ID (ADR 0044, unit 9b). Each result is one line of logcat under the tag
 * DatapavanWorkload, and "done" ends them.
 *
 * For W5's live view (ADR 0046, scripts/verify-activity.sh): "background" (host:port,seconds,bytes) opens a
 * connection that sends while this screen shows, and then in the background from {@link SendJob}, and the
 * screen stays three seconds and a half; "stay" (seconds) with "udp-every" (host:port) keeps the screen up that long,
 * sending a datagram of 300 bytes each second; "service" (host:port,seconds,bytes) starts
 * {@link NoticeService}, a foreground service with its notification, and the screen leaves at once. Their
 * lines begin with the app's package name, as several copies of it run side by side.
 */
public final class WorkActivity extends Activity {
    static final String TAG = "DatapavanWorkload";

    /** When this screen last stopped being visible, in milliseconds since 1970; 0 while it has not. */
    static volatile long stoppedAt;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String name = getIntent().getStringExtra("name");
        String tcp = getIntent().getStringExtra("tcp");
        String udp = getIntent().getStringExtra("udp");
        String stun = getIntent().getStringExtra("stun");
        String background = getIntent().getStringExtra("background");
        String stay = getIntent().getStringExtra("stay");
        String udpEvery = getIntent().getStringExtra("udp-every");
        String service = getIntent().getStringExtra("service");
        stoppedAt = 0;
        if (background != null) SendJob.begin(this, background);
        if (service != null) {
            startForegroundService(new android.content.Intent(this, NoticeService.class).putExtra("service", service));
        }
        new Thread(() -> {
            if (name != null) resolve(name);
            if (tcp != null) tcp(tcp);
            if (udp != null) udp(udp);
            if (stun != null) stun(stun);
            if (background != null) pause(3_500);
            if (stay != null && udpEvery != null) stay(Integer.parseInt(stay), udpEvery);
            Log.i(TAG, "done");
            runOnUiThread(this::finish);
        }, "workload").start();
    }

    @Override
    protected void onStop() {
        super.onStop();
        stoppedAt = System.currentTimeMillis();
    }

    static void pause(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Sends a datagram of 300 bytes to `target` (host:port) each second for `seconds`, while on screen. */
    private void stay(int seconds, String target) {
        String[] hostPort = target.split(":", 2);
        long sent = 0;
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress host = InetAddress.getByName(hostPort[0]);
            byte[] out = new byte[300];
            for (int i = 0; i < seconds; i++) {
                socket.send(new DatagramPacket(out, out.length, host, Integer.parseInt(hostPort[1])));
                sent += out.length;
                pause(1_000);
            }
            Log.i(TAG, getPackageName() + " stay-sent " + sent);
        } catch (Exception e) {
            Log.i(TAG, getPackageName() + " stay failed: " + e);
        }
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

    /** RFC 8489 6.2.1's defaults for a STUN client over UDP: the first retransmission timeout, doubled
     * after each, how many requests in all, and how many timeouts after the last before giving up. */
    private static final long RTO = 500;
    private static final int RC = 7;
    private static final int RM = 16;

    /**
     * Sends a STUN Binding request (RFC 8489) to each of the two names in [target], "first,second:port",
     * from one socket, back to back once both names are resolved, so that both stand-ins wait on the
     * port when the first answer comes back; each one not answered yet is sent again with its transaction
     * ID as RFC 8489 6.2.1 has a client do over UDP, after 500 ms, then after twice as long each time, 7
     * requests in all, until 16 times 500 ms after the last (fix round 2 of unit 9b: a datagram lost on
     * the emulator's way no longer fails the step). Logs "stun TARGET both after N sendings" once each
     * name's address answered with a Binding success response carrying the transaction ID sent to it, or
     * "stun TARGET got M after N sendings" with how many did by then.
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
            java.util.Map<InetSocketAddress, DatagramPacket> requests = new java.util.LinkedHashMap<>();
            for (java.util.Map.Entry<InetSocketAddress, byte[]> entry : asked.entrySet()) {
                byte[] request = new byte[20];
                request[1] = 0x01;
                request[4] = 0x21;
                request[5] = 0x12;
                request[6] = (byte) 0xa4;
                request[7] = 0x42;
                System.arraycopy(entry.getValue(), 0, request, 8, 12);
                requests.put(entry.getKey(), new DatagramPacket(request, request.length, entry.getKey()));
            }
            long start = System.currentTimeMillis();
            long timeout = RTO;
            long next = start;
            int sent = 0;
            byte[] in = new byte[1500];
            while (answered.size() < asked.size()) {
                long now = System.currentTimeMillis();
                if (now >= next) {
                    if (sent == RC) break;
                    for (java.util.Map.Entry<InetSocketAddress, DatagramPacket> request : requests.entrySet()) {
                        if (!answered.contains(request.getKey())) socket.send(request.getValue());
                    }
                    sent++;
                    // After the last request, the client waits Rm times the first timeout.
                    next = now + (sent == RC ? RM * RTO : timeout);
                    timeout *= 2;
                    continue;
                }
                socket.setSoTimeout((int) Math.max(1, next - now));
                DatagramPacket reply = new DatagramPacket(in, in.length);
                try {
                    socket.receive(reply);
                } catch (java.net.SocketTimeoutException e) {
                    continue;
                }
                InetSocketAddress from = (InetSocketAddress) reply.getSocketAddress();
                byte[] id = asked.get(from);
                boolean success = reply.getLength() >= 20 && in[0] == 0x01 && in[1] == 0x01;
                if (id != null && success && java.util.Arrays.equals(java.util.Arrays.copyOfRange(in, 8, 20), id)) {
                    answered.add(from);
                }
            }
            Log.i(TAG, "stun " + target + (answered.size() == names.length ? " both" : " got " + answered.size())
                    + " after " + sent + " sendings");
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
