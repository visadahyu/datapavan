package org.visadahyu.datapavan.testtool;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A SOCKS5 proxy on the phone's loopback (RFC 1928, RFC 1929's password), standing in for the user's
 * circumvention tool in W6's check. It carries CONNECT and UDP ASSOCIATE and refuses BIND; names are
 * looked up in the "map" extra (name=address, comma separated) before Android's resolver. Each request
 * goes to logcat under the tag DatapavanTestTool: "connect HOST PORT", "associate", "password refused".
 *
 * With the "stun" extra it also runs, beside the proxy, a STUN server for the check of ADR 0044's unit
 * 9b: at 127.0.0.1 and 127.0.0.2 on that port, two servers on one port the relay reaches at two
 * addresses, as two names a tool resolves. Each answers a Binding request with a success response
 * carrying its transaction ID and the sender's address (RFC 8489), and logs "stun answered ADDRESS". It holds
 * its answers until both addresses have a request, at most 5 s, so that both of the app's stand-ins wait when
 * the first answer comes back, and logs how each hold ended ([stun]).
 * It is the check's server, not part of what a tool does; it holds the phone's loopback only.
 *
 * With the "own" extra (HOST:PORT) it opens one TCP connection of its own, as a tool reaches its server (the proxy
 * record's unit D, D9): it sends the line "own", reads the answer's line, logs "own HOST PORT open", and keeps the
 * connection open until "stop-own" closes it, which logs "own closed"; a new "own" closes the one before. Both are
 * taken by a running service too, with or without a port.
 *
 *   am start-foreground-service -n org.visadahyu.datapavan.testtool/.ToolService \
 *       --ei port 10870 [--es user U --es password P] [--es map network.test=10.0.2.2] [--ei stun 10871]
 *   am start-foreground-service -n org.visadahyu.datapavan.testtool/.ToolService --es own 10.0.2.2:8794
 *   am start-foreground-service -n org.visadahyu.datapavan.testtool/.ToolService --ez stop-own true
 */
public final class ToolService extends Service {
    private static final String TAG = "DatapavanTestTool";
    private static final String CHANNEL = "tool";
    /** 127.0.0.1, where the table says the tool listens; Android's loopback address of choice is ::1. */
    private static final InetAddress LOOPBACK = loopback();
    private volatile ServerSocket server;
    /** The tool's own connection, while one is open (D9). */
    private Socket own;
    private final Map<String, String> names = new HashMap<>();
    private byte[] user;
    private byte[] password;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Test tool", NotificationManager.IMPORTANCE_LOW));
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setContentTitle("Datapavan test tool")
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .build();
        startForeground(1, notification);
        if (intent != null) {
            if (intent.getBooleanExtra("stop-own", false)) closeOwn();
            String target = intent.getStringExtra("own");
            if (target != null) new Thread(() -> openOwn(target), "tool-own").start();
        }
        // A start that only opens or closes the own connection starts no proxy.
        if (server != null || intent == null || !intent.hasExtra("port")) return START_NOT_STICKY;
        int port = intent.getIntExtra("port", 10870);
        String u = intent.getStringExtra("user");
        String p = intent.getStringExtra("password");
        user = u == null ? null : u.getBytes(StandardCharsets.UTF_8);
        password = p == null ? null : p.getBytes(StandardCharsets.UTF_8);
        String map = intent.getStringExtra("map");
        if (map != null) {
            for (String entry : map.split(",")) {
                String[] pair = entry.split("=", 2);
                if (pair.length == 2) names.put(pair[0], pair[1]);
            }
        }
        new Thread(() -> listen(port), "tool-listen").start();
        int stun = intent.getIntExtra("stun", 0);
        if (stun > 0) new Thread(() -> stun(stun), "tool-stun").start();
        return START_NOT_STICKY;
    }

    private static InetAddress loopback() {
        try {
            return InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
        } catch (java.net.UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Opens the tool's own connection to [target], HOST:PORT, as a tool reaches its server: one line out, one line back,
     * then held open. A connection that fails logs why.
     */
    private void openOwn(String target) {
        int colon = target.lastIndexOf(':');
        if (colon < 0) {
            Log.i(TAG, "own " + target + " refused: no port");
            return;
        }
        String host = target.substring(0, colon);
        int port;
        try {
            port = Integer.parseInt(target.substring(colon + 1));
        } catch (NumberFormatException e) {
            Log.i(TAG, "own " + target + " refused: no port");
            return;
        }
        closeOwn();
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(resolve(host), port), 10_000);
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write("own\n".getBytes(StandardCharsets.US_ASCII));
            InputStream in = socket.getInputStream();
            int b;
            while ((b = in.read()) >= 0 && b != '\n') {
            }
            if (b < 0) throw new IOException("no answer");
            socket.setSoTimeout(0);
        } catch (IOException e) {
            Log.i(TAG, "own " + host + " " + port + " failed: " + e);
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            return;
        }
        synchronized (this) {
            own = socket;
        }
        Log.i(TAG, "own " + host + " " + port + " open");
    }

    /** Closes the tool's own connection, if one is open. */
    private void closeOwn() {
        Socket socket;
        synchronized (this) {
            socket = own;
            own = null;
        }
        if (socket == null) return;
        try {
            socket.close();
        } catch (IOException ignored) {
        }
        Log.i(TAG, "own closed");
    }

    @Override
    public void onDestroy() {
        closeOwn();
        ServerSocket s = server;
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
            }
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void listen(int port) {
        try (ServerSocket s = new ServerSocket()) {
            s.bind(new InetSocketAddress(LOOPBACK, port));
            server = s;
            Log.i(TAG, "listening " + port);
            while (true) {
                Socket client = s.accept();
                new Thread(() -> serve(client), "tool-client").start();
            }
        } catch (IOException e) {
            Log.i(TAG, "stopped");
        }
    }

    private void serve(Socket client) {
        try (Socket c = client) {
            DataInputStream in = new DataInputStream(c.getInputStream());
            OutputStream out = c.getOutputStream();
            if (in.readUnsignedByte() != 5) return;
            byte[] methods = new byte[in.readUnsignedByte()];
            in.readFully(methods);
            int wanted = user != null ? 2 : 0;
            boolean offered = false;
            for (byte m : methods) offered |= m == wanted;
            out.write(new byte[] {5, (byte) (offered ? wanted : 0xff)});
            if (!offered) return;
            if (user != null) {
                in.readUnsignedByte();
                byte[] u = new byte[in.readUnsignedByte()];
                in.readFully(u);
                byte[] p = new byte[in.readUnsignedByte()];
                in.readFully(p);
                boolean right = java.util.Arrays.equals(u, user) && java.util.Arrays.equals(p, password);
                out.write(new byte[] {1, (byte) (right ? 0 : 1)});
                if (!right) {
                    Log.i(TAG, "password refused");
                    return;
                }
            }
            in.readUnsignedByte();
            int command = in.readUnsignedByte();
            in.readUnsignedByte();
            String host = readHost(in);
            int port = in.readUnsignedShort();
            if (command == 1) {
                connect(c, in, out, host, port);
            } else if (command == 3) {
                associate(c, out);
            } else {
                Log.i(TAG, "bind refused");
                out.write(reply(7, new InetSocketAddress(0)));
            }
        } catch (IOException ignored) {
        }
    }

    private static String readHost(DataInputStream in) throws IOException {
        int kind = in.readUnsignedByte();
        byte[] address;
        if (kind == 3) {
            address = new byte[in.readUnsignedByte()];
            in.readFully(address);
            return new String(address, StandardCharsets.US_ASCII);
        }
        address = new byte[kind == 1 ? 4 : 16];
        in.readFully(address);
        return InetAddress.getByAddress(address).getHostAddress();
    }

    private InetAddress resolve(String host) throws IOException {
        String mapped = names.get(host);
        return InetAddress.getByName(mapped != null ? mapped : host);
    }

    private void connect(Socket client, InputStream in, OutputStream out, String host, int port) throws IOException {
        Socket upstream = new Socket();
        try {
            upstream.connect(new InetSocketAddress(resolve(host), port), 10_000);
        } catch (IOException e) {
            Log.i(TAG, "connect " + host + " " + port + " refused");
            out.write(reply(5, new InetSocketAddress(0)));
            upstream.close();
            return;
        }
        Log.i(TAG, "connect " + host + " " + port);
        out.write(reply(0, upstream.getLocalSocketAddress()));
        Thread back = new Thread(() -> pump(upstream, client), "tool-down");
        back.start();
        pump(client, upstream);
        try {
            back.join();
        } catch (InterruptedException ignored) {
        }
        upstream.close();
    }

    private static void pump(Socket from, Socket to) {
        byte[] buffer = new byte[16384];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(buffer)) > 0) out.write(buffer, 0, n);
            to.shutdownOutput();
        } catch (IOException ignored) {
        }
    }

    private void associate(Socket control, OutputStream out) throws IOException {
        // On every address: one bound to the loopback could not send to the servers outside.
        DatagramSocket relay = new DatagramSocket(new InetSocketAddress(0));
        Log.i(TAG, "associate");
        out.write(reply(0, relay.getLocalSocketAddress()));
        Thread worker = new Thread(() -> relay(relay), "tool-relay");
        worker.start();
        // The relay lives as long as the request's connection.
        InputStream in = control.getInputStream();
        while (in.read() >= 0) {
        }
        relay.close();
    }

    private void relay(DatagramSocket relay) {
        byte[] buffer = new byte[65535];
        SocketAddress app = null;
        try {
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                relay.receive(packet);
                if (app == null || app.equals(packet.getSocketAddress())) {
                    app = packet.getSocketAddress();
                    DataInputStream header = new DataInputStream(new java.io.ByteArrayInputStream(buffer, 0, packet.getLength()));
                    if (header.readUnsignedShort() != 0 || header.readUnsignedByte() != 0) continue;
                    String host = readHost(header);
                    int port = header.readUnsignedShort();
                    int start = packet.getLength() - header.available();
                    relay.send(new DatagramPacket(buffer, start, packet.getLength() - start, new InetSocketAddress(resolve(host), port)));
                } else {
                    byte[] head = reply(0, packet.getSocketAddress());
                    byte[] out = new byte[head.length + packet.getLength()];
                    System.arraycopy(head, 0, out, 0, head.length);
                    out[0] = 0;
                    out[1] = 0;
                    out[2] = 0;
                    System.arraycopy(buffer, 0, out, head.length, packet.getLength());
                    relay.send(new DatagramPacket(out, out.length, app));
                }
            }
        } catch (IOException ignored) {
        }
    }

    /** The STUN server's two addresses, as the "map" extra gives them to stun-a.test and stun-b.test. */
    private static final String[] STUN_ADDRESSES = {"127.0.0.1", "127.0.0.2"};
    /** How long, at most, the STUN server holds the answers to one address's requests for a request at the other. */
    private static final long STUN_HOLD_MS = 5_000;

    /** A STUN response held, with the server it leaves from and where it goes. */
    private static final class Held {
        final int server;
        final ByteBuffer response;
        final SocketAddress to;

        Held(int server, ByteBuffer response, SocketAddress to) {
            this.server = server;
            this.response = response;
            this.to = to;
        }
    }

    /**
     * The STUN server at [STUN_ADDRESSES] on [port], one thread for both, which answers each Binding request
     * (type 0x0001, the magic cookie, no attributes needed) with a Binding success response (0x0101) with the
     * same transaction ID and an XOR-MAPPED-ADDRESS of the sender, an IPv4 address (RFC 8489 14.2).
     *
     * It holds its answers until both addresses have a request, at most [STUN_HOLD_MS] after the first came, and
     * then sends every answer held, in the order the requests came. So both of the app's stand-ins wait on the port
     * when the first answer comes back, which unit 9b's step reads: the network part's engine makes a new mapping's
     * destinations peers in whatever order its tasks run once the association is open, not in the order the app
     * sent, and in CI on 2026-11-27 the first answer came back before the second request had left the engine
     * (docs/ci-flakes.md). Each hold ends with the line "stun hold N ended: both asked (A, B)", the addresses in the
     * order their first requests came, or "stun hold N ended: only A asked within 5000 ms", before its answers'
     * "stun answered ADDRESS" lines.
     */
    private static void stun(int port) {
        DatagramChannel[] servers = new DatagramChannel[STUN_ADDRESSES.length];
        try (Selector selector = Selector.open()) {
            for (int i = 0; i < servers.length; i++) {
                servers[i] = DatagramChannel.open();
                servers[i].bind(new InetSocketAddress(InetAddress.getByName(STUN_ADDRESSES[i]), port));
                servers[i].configureBlocking(false);
                servers[i].register(selector, SelectionKey.OP_READ);
                Log.i(TAG, "stun " + STUN_ADDRESSES[i] + " " + port);
            }
            ByteBuffer in = ByteBuffer.allocate(1500);
            List<Held> held = new ArrayList<>();
            List<String> asked = new ArrayList<>();
            long first = 0;
            int holds = 0;
            while (true) {
                long left = first + STUN_HOLD_MS - SystemClock.elapsedRealtime();
                if (held.isEmpty()) {
                    selector.select();
                } else if (left > 0) {
                    selector.select(left);
                }
                selector.selectedKeys().clear();
                for (int i = 0; i < servers.length; i++) {
                    while (true) {
                        in.clear();
                        SocketAddress from = servers[i].receive(in);
                        if (from == null) break;
                        ByteBuffer response = binding(in, (InetSocketAddress) from);
                        if (response == null) continue;
                        if (held.isEmpty()) first = SystemClock.elapsedRealtime();
                        held.add(new Held(i, response, from));
                        if (!asked.contains(STUN_ADDRESSES[i])) asked.add(STUN_ADDRESSES[i]);
                    }
                }
                boolean both = asked.size() == STUN_ADDRESSES.length;
                if (held.isEmpty() || !both && SystemClock.elapsedRealtime() - first < STUN_HOLD_MS) continue;
                holds++;
                Log.i(TAG, "stun hold " + holds + " ended: " + (both
                        ? "both asked (" + String.join(", ", asked) + ")"
                        : "only " + asked.get(0) + " asked within " + STUN_HOLD_MS + " ms"));
                for (Held answer : held) {
                    servers[answer.server].send(answer.response, answer.to);
                    Log.i(TAG, "stun answered " + STUN_ADDRESSES[answer.server]);
                }
                held.clear();
                asked.clear();
            }
        } catch (IOException e) {
            Log.i(TAG, "stun stopped: " + e);
        } finally {
            for (DatagramChannel server : servers) {
                try {
                    if (server != null) server.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * The Binding success response to [request], as received (its position the length), from [from]; null if it is
     * not a Binding request from an IPv4 address.
     */
    private static ByteBuffer binding(ByteBuffer request, InetSocketAddress from) {
        byte[] buffer = request.array();
        if (request.position() < 20 || buffer[0] != 0 || buffer[1] != 1
                || buffer[4] != 0x21 || buffer[5] != 0x12 || buffer[6] != (byte) 0xa4 || buffer[7] != 0x42) return null;
        byte[] address = from.getAddress().getAddress();
        if (address.length != 4) return null;
        byte[] out = new byte[32];
        out[1] = 0x01;
        out[0] = 0x01;
        out[3] = 12;
        System.arraycopy(buffer, 4, out, 4, 16);
        // XOR-MAPPED-ADDRESS: family 1, the port and address each XORed with the magic cookie.
        out[20] = 0x00;
        out[21] = 0x20;
        out[23] = 8;
        out[25] = 1;
        int mapped = from.getPort() ^ 0x2112;
        out[26] = (byte) (mapped >> 8);
        out[27] = (byte) mapped;
        for (int i = 0; i < 4; i++) out[28 + i] = (byte) (address[i] ^ buffer[4 + i]);
        return ByteBuffer.wrap(out);
    }

    /** A reply with code [code] naming [bound]: version, code, reserved, then the address and port. */
    private static byte[] reply(int code, SocketAddress bound) {
        InetSocketAddress address = (InetSocketAddress) bound;
        byte[] ip = address.getAddress() != null ? address.getAddress().getAddress() : new byte[4];
        byte[] out = new byte[4 + ip.length + 2];
        out[0] = 5;
        out[1] = (byte) code;
        out[3] = (byte) (address.getAddress() instanceof Inet4Address || address.getAddress() == null ? 1 : 4);
        System.arraycopy(ip, 0, out, 4, ip.length);
        out[4 + ip.length] = (byte) (address.getPort() >> 8);
        out[5 + ip.length] = (byte) address.getPort();
        return out;
    }
}
