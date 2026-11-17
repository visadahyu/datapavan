package org.visadahyu.datapavan.testtool;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
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
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
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
 * carrying its transaction ID and the sender's address (RFC 8489), and logs "stun answered ADDRESS".
 * It is the check's server, not part of what a tool does; it holds the phone's loopback only.
 *
 *   am start-foreground-service -n org.visadahyu.datapavan.testtool/.ToolService \
 *       --ei port 10870 [--es user U --es password P] [--es map watch.test=10.0.2.2] [--ei stun 10871]
 */
public final class ToolService extends Service {
    private static final String TAG = "DatapavanTestTool";
    private static final String CHANNEL = "tool";
    /** 127.0.0.1, where the table says the tool listens; Android's loopback address of choice is ::1. */
    private static final InetAddress LOOPBACK = loopback();
    private volatile ServerSocket server;
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
        if (server != null || intent == null) return START_NOT_STICKY;
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
        if (stun > 0) {
            for (String address : new String[] {"127.0.0.1", "127.0.0.2"}) {
                new Thread(() -> stun(address, stun), "tool-stun").start();
            }
        }
        return START_NOT_STICKY;
    }

    private static InetAddress loopback() {
        try {
            return InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
        } catch (java.net.UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void onDestroy() {
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

    /**
     * A STUN server at [address]:[port] that answers each Binding request (type 0x0001, the magic cookie,
     * no attributes needed) with a Binding success response (0x0101) with the same transaction ID and an
     * XOR-MAPPED-ADDRESS of the sender, an IPv4 address (RFC 8489 14.2).
     */
    private static void stun(String address, int port) {
        try (DatagramSocket socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName(address), port))) {
            Log.i(TAG, "stun " + address + " " + port);
            byte[] buffer = new byte[1500];
            while (true) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                if (packet.getLength() < 20 || buffer[0] != 0 || buffer[1] != 1
                        || buffer[4] != 0x21 || buffer[5] != 0x12 || buffer[6] != (byte) 0xa4 || buffer[7] != 0x42) continue;
                byte[] from = packet.getAddress().getAddress();
                if (from.length != 4) continue;
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
                int mapped = packet.getPort() ^ 0x2112;
                out[26] = (byte) (mapped >> 8);
                out[27] = (byte) mapped;
                for (int i = 0; i < 4; i++) out[28 + i] = (byte) (from[i] ^ buffer[4 + i]);
                socket.send(new DatagramPacket(out, out.length, packet.getSocketAddress()));
                Log.i(TAG, "stun answered " + address);
            }
        } catch (IOException e) {
            Log.i(TAG, "stun " + address + " stopped: " + e);
        }
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
