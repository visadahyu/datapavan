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
 * "udp" (host:port) gets a datagram and waits for its echo. Each result is one line of logcat under
 * the tag DatapavanWorkload, and "done" ends them.
 */
public final class WorkActivity extends Activity {
    private static final String TAG = "DatapavanWorkload";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String name = getIntent().getStringExtra("name");
        String tcp = getIntent().getStringExtra("tcp");
        String udp = getIntent().getStringExtra("udp");
        new Thread(() -> {
            if (name != null) resolve(name);
            if (tcp != null) tcp(tcp);
            if (udp != null) udp(udp);
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
