package org.visadahyu.datapavan.trafficlab;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.util.Random;

/**
 * Downloads and uploads a given number of bytes over plain HTTP to scripts/traffic-lab/server.py, at
 * the base URL in the extra "server", or on the computer as the emulator sees it. With the extra
 * "listen", it waits for the computer to connect on that port instead, reads "down" bytes from it and
 * writes "up" bytes back, for a phone whose computer lets no connection in.
 */
final class Transfer {
    static final String TAG = "TrafficLab";
    private static final String EMULATOR_HOST = "http://10.0.2.2:8765";

    private Transfer() {}

    static void run(String server, long down, long up) {
        String base = server != null ? server : EMULATOR_HOST;
        try {
            if (down > 0) download(base, down);
            if (up > 0) upload(base, up);
            Log.i(TAG, "done down=" + down + " up=" + up);
        } catch (IOException e) {
            Log.e(TAG, "failed down=" + down + " up=" + up, e);
        }
    }

    static void serve(int port, long down, long up) {
        try (ServerSocket server = new ServerSocket()) {
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(port));
            server.setSoTimeout(60_000);
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(120_000);
                InputStream in = socket.getInputStream();
                byte[] buffer = new byte[64 * 1024];
                long read = 0;
                for (int n; read < down && (n = in.read(buffer, 0, (int) Math.min(buffer.length, down - read))) > 0; ) read += n;
                if (read != down) throw new IOException("read " + read + " of " + down);
                new Random(up).nextBytes(buffer);
                OutputStream out = socket.getOutputStream();
                for (long left = up; left > 0; ) {
                    int n = (int) Math.min(buffer.length, left);
                    out.write(buffer, 0, n);
                    left -= n;
                }
                out.flush();
            }
            Log.i(TAG, "done down=" + down + " up=" + up);
        } catch (IOException e) {
            Log.e(TAG, "failed down=" + down + " up=" + up, e);
        }
    }

    private static void download(String base, long bytes) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(base + "/down/" + bytes).openConnection();
        c.setRequestProperty("Accept-Encoding", "identity");
        long read = 0;
        try (InputStream in = c.getInputStream()) {
            byte[] buffer = new byte[64 * 1024];
            for (int n; (n = in.read(buffer)) > 0; ) read += n;
        } finally {
            c.disconnect();
        }
        if (read != bytes) throw new IOException("read " + read + " of " + bytes);
    }

    private static void upload(String base, long bytes) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(base + "/up").openConnection();
        c.setDoOutput(true);
        c.setFixedLengthStreamingMode(bytes);
        byte[] buffer = new byte[64 * 1024];
        new Random(bytes).nextBytes(buffer);
        try (OutputStream out = c.getOutputStream()) {
            for (long left = bytes; left > 0; ) {
                int n = (int) Math.min(buffer.length, left);
                out.write(buffer, 0, n);
                left -= n;
            }
        }
        try {
            if (c.getResponseCode() != 200) throw new IOException("status " + c.getResponseCode());
        } finally {
            c.disconnect();
        }
    }
}
