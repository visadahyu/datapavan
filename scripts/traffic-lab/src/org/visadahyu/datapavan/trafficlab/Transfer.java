package org.visadahyu.datapavan.trafficlab;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Random;

/** Downloads and uploads a given number of bytes over plain HTTP to scripts/traffic-lab/server.py. */
final class Transfer {
    static final String TAG = "TrafficLab";
    /** The computer, as the emulator sees it. */
    static final String SERVER = "http://10.0.2.2:8765";

    private Transfer() {}

    static void run(long down, long up) {
        try {
            if (down > 0) download(down);
            if (up > 0) upload(up);
            Log.i(TAG, "done down=" + down + " up=" + up);
        } catch (IOException e) {
            Log.e(TAG, "failed down=" + down + " up=" + up, e);
        }
    }

    private static void download(long bytes) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(SERVER + "/down/" + bytes).openConnection();
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

    private static void upload(long bytes) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(SERVER + "/up").openConnection();
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
