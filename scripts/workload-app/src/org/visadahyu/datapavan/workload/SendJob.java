package org.visadahyu.datapavan.workload;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.util.Log;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Sends in the background, as a sync job does, with no notification (W5, ADR 0046, decision 6, item 1).
 * {@link #begin} opens a long connection to the test server while {@link WorkActivity} shows, a POST to
 * /sink, and sends 1,000 bytes on it each second for three seconds, and asks Android for this job at once:
 * while it runs, the app's process is not cached, so Android neither freezes it nor closes its sockets once
 * the screen has left (Android 15 closes a cached app's connections). 35 seconds after the screen stopped
 * being visible, past the 30 seconds' grace in which the app still counts as in use, it sends "bytes" more on
 * the connection each second for "seconds", and a datagram of 500 bytes to the next port each second, as on
 * a timer, and the job ends. It logs "PACKAGE background-sent N on-screen-sent M", N the bytes it sent in
 * the background, as the app sent them, M those before.
 */
public final class SendJob extends JobService {
    private static final int JOB = 1;
    private static final int ON_SCREEN = 1_000;
    private static final int DATAGRAM = 500;

    /** The job, once it runs, to end when the sending is done. */
    private static volatile JobParameters running;
    private static volatile SendJob service;

    /** Asks for the job at once, and opens the connection and sends, on a thread of its own. */
    static void begin(Context context, String target) {
        String app = context.getPackageName();
        JobInfo job = new JobInfo.Builder(JOB, new ComponentName(context, SendJob.class))
                .setOverrideDeadline(1_000)
                .build();
        context.getSystemService(JobScheduler.class).schedule(job);
        new Thread(() -> send(app, target), "workload-background").start();
    }

    @Override
    public boolean onStartJob(JobParameters params) {
        running = params;
        service = this;
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return false;
    }

    private static void send(String app, String target) {
        String[] parts = target.split(",", 3);
        String[] hostPort = parts[0].split(":", 2);
        int seconds = Integer.parseInt(parts[1]);
        int bytes = Integer.parseInt(parts[2]);
        try (Socket socket = new Socket(); DatagramSocket udp = new DatagramSocket()) {
            InetAddress host = InetAddress.getByName(hostPort[0]);
            int port = Integer.parseInt(hostPort[1]);
            socket.connect(new InetSocketAddress(host, port), 8_000);
            socket.setSoTimeout(30_000);
            OutputStream out = socket.getOutputStream();
            long body = 3L * ON_SCREEN + (long) seconds * bytes;
            byte[] head = ("POST /sink HTTP/1.0\r\nContent-Length: " + body + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            out.write(head);
            long onScreen = head.length;
            for (int i = 0; i < 3; i++) {
                out.write(new byte[ON_SCREEN]);
                out.flush();
                onScreen += ON_SCREEN;
                WorkActivity.pause(1_000);
            }
            while (WorkActivity.stoppedAt == 0 || System.currentTimeMillis() < WorkActivity.stoppedAt + 35_000) {
                WorkActivity.pause(200);
            }
            long sent = 0;
            byte[] chunk = new byte[bytes];
            byte[] datagram = new byte[DATAGRAM];
            for (int i = 0; i < seconds; i++) {
                out.write(chunk);
                out.flush();
                udp.send(new DatagramPacket(datagram, datagram.length, host, port + 1));
                sent += bytes + DATAGRAM;
                WorkActivity.pause(1_000);
            }
            InputStream in = socket.getInputStream();
            byte[] answer = new byte[512];
            while (in.read(answer) > 0) {
                // The server's "ok", then the close.
            }
            Log.i(WorkActivity.TAG, app + " background-sent " + sent + " on-screen-sent " + onScreen);
        } catch (Exception e) {
            Log.i(WorkActivity.TAG, app + " background failed: " + e);
        } finally {
            SendJob job = service;
            JobParameters params = running;
            if (job != null && params != null) job.jobFinished(params, false);
        }
    }
}
