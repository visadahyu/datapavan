package org.visadahyu.datapavan.workload;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

/**
 * A foreground service, which Android shows the user with its notification (W5, ADR 0046, decision 6, item
 * 1: "with its notification"): begun while {@link WorkActivity} shows, which then leaves; 35 seconds later,
 * past the grace in which the app still counts as in use, it sends a datagram of "bytes" each second for
 * "seconds" to the test server's echo, logs "PACKAGE service-sent N", and stops.
 */
public final class NoticeService extends Service {
    private static final String CHANNEL = "workload";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager notifications = getSystemService(NotificationManager.class);
        notifications.createNotificationChannel(new NotificationChannel(CHANNEL, "Workload", NotificationManager.IMPORTANCE_LOW));
        Notification notice = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentTitle("Workload")
                .build();
        startForeground(1, notice);
        String service = intent == null ? null : intent.getStringExtra("service");
        new Thread(() -> {
            if (service != null) send(service);
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf(startId);
        }, "workload-service").start();
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void send(String target) {
        String[] parts = target.split(",", 3);
        String[] hostPort = parts[0].split(":", 2);
        int seconds = Integer.parseInt(parts[1]);
        int bytes = Integer.parseInt(parts[2]);
        String app = getPackageName();
        WorkActivity.pause(35_000);
        long sent = 0;
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress host = InetAddress.getByName(hostPort[0]);
            byte[] out = new byte[bytes];
            for (int i = 0; i < seconds; i++) {
                socket.send(new DatagramPacket(out, out.length, host, Integer.parseInt(hostPort[1])));
                sent += bytes;
                WorkActivity.pause(1_000);
            }
            Log.i(WorkActivity.TAG, app + " service-sent " + sent);
        } catch (Exception e) {
            Log.i(WorkActivity.TAG, app + " service failed: " + e);
        }
    }
}
