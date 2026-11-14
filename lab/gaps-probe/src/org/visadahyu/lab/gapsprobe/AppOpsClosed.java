package org.visadahyu.lab.gapsprobe;

import android.app.AppOpsManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * appops-closed: whether this app reaches Android's history of other apps' operations, and whether
 * startWatchingActive tells it of another app's microphone. Steps: "history-..." asks getHistoricalOps,
 * a system API reached by reflection, for the last hour, for every app (sought: the fixture) and, as
 * the control, for this app alone, and records the answer or the first stage that fails (the run names
 * the step after the condition it set, such as a granted permission); "watch" watches the
 * microphone and the camera for 40 seconds, from a foreground service, so that Android neither freezes
 * nor ends this app while the fixture is on screen; "self-mic" records one second with this app's own
 * microphone, the watcher's control. The recording stays in memory and is dropped.
 */
final class AppOpsClosed {
    private static final String FIXTURE = "org.visadahyu.lab.gapsfixture";

    private AppOpsClosed() {}

    static void run(Context context, String step) throws Exception {
        if (step.startsWith("history")) history(context, step);
        else if (step.equals("watch")) context.startForegroundService(new Intent(context, Watcher.class));
        else if (step.equals("self-mic")) GapsProbe.out("appops-closed", step, "recorded bytes=" + recordOneSecond());
    }

    private static void history(Context context, String step) throws Exception {
        int fixture = context.getPackageManager().getPackageUid(FIXTURE, 0);
        GapsProbe.out("appops-closed", step, "scope=all " + ask(context, -1, fixture));
        // The control: the same call for this app's own UID only.
        GapsProbe.out("appops-closed", step, "scope=own " + ask(context, Process.myUid(), Process.myUid()));
    }

    /** One call of getHistoricalOps for the last hour, for every UID (-1) or one; the first stage that fails. */
    private static String ask(Context context, int uid, int sought) throws InterruptedException {
        AppOpsManager ops = context.getSystemService(AppOpsManager.class);
        String stage = "class";
        try {
            Class<?> builder = Class.forName("android.app.AppOpsManager$HistoricalOpsRequest$Builder");
            stage = "builder";
            long now = System.currentTimeMillis();
            Object request = builder.getConstructor(long.class, long.class).newInstance(now - 3_600_000L, now);
            if (uid >= 0) {
                stage = "uid";
                builder.getMethod("setUid", int.class).invoke(request, uid);
            }
            stage = "build";
            request = builder.getMethod("build").invoke(request);
            stage = "method";
            Method get = AppOpsManager.class.getMethod("getHistoricalOps", request.getClass(), Executor.class, Consumer.class);
            stage = "call";
            CountDownLatch answered = new CountDownLatch(1);
            Object[] answer = new Object[1];
            Consumer<Object> callback = result -> {
                answer[0] = result;
                answered.countDown();
            };
            get.invoke(ops, request, (Executor) Runnable::run, callback);
            if (!answered.await(10, TimeUnit.SECONDS)) return "answer=none stage=wait";
            if (answer[0] == null) return "answer=empty stage=result";
            stage = "read";
            Object uids = answer[0].getClass().getMethod("getUidCount").invoke(answer[0]);
            Object found = answer[0].getClass().getMethod("getUidOps", int.class).invoke(answer[0], sought);
            return "answer=opened uids=" + uids + " sought=" + (found == null ? "absent" : "present");
        } catch (InvocationTargetException e) {
            return "answer=refused stage=" + stage + " error=" + e.getCause().getClass().getSimpleName();
        } catch (ReflectiveOperationException e) {
            return "answer=hidden stage=" + stage + " error=" + e.getClass().getSimpleName();
        }
    }

    /** The watcher's foreground service: it runs the watch, then stops. */
    public static final class Watcher extends Service {
        @Override
        public IBinder onBind(Intent intent) {
            return null;
        }

        @Override
        public int onStartCommand(Intent intent, int flags, int startId) {
            getSystemService(NotificationManager.class).createNotificationChannel(
                    new NotificationChannel("gaps", "Gaps probe (lab)", NotificationManager.IMPORTANCE_LOW));
            Notification notification = new Notification.Builder(this, "gaps").setContentTitle("Gaps probe (lab)")
                    .setSmallIcon(android.R.drawable.stat_notify_sync).build();
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(1, notification);
            new Thread(() -> {
                try {
                    watch(this);
                } catch (Exception e) {
                    GapsProbe.out("appops-closed", "watch", "error " + GapsProbe.word(e));
                }
                GapsProbe.out("appops-closed", "watch", "done");
                stopSelf();
            }, "gaps-watch").start();
            return START_NOT_STICKY;
        }
    }

    private static void watch(Context context) throws Exception {
        if (Build.VERSION.SDK_INT < 30) {
            // startWatchingActive came with Android 11 (API 30).
            GapsProbe.out("appops-closed", "watch", "ready");
            GapsProbe.out("appops-closed", "watch", "end unavailable=api" + Build.VERSION.SDK_INT);
            return;
        }
        AppOpsManager ops = context.getSystemService(AppOpsManager.class);
        int self = Process.myUid();
        int fixture = context.getPackageManager().getPackageUid(FIXTURE, 0);
        AtomicInteger own = new AtomicInteger();
        AtomicInteger theFixture = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();
        AppOpsManager.OnOpActiveChangedListener listener = (op, uid, packageName, active) -> {
            String who = uid == self ? "own" : uid == fixture ? "fixture" : "other";
            (uid == self ? own : uid == fixture ? theFixture : other).incrementAndGet();
            GapsProbe.out("appops-closed", "watch", "callback op=" + op + " who=" + who + " active=" + active);
        };
        ops.startWatchingActive(new String[] {AppOpsManager.OPSTR_RECORD_AUDIO, AppOpsManager.OPSTR_CAMERA},
                Runnable::run, listener);
        GapsProbe.out("appops-closed", "watch", "ready");
        Thread.sleep(40_000);
        ops.stopWatchingActive(listener);
        GapsProbe.out("appops-closed", "watch", "end own=" + own + " fixture=" + theFixture + " other=" + other);
    }

    private static int recordOneSecond() {
        int rate = 16_000;
        byte[] second = new byte[rate * 2];
        int size = Math.max(AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT), second.length);
        AudioRecord recorder = new AudioRecord(MediaRecorder.AudioSource.MIC, rate, AudioFormat.CHANNEL_IN_MONO,
                AudioFormat.ENCODING_PCM_16BIT, size);
        int total = 0;
        try {
            recorder.startRecording();
            while (total < second.length) {
                int n = recorder.read(second, total, second.length - total);
                if (n <= 0) break;
                total += n;
            }
            recorder.stop();
        } finally {
            recorder.release();
            Arrays.fill(second, (byte) 0);
        }
        return total;
    }
}
