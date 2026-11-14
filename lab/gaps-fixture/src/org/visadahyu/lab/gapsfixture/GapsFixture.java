package org.visadahyu.lab.gapsfixture;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Checks first that it runs on an emulator, from the emulator's own properties (ro.boot.qemu, or
 * ro.kernel.qemu on older images) and its hardware name, and otherwise stops before it reads anything,
 * unless it was built with --lab-phone. Then it shows the device and waits to be confirmed; only then
 * does it make the reads that the extra "reads" lists, in order: contacts, calllog, sms, media,
 * clipboard, mic, socket. Each result is one line of logcat under the tag GapsFixture.
 */
public final class GapsFixture extends Activity {
    static void out(String line) {
        Log.i("GapsFixture", "fixture " + line);
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (!FixtureFlags.LAB_PHONE && !emulator()) {
            out("refused not-an-emulator");
            finish();
            return;
        }
        LinearLayout screen = new LinearLayout(this);
        screen.setOrientation(LinearLayout.VERTICAL);
        screen.setPadding(48, 160, 48, 48);
        TextView text = new TextView(this);
        text.setText("Gaps fixture (lab)\n\nThis app reads synthetic test data on a lab device, and records only that each "
                + "read happened and how many items it returned.\n\nDevice: " + Build.MANUFACTURER + " " + Build.MODEL
                + "\nBuild: " + Build.FINGERPRINT
                + "\nSerial: apps cannot read it since Android 10; lab/run.sh names the device by its adb serial."
                + (FixtureFlags.LAB_PHONE ? "\n\nBuilt for a lab phone (--lab-phone)." : "\n\nEmulator: yes."));
        Button confirm = new Button(this);
        confirm.setText("Confirm");
        confirm.setOnClickListener(v -> {
            confirm.setEnabled(false);
            start();
        });
        screen.addView(text);
        screen.addView(confirm);
        setContentView(screen);
        out("waiting confirm");
    }

    private void start() {
        String reads = String.valueOf(getIntent().getStringExtra("reads"));
        out("confirmed");
        // The clipboard is read here, on the main thread, while this app has the focus (Android 10).
        for (String kind : reads.split(",")) {
            if (kind.equals("clipboard")) FixtureReads.clipboard(this);
        }
        new Thread(() -> {
            for (String kind : reads.split(",")) {
                switch (kind) {
                    case "contacts": case "calllog": case "sms": case "media": FixtureReads.read(this, kind); break;
                    case "mic": FixtureMicrophone.record(); break;
                    case "socket": FixtureNoSocket.attempt(); break;
                    default: break;
                }
            }
            out("done");
        }, "gaps-fixture").start();
    }

    /** The emulator's own properties and its hardware name; a phone has neither. */
    private static boolean emulator() {
        boolean hardware = Build.HARDWARE.equals("ranchu") || Build.HARDWARE.equals("goldfish");
        boolean qemu = "1".equals(property("ro.boot.qemu")) || "1".equals(property("ro.kernel.qemu"));
        out("emulator hardware=" + Build.HARDWARE + " qemu=" + qemu);
        return hardware && qemu;
    }

    private static String property(String name) {
        try {
            Process getprop = new ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(getprop.getInputStream()))) {
                String line = reader.readLine();
                return line == null ? "" : line.trim();
            }
        } catch (Exception e) {
            return "";
        }
    }
}
