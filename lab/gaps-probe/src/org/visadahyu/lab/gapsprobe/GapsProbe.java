package org.visadahyu.lab.gapsprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

/**
 * Started by lab/run.sh with the extras "behaviour", "step" and "trials" (ADR 0048, decision 2). Each
 * behaviour is one file of this package and writes its results as lines of logcat under the tag
 * GapsProbe: "behaviour step what key=value ...", then "behaviour step done". Values hold no spaces.
 * The activity stays open until the run stops the app.
 */
public final class GapsProbe extends Activity {
    /** The lab's own server, on the computer that runs the emulator. */
    static final String LAB_HOST = "10.0.2.2";

    private String behaviour;
    private String step;
    private boolean clipped;

    static void out(String behaviour, String step, String line) {
        Log.i("GapsProbe", behaviour + " " + step + " " + line);
    }

    /** A value as one word: spaces become underscores, and it is cut at 160 characters. */
    static String word(Object value) {
        String text = String.valueOf(value).replaceAll("\\s+", "_");
        return text.length() > 160 ? text.substring(0, 160) : text;
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        behaviour = String.valueOf(getIntent().getStringExtra("behaviour"));
        step = String.valueOf(getIntent().getStringExtra("step"));
        int trials = Math.max(1, Math.min(1000, getIntent().getIntExtra("trials", 1)));
        // Android may create the activity again, as on Android 14 just after a start: the step runs once.
        if (state != null) {
            clipped = true;
            return;
        }
        if (behaviour.equals("webview")) {
            WebViewOrigin.load(this);
            return;
        }
        if (behaviour.equals("indicators")) {
            return;
        }
        new Thread(() -> {
            try {
                switch (behaviour) {
                    case "vpn-seen": VpnSeen.run(this, step); break;
                    case "appops-closed": AppOpsClosed.run(this, step); break;
                    case "proc-net": ProcNet.run(step); break;
                    case "loopback": LoopbackExchange.run(step); break;
                    case "carried-by-system": CarriedBySystem.run(this, step, trials); break;
                    case "short-lived": ShortLived.run(step, trials); break;
                    default: out(behaviour, step, "unknown");
                }
            } catch (Throwable t) {
                out(behaviour, step, "error " + word(t));
            }
            out(behaviour, step, "done");
        }, "gaps-probe").start();
    }

    @Override
    public void onWindowFocusChanged(boolean focus) {
        super.onWindowFocusChanged(focus);
        // Android 10 and later: only the focused app writes and reads the clipboard.
        if (focus && behaviour.equals("indicators") && !clipped) {
            clipped = true;
            IndicatorsClip.set(this, step);
            out(behaviour, step, "done");
        }
    }
}
