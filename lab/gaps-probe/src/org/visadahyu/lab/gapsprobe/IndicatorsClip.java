package org.visadahyu.lab.gapsprobe;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;

/**
 * indicators: puts a fixed clip on the clipboard, so that the fixture, another app, reads a clip it
 * did not put there (Android 12 and later tell the user of that read).
 */
final class IndicatorsClip {
    private IndicatorsClip() {}

    static void set(Activity activity, String step) {
        activity.getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("gaps", "gaps-lab-clip"));
        GapsProbe.out("indicators", step, "clip=set");
    }
}
