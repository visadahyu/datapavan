package org.visadahyu.datapavan.speechlog;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Path;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;

/**
 * Performs a screen reader's gestures through Android's gesture dispatch, which passes through touch exploration as
 * a finger would (an injected "adb shell input" swipe does not: it goes past the screen reader to the app). Told by a
 * broadcast:
 *
 *   adb shell am broadcast -a org.visadahyu.datapavan.speechlog.GESTURE --es do next|previous|activate
 *
 * "next" is a swipe right, "previous" a swipe left, "activate" a double tap, each across the middle of the screen.
 * Each result goes to logcat under the tag DatapavanSpeech as "gesture DO done" or "gesture DO cancelled".
 */
public class GestureService extends AccessibilityService {
    static final String ACTION = "org.visadahyu.datapavan.speechlog.GESTURE";
    private BroadcastReceiver receiver;

    @Override
    protected void onServiceConnected() {
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                perform(String.valueOf(intent.getStringExtra("do")));
            }
        };
        registerReceiver(receiver, new IntentFilter(ACTION), Context.RECEIVER_EXPORTED);
        Log.i(SpeechLogService.TAG, "gestures ready");
    }

    @Override
    public void onDestroy() {
        if (receiver != null) unregisterReceiver(receiver);
        super.onDestroy();
    }

    private void perform(final String what) {
        DisplayMetrics metrics = getResources().getDisplayMetrics();
        float w = metrics.widthPixels, h = metrics.heightPixels;
        GestureDescription.Builder gesture = new GestureDescription.Builder();
        switch (what) {
            case "next":
            case "previous": {
                Path path = new Path();
                boolean next = what.equals("next");
                path.moveTo(w * (next ? 0.2f : 0.8f), h * 0.5f);
                path.lineTo(w * (next ? 0.8f : 0.2f), h * 0.5f);
                gesture.addStroke(new GestureDescription.StrokeDescription(path, 0, 120));
                break;
            }
            case "activate": {
                Path first = new Path();
                first.moveTo(w * 0.5f, h * 0.5f);
                Path second = new Path();
                second.moveTo(w * 0.5f, h * 0.5f);
                gesture.addStroke(new GestureDescription.StrokeDescription(first, 0, 40));
                gesture.addStroke(new GestureDescription.StrokeDescription(second, 140, 40));
                break;
            }
            default:
                Log.i(SpeechLogService.TAG, "gesture " + what + " unknown");
                return;
        }
        dispatchGesture(gesture.build(), new GestureResultCallback() {
            @Override
            public void onCompleted(GestureDescription description) {
                Log.i(SpeechLogService.TAG, "gesture " + what + " done");
            }

            @Override
            public void onCancelled(GestureDescription description) {
                Log.i(SpeechLogService.TAG, "gesture " + what + " cancelled");
            }
        }, null);
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
    }

    @Override
    public void onInterrupt() {
    }
}
