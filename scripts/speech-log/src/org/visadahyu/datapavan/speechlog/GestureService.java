package org.visadahyu.datapavan.speechlog;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Path;
import android.os.Bundle;
import android.text.Spanned;
import android.text.style.LocaleSpan;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.accessibility.AccessibilityWindowInfo;

/**
 * Performs a screen reader's gestures through Android's gesture dispatch, which passes through touch exploration as
 * a finger would (an injected "adb shell input" swipe does not: it goes past the screen reader to the app). Told by a
 * broadcast:
 *
 *   adb shell am broadcast -a org.visadahyu.datapavan.speechlog.GESTURE --es do next|previous|activate|back|tree
 *   adb shell am broadcast -a org.visadahyu.datapavan.speechlog.GESTURE --es do click --es id TEST_TAG
 *
 * "next" is a swipe right, "previous" a swipe left, "activate" a double tap, each across the middle of the screen.
 * "click" clicks the element whose resource id is the test tag (Compose's testTagsAsResourceId), or its nearest
 * clickable ancestor, while the screen reader stays on, so that what it says on arriving at a screen is heard. "back"
 * is Android's Back. "tree" writes the active window's title and every node of its tree to logcat under the tag
 * DatapavanTree: its depth, class, role, whether it is a heading, its text with the locales of its LocaleSpans, its
 * content description, state, pane title, checked and selected, live region, clickable and id.
 * Each result goes to logcat under the tag DatapavanSpeech as "gesture DO done", "... cancelled" or "... missing".
 */
public class GestureService extends AccessibilityService {
    static final String ACTION = "org.visadahyu.datapavan.speechlog.GESTURE";
    private BroadcastReceiver receiver;

    @Override
    protected void onServiceConnected() {
        receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                perform(String.valueOf(intent.getStringExtra("do")), intent.getStringExtra("id"));
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
        perform(what, null);
    }

    private void perform(final String what, String id) {
        switch (what) {
            case "click": {
                // An element of a lazy list exists only once it is scrolled to: scroll forward until it does, at most 15
                // times, and if it is not below, backward, at most 30 times.
                AccessibilityNodeInfo node = find(getRootInActiveWindow(), id);
                for (int action : new int[] {AccessibilityNodeInfo.ACTION_SCROLL_FORWARD, AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD}) {
                    int tries = action == AccessibilityNodeInfo.ACTION_SCROLL_FORWARD ? 15 : 30;
                    for (int i = 0; node == null && i < tries; i++) {
                        AccessibilityNodeInfo list = scrollable(getRootInActiveWindow());
                        if (list == null || !list.performAction(action)) break;
                        try {
                            Thread.sleep(300);
                        } catch (InterruptedException e) {
                            break;
                        }
                        node = find(getRootInActiveWindow(), id);
                    }
                }
                while (node != null && !node.isClickable()) node = node.getParent();
                boolean done = node != null && node.performAction(AccessibilityNodeInfo.ACTION_CLICK);
                Log.i(SpeechLogService.TAG, "gesture click " + id + (done ? " done" : " missing"));
                return;
            }
            case "end":
                // The walk's own mark of how a screen's walk ended (wrap, quiet or cap), for talkback-check.py.
                Log.i(SpeechLogService.TAG, "gesture end " + id);
                return;
            case "back":
                Log.i(SpeechLogService.TAG, "gesture back " + (performGlobalAction(GLOBAL_ACTION_BACK) ? "done" : "cancelled"));
                return;
            case "tree": {
                for (AccessibilityWindowInfo window : getWindows()) {
                    if (window.isActive()) Log.i(TREE, "window " + window.getTitle());
                }
                write(getRootInActiveWindow(), 0);
                Log.i(TREE, "end");
                return;
            }
            default:
                break;
        }
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

    static final String TREE = "DatapavanTree";

    private static AccessibilityNodeInfo find(AccessibilityNodeInfo node, String id) {
        if (node == null || id == null) return null;
        String name = node.getViewIdResourceName();
        if (name != null && (name.equals(id) || name.endsWith(":id/" + id))) return node;
        for (int i = 0; i < node.getChildCount(); i++) {
            AccessibilityNodeInfo found = find(node.getChild(i), id);
            if (found != null) return found;
        }
        return null;
    }

    private static AccessibilityNodeInfo scrollable(AccessibilityNodeInfo node) {
        if (node == null) return null;
        if (node.isScrollable()) return node;
        for (int i = 0; i < node.getChildCount(); i++) {
            AccessibilityNodeInfo found = scrollable(node.getChild(i));
            if (found != null) return found;
        }
        return null;
    }

    private static String clean(CharSequence text) {
        return text == null ? "" : text.toString().replace('\n', ' ').replace('|', '/');
    }

    /** A node's text, followed by the locales its LocaleSpans give, as "{fa}". */
    private static String withLocales(CharSequence text) {
        StringBuilder out = new StringBuilder(clean(text));
        if (text instanceof Spanned) {
            Spanned spanned = (Spanned) text;
            for (LocaleSpan span : spanned.getSpans(0, spanned.length(), LocaleSpan.class)) {
                out.append(" {").append(span.getLocales().toLanguageTags()).append('}');
            }
        }
        return out.toString();
    }

    private void write(AccessibilityNodeInfo node, int depth) {
        if (node == null) return;
        Bundle extras = node.getExtras();
        CharSequence role = extras == null ? null : extras.getCharSequence("AccessibilityNodeInfo.roleDescription");
        Log.i(TREE, depth + "|" + clean(node.getClassName()) + "|" + clean(role) + "|" + (node.isHeading() ? "heading" : "")
            + "|" + withLocales(node.getText()) + "|" + withLocales(node.getContentDescription())
            + "|" + clean(node.getStateDescription()) + "|" + clean(node.getPaneTitle())
            + "|" + (node.isCheckable() ? (node.isChecked() ? "checked" : "unchecked") : "") + "|" + (node.isSelected() ? "selected" : "")
            + "|" + (node.getLiveRegion() == 0 ? "" : "live" + node.getLiveRegion()) + "|" + (node.isClickable() ? "clickable" : "")
            + "|" + clean(node.getViewIdResourceName()));
        for (int i = 0; i < node.getChildCount(); i++) write(node.getChild(i), depth + 1);
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
    }

    @Override
    public void onInterrupt() {
    }
}
