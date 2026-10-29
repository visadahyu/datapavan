package org.visadahyu.datapavan.fixture;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.AccessibilityEvent;

/** Inert: verify-audit.sh enables it over adb so that the fixture holds remote-control access. */
public final class FixtureAccessibilityService extends AccessibilityService {
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {}

    @Override
    public void onInterrupt() {}
}
