package org.visadahyu.datapavan.probe

import android.accessibilityservice.AccessibilityService
import android.app.admin.DeviceAdminReceiver
import android.net.VpnService
import android.service.notification.NotificationListenerService
import android.view.accessibility.AccessibilityEvent

// Inert test fixtures for the M2 spike. adb enables them so the probe has something to detect.

class ProbeAccessibilityService : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit
    override fun onInterrupt() = Unit
}

class ProbeNotificationListener : NotificationListenerService()

class ProbeVpnService : VpnService()

class ProbeAdminReceiver : DeviceAdminReceiver()
