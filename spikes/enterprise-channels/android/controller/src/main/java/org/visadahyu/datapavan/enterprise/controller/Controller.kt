package org.visadahyu.datapavan.enterprise.controller

import android.app.Activity
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.enterprise.feedback.KeyedAppStatesService
import androidx.enterprise.feedback.ReceivedKeyedAppState

const val TAG = "EntSpike"

class Admin : DeviceAdminReceiver()

/** Logs every keyed app state a managed app reports, as a suite's agent would upload it. */
class FeedbackService : KeyedAppStatesService() {
    override fun onReceive(states: MutableCollection<ReceivedKeyedAppState>, requestSync: Boolean) {
        for (state in states) {
            Log.i(
                TAG,
                "SPIKE_FEEDBACK from=${state.packageName} key=${state.key} severity=${state.severity} " +
                    "message_len=${state.message?.length ?: 0} data_len=${state.data?.length ?: 0} sync=$requestSync " +
                    "message=${state.message?.take(80)}",
            )
        }
    }
}

/**
 * Driven by adb: `--es action config --es pkg P [--es level L] [--ez report true]`,
 * `--es action delegate --es pkg P`, `--es action logging --ez on true|false`, `--es action status`.
 */
class ControlActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
        finish()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
        finish()
    }

    private fun handle(intent: Intent) {
        val dpm = getSystemService(DevicePolicyManager::class.java)
        val admin = ComponentName(this, Admin::class.java)
        val pkg = intent.getStringExtra("pkg").orEmpty()
        val line = try {
            when (intent.getStringExtra("action")) {
                "config" -> {
                    val bundle = Bundle().apply {
                        putString("level", intent.getStringExtra("level") ?: "medium")
                        putBoolean("report", intent.getBooleanExtra("report", true))
                        putString("allowed_vpn", intent.getStringExtra("allowed_vpn") ?: "")
                    }
                    dpm.setApplicationRestrictions(admin, pkg, bundle)
                    "config set for $pkg: $bundle"
                }
                "delegate" -> {
                    dpm.setDelegatedScopes(admin, pkg, listOf(DevicePolicyManager.DELEGATION_NETWORK_LOGGING))
                    "delegated network logging to $pkg: ${dpm.getDelegatedScopes(admin, pkg)}"
                }
                "logging" -> {
                    dpm.setNetworkLoggingEnabled(admin, intent.getBooleanExtra("on", true))
                    "network logging ${dpm.isNetworkLoggingEnabled(admin)}"
                }
                "status" -> "device owner=${dpm.isDeviceOwnerApp(packageName)} profile owner=${dpm.isProfileOwnerApp(packageName)} " +
                    "logging=${runCatching { dpm.isNetworkLoggingEnabled(admin) }.getOrElse { it.javaClass.simpleName }}"
                else -> "unknown action"
            }
        } catch (e: Exception) {
            "error=${e.javaClass.simpleName}:${e.message}"
        }
        Log.i(TAG, "SPIKE_CONTROL $line")
    }
}
