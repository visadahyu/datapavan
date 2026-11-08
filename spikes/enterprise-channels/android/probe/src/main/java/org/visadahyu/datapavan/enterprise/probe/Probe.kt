package org.visadahyu.datapavan.enterprise.probe

import android.Manifest
import android.app.Activity
import android.app.admin.DelegatedAdminReceiver
import android.app.admin.DevicePolicyManager
import android.app.admin.DnsEvent
import android.app.admin.ConnectEvent
import android.content.Context
import android.content.Intent
import android.content.RestrictionsManager
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import androidx.enterprise.feedback.KeyedAppState
import androidx.enterprise.feedback.KeyedAppStatesReporter

const val TAG = "EntSpike"

/**
 * Driven by adb: `--es action whoami|config|report|logging`. report: `[--ei keylen K] [--ei msglen M]
 * [--ei datalen D] [--ez immediate true] [--ei count N]`, a verdict of the given sizes.
 */
class ProbeActivity : Activity() {
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
        val line = try {
            when (intent.getStringExtra("action")) {
                "whoami" -> "internet=${checkSelfPermission(Manifest.permission.INTERNET) == PackageManager.PERMISSION_GRANTED} " +
                    "scopes=${getSystemService(DevicePolicyManager::class.java).getDelegatedScopes(null, packageName)}"
                "config" -> {
                    val config = getSystemService(RestrictionsManager::class.java).applicationRestrictions
                    "config=" + config.keySet().sorted().joinToString { "$it=${config.get(it)}" }
                }
                "report" -> report(intent)
                "logging" -> {
                    // As the delegate: turn network logging on without being the device owner.
                    val dpm = getSystemService(DevicePolicyManager::class.java)
                    dpm.setNetworkLoggingEnabled(null, intent.getBooleanExtra("on", true))
                    "network logging by the delegate: ${dpm.isNetworkLoggingEnabled(null)}"
                }
                else -> "unknown action"
            }
        } catch (e: Exception) {
            "error=${e.javaClass.simpleName}:${e.message}"
        }
        Log.i(TAG, "SPIKE_PROBE $line")
    }

    private fun report(intent: Intent): String {
        val count = intent.getIntExtra("count", 1)
        val states = (1..count).map { i ->
            KeyedAppState.builder()
                .setKey("verdict".padEnd(intent.getIntExtra("keylen", 7), 'k').let { if (count > 1) "$it$i" else it })
                .setSeverity(KeyedAppState.SEVERITY_INFO)
                .setMessage("compliant".padEnd(intent.getIntExtra("msglen", 9), '.'))
                .setData("{\"findings\":0}".padEnd(intent.getIntExtra("datalen", 14), ' '))
                .build()
        }
        val reporter = KeyedAppStatesReporter.create(applicationContext)
        val callback = { status: Int, error: Throwable? -> Log.i(TAG, "SPIKE_PROBE report status=$status error=$error"); Unit }
        if (intent.getBooleanExtra("immediate", false)) reporter.setStatesImmediate(states, callback) else reporter.setStates(states, callback)
        return "report sent: ${states.size} state(s), key ${states[0].key.length}, message ${states[0].message?.length}, data ${states[0].data?.length}"
    }
}

/** Network-log batches, delivered to this app because the controller delegated network logging to it. */
class LogsReceiver : DelegatedAdminReceiver() {
    override fun onNetworkLogsAvailable(context: Context, intent: Intent, batchToken: Long, networkLogsCount: Int) {
        val events = context.getSystemService(DevicePolicyManager::class.java).retrieveNetworkLogs(null, batchToken).orEmpty()
        val dns = events.filterIsInstance<DnsEvent>()
        val connects = events.filterIsInstance<ConnectEvent>()
        val byPackage = events.groupingBy { it.packageName }.eachCount().entries.sortedByDescending { it.value }.take(6)
        Log.i(
            TAG,
            "SPIKE_LOGS batch=$batchToken count=$networkLogsCount retrieved=${events.size} dns=${dns.size} connect=${connects.size} " +
                "packages=${byPackage.joinToString { "${it.key}:${it.value}" }} " +
                "sample_dns=${dns.take(3).joinToString { "${it.packageName}->${it.hostname}(${it.totalResolvedAddressCount}: ${it.inetAddresses.joinToString("|") { a -> a.hostAddress.orEmpty() }})" }} " +
                "sample_connect=${connects.take(3).joinToString { "${it.packageName}->${it.inetAddress.hostAddress}:${it.port}" }}",
        )
    }
}
