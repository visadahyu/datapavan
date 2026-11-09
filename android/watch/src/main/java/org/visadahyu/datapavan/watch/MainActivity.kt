package org.visadahyu.datapavan.watch

import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import org.visadahyu.datapavan.watch.ui.WatchScreen
import org.visadahyu.datapavan.watch.ui.WatchTheme

class MainActivity : ComponentActivity() {
    /** Android refused the VPN consent the last time Watch asked. */
    private val refused = mutableStateOf(false)

    /** Debug builds: the only apps the end-to-end test sends through the tunnel, comma-separated. */
    private var onlyApps: String? = null

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startTunnel() else refused.value = true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dark = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
        setContent {
            val running by WatchVpnService.running.collectAsState()
            val privateDns by WatchVpnService.privateDns.collectAsState()
            WatchTheme {
                WatchScreen(
                    running = running,
                    privateDns = privateDns,
                    refused = refused.value,
                    onStart = ::requestStart,
                    onStop = ::stopTunnel,
                )
            }
        }
        // Debug builds only: scripts/verify-watch.sh starts the tunnel for its own apps from adb, since
        // the VPN service itself is not exported.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (debuggable && savedInstanceState == null && intent.getBooleanExtra(EXTRA_START, false)) {
            onlyApps = intent.getStringExtra(WatchVpnService.EXTRA_ONLY_APPS)
            requestStart()
        }
        if (debuggable && intent.getBooleanExtra(EXTRA_STOP, false)) stopTunnel()
    }

    /** The activity is single-top: a debug start or stop sent while it is open comes here. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!debuggable) return
        if (intent.getBooleanExtra(EXTRA_START, false)) {
            onlyApps = intent.getStringExtra(WatchVpnService.EXTRA_ONLY_APPS)
            requestStart()
        }
        if (intent.getBooleanExtra(EXTRA_STOP, false)) stopTunnel()
    }

    /** Asks for Android's VPN consent the first time, then starts the tunnel. */
    private fun requestStart() {
        refused.value = false
        val ask = VpnService.prepare(this) ?: return startTunnel()
        try {
            consent.launch(ask)
        } catch (e: ActivityNotFoundException) {
            // Some builds of Android have no consent screen; Watch cannot become the VPN there.
            refused.value = true
        }
    }

    private fun startTunnel() {
        val start = Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_START)
        onlyApps?.let { start.putExtra(WatchVpnService.EXTRA_ONLY_APPS, it) }
        startService(start)
    }

    private fun stopTunnel() {
        startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_STOP))
    }

    private companion object {
        /** Debug builds: start the tunnel at once (scripts/verify-watch.sh). */
        const val EXTRA_START = "start"

        /** Debug builds: stop the tunnel, so that the engine hands its last records to the log (scripts/verify-log.sh). */
        const val EXTRA_STOP = "stop"
    }
}
