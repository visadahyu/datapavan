package org.visadahyu.datapavan.watch

import android.content.ActivityNotFoundException
import android.content.Intent
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
            WatchTheme {
                WatchScreen(running = running, refused = refused.value, onStart = ::requestStart, onStop = ::stopTunnel)
            }
        }
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
        startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_START))
    }

    private fun stopTunnel() {
        startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_STOP))
    }
}
