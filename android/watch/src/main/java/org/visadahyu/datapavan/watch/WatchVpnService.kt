package org.visadahyu.datapavan.watch

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Watch's VPN (docs/VPN.md). Milestone W1: the tunnel starts and stops, and only Watch itself is inside
 * it, so no other app's traffic is touched until the packet engine forwards it (W2).
 *
 * Android starts this service in two ways: from Watch's screen with [ACTION_START] or [ACTION_STOP],
 * and with [VpnService.SERVICE_INTERFACE] when the user made Watch the always-on VPN. Both start the
 * tunnel. Android binds to the service while the tunnel is up, which keeps it running.
 */
class WatchVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) stop() else start()
        return START_NOT_STICKY
    }

    private fun start() {
        if (tunnel != null) return
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .addAddress(ADDRESS_V4, 32)
            .addAddress(ADDRESS_V6, 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // The engine reads until "would block" (spike, finding 8).
            .setBlocking(false)
            // A VPN that targets Android 10 or later is metered unless it says otherwise. Watch is
            // local, so the network keeps the meteredness of the Wi-Fi or mobile network beneath it.
            .setMetered(false)
            .addAllowedApplication(packageName)
        val established = try {
            builder.establish()
        } catch (e: IllegalStateException) {
            Log.w(TAG, "The tunnel could not be set up", e)
            null
        } catch (e: SecurityException) {
            Log.w(TAG, "The tunnel was not allowed", e)
            null
        }
        // null: the user's consent is missing or was withdrawn.
        if (established == null) {
            stop()
            return
        }
        tunnel = established
        state.value = true
    }

    private fun stop() {
        close()
        stopSelf()
    }

    private fun close() {
        tunnel?.close()
        tunnel = null
        state.value = false
    }

    /** Another VPN took Android's one VPN slot, or the user turned Watch off in Settings. */
    override fun onRevoke() {
        stop()
    }

    override fun onDestroy() {
        close()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "org.visadahyu.datapavan.watch.START"
        const val ACTION_STOP = "org.visadahyu.datapavan.watch.STOP"
        private const val TAG = "Watch"

        // The tunnel's own addresses: from the ranges for private networks (RFC 1918) and unique local
        // addresses (RFC 4193), picked so that they are unlikely to meet a home or office network.
        private const val ADDRESS_V4 = "10.215.173.1"
        private const val ADDRESS_V6 = "fd7a:6470:7761::1"

        private val state = MutableStateFlow(false)

        /** Whether the tunnel is up, for Watch's own screens. */
        val running: StateFlow<Boolean> = state.asStateFlow()
    }
}
