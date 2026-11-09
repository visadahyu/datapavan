package org.visadahyu.datapavan.watch

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileDescriptor
import java.io.PrintWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Watch's VPN (docs/VPN.md). Every app's traffic enters the tunnel, and the packet engine in Rust
 * ([Engine]) passes it on to where it was going over sockets this service protects, after asking
 * Android whose each flow is. Watch is inside its own tunnel, as the engine needs (ADR 0012).
 *
 * Android starts this service in two ways: from Watch's screen with [ACTION_START] or [ACTION_STOP],
 * and with [VpnService.SERVICE_INTERFACE] when the user made Watch the always-on VPN. Both start the
 * tunnel. Android binds to the service while the tunnel is up, which keeps it running (ADR 0034).
 */
class WatchVpnService : VpnService() {
    private var active = false
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val debuggable by lazy { applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }

    /** Follows the network beneath the tunnel: Wi-Fi, mobile data, or none. */
    private val network = object : ConnectivityManager.NetworkCallback() {
        private var current: Network? = null

        override fun onAvailable(network: Network) {
            current = network
            setUnderlyingNetworks(arrayOf(network))
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (network != current) return
            // A link-local DNS server needs its interface's scope, which the engine does not take.
            val dns = properties.dnsServers.firstOrNull { !it.isLinkLocalAddress }
            Engine.nativeNetworkChanged(dns?.hostAddress ?: "")
        }

        override fun onLost(network: Network) {
            if (network != current) return
            current = null
            setUnderlyingNetworks(null)
            Engine.nativeNetworkChanged("")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) stop() else start(intent)
        return START_NOT_STICKY
    }

    private fun start(intent: Intent?) {
        if (active) return
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(MTU)
            // A /32 and a /128: a wider prefix would count as local network on Android 17 (ADR 0034).
            .addAddress(ADDRESS_V4, 32)
            .addAddress(ADDRESS_V6, 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // The engine passes queries to this address on to the DNS server of the network beneath.
            .addDnsServer(DNS_V4)
            .addDnsServer(DNS_V6)
            // The engine reads until "would block" (spike, finding 8).
            .setBlocking(false)
            // A VPN that targets Android 10 or later is metered unless it says otherwise. Watch is
            // local, so the network keeps the meteredness of the Wi-Fi or mobile network beneath it.
            .setMetered(false)
        // Debug builds only: the end-to-end test sends only its own apps through the tunnel.
        val only = intent?.getStringExtra(EXTRA_ONLY_APPS)?.takeIf { debuggable }?.split(',')?.filter { it.isNotBlank() }
        if (!only.isNullOrEmpty()) {
            for (app in only + packageName) {
                try {
                    builder.addAllowedApplication(app)
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "Not installed: an app named for the test", e)
                }
            }
        }
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
        if (established == null || !startEngine(established)) {
            stop()
            return
        }
        active = true
        state.value = true
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val handler = Handler(Looper.getMainLooper())
        // Watch is inside its own tunnel, so its default network is its own VPN. From Android 12 the
        // best-matching callback follows the network beneath; before, requestNetwork does, with
        // CHANGE_NETWORK_STATE, and brings up no other network when the current one matches (ADR 0034).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            connectivity.registerBestMatchingNetworkCallback(request, network, handler)
        } else {
            connectivity.requestNetwork(request, network, handler)
        }
    }

    /** Hands the tunnel's descriptor to the engine, which owns it from then on. */
    private fun startEngine(tunnel: ParcelFileDescriptor): Boolean {
        val fd = tunnel.detachFd()
        return Engine.nativeStart(this, fd, MTU, if (debuggable) KEPT_FLOWS else 0)
    }

    private fun stop() {
        close()
        stopSelf()
    }

    private fun close() {
        if (active) {
            try {
                connectivity.unregisterNetworkCallback(network)
            } catch (e: IllegalArgumentException) {
                Log.w(TAG, "The network callback was not registered", e)
            }
        }
        Engine.nativeStop()
        active = false
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

    /** Called by the engine for each new flow: the app's UID, or -1 when Android does not know. */
    @Suppress("unused")
    fun ownerUid(protocol: Int, local: ByteArray, localPort: Int, remote: ByteArray, remotePort: Int): Int = try {
        connectivity.getConnectionOwnerUid(
            protocol,
            InetSocketAddress(InetAddress.getByAddress(local), localPort),
            InetSocketAddress(InetAddress.getByAddress(remote), remotePort),
        )
    } catch (e: SecurityException) {
        // Not (or no longer) the active VPN.
        -1
    } catch (e: IllegalArgumentException) {
        -1
    } catch (e: java.net.UnknownHostException) {
        -1
    }

    /** Called by the engine for each socket of its own, before it connects: keeps it out of the tunnel. */
    @Suppress("unused")
    fun protectSocket(fd: Int): Boolean = protect(fd)

    /**
     * `adb shell dumpsys activity service org.visadahyu.datapavan.watch/.WatchVpnService`: the
     * engine's counters, and in debug builds the flows it kept, for the end-to-end test
     * (scripts/verify-watch.sh). Release builds print no destination.
     */
    override fun dump(fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        writer.println("running ${state.value}")
        writer.println("counters ${Engine.nativeCounters().joinToString(" ")}")
        if (debuggable) {
            Engine.nativeFlows().lineSequence().filter { it.isNotBlank() }.forEach { writer.println("flow $it") }
        }
    }

    companion object {
        const val ACTION_START = "org.visadahyu.datapavan.watch.START"
        const val ACTION_STOP = "org.visadahyu.datapavan.watch.STOP"

        /** Debug builds: a comma-separated list of the only apps to send through the tunnel. */
        const val EXTRA_ONLY_APPS = "only_apps"
        private const val TAG = "Watch"
        private const val MTU = 1500
        private const val KEPT_FLOWS = 512

        // The tunnel's own addresses and its DNS server, the same as the engine's (core/net,
        // engine.rs): from the ranges for private networks (RFC 1918) and unique local addresses
        // (RFC 4193), picked so that they are unlikely to meet a home or office network.
        private const val ADDRESS_V4 = "10.215.173.1"
        private const val ADDRESS_V6 = "fd7a:6470:7761::1"
        private const val DNS_V4 = "10.215.173.3"
        private const val DNS_V6 = "fd7a:6470:7761::3"

        private val state = MutableStateFlow(false)

        /** Whether the tunnel is up, for Watch's own screens. */
        val running: StateFlow<Boolean> = state.asStateFlow()
    }
}
