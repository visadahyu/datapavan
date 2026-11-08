package org.visadahyu.datapavan.watch.spike

import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * The spike's tunnel. Only the apps named in "allow" (by default the workload app) go through it, so
 * nobody else's traffic is touched, and the watch app is outside it, so its own sockets go straight
 * to the network. The addresses match `system.rs`.
 */
class SpikeVpnService : VpnService() {
    private val handler = Handler(Looper.getMainLooper())
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private var engine: PacketEngine? = null
    private var name = ""
    private var quiet = false

    /** "host:port" of a SOCKS5 proxy the system engine chains through, from the start command, or "". */
    var socks = ""
        private set

    private val tick = object : Runnable {
        override fun run() {
            logStats("SPIKE_STATS")
            handler.postDelayed(this, STATS_EVERY_MS)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopEngine()
            stopSelf()
        } else if (intent?.action == ACTION_STATS) {
            logStats("SPIKE_STATS")
        } else if (intent?.action == ACTION_LOOPBACK) {
            loopback(intent.getIntExtra(EXTRA_PORT, 10808))
        } else {
            // Quiet: no stats every few seconds, so that an idle tunnel wakes nothing (battery runs).
            quiet = intent?.getBooleanExtra(EXTRA_QUIET, false) ?: false
            socks = intent?.getStringExtra(EXTRA_SOCKS).orEmpty()
            startEngine(intent?.getStringExtra(EXTRA_ENGINE) ?: "userspace", intent?.getStringExtra(EXTRA_ALLOW) ?: LOAD_APP)
        }
        return START_NOT_STICKY
    }

    private fun startEngine(which: String, allow: String) {
        stopEngine()
        val selected = engines[which] ?: return Log.e(TAG, "SPIKE_ERROR unknown engine $which").let { }
        val dns = connectivity.getLinkProperties(connectivity.activeNetwork)?.dnsServers.orEmpty()
        val builder = Builder()
            .setSession("Watch spike: $which")
            .setMtu(MTU)
            // The engines poll the descriptor; a blocking one hangs the engine's thread when idle.
            .setBlocking(false)
            .addAddress(TUN4, 24)
            .addAddress(TUN6, 64)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
        // The system engine's listener answers through the tunnel only for apps inside it, so the
        // watch app joins its own tunnel there and protects its sockets instead (system.rs).
        val allowed = allow.split(',').map { it.trim() }.filter { it.isNotEmpty() } + if (which == "system") listOf(packageName) else emptyList()
        when {
            // "*": every app on the phone, as in real use. The system engine needs this app inside too;
            // the others keep it out, since their sockets are not protected.
            allow == "*" -> if (which != "system") builder.addDisallowedApplication(packageName)
            // An empty list would put every app in the tunnel, this one too.
            allowed.isEmpty() -> builder.addDisallowedApplication(packageName)
            else -> allowed.forEach { builder.addAllowedApplication(it) }
        }
        dns.forEach { builder.addDnsServer(it) }
        val tunnel = builder.establish() ?: return Log.e(TAG, "SPIKE_ERROR establish failed: no consent?").let { }
        if (!selected.start(this, tunnel.detachFd(), MTU)) return Log.e(TAG, "SPIKE_ERROR $which did not start").let { }
        engine = selected
        name = which
        Log.i(TAG, "SPIKE_STARTED engine=$which allow=${if (allow == "*") "all apps" else allowed.toString()} dns=$dns socks=$socks quiet=$quiet pid=${Process.myPid()}")
        if (!quiet) handler.postDelayed(tick, STATS_EVERY_MS)
    }

    private fun stopEngine() {
        handler.removeCallbacks(tick)
        val running = engine ?: return
        running.stop()
        logStats("SPIKE_STOPPED")
        engine = null
    }

    private fun logStats(label: String) {
        val s = engine?.stats() ?: return
        val lookupMs = if (s[4] > 0) s[5] / s[4] / 1e6 else 0.0
        Log.i(
            TAG,
            "$label engine=$name tcp=${s[0]} udp=${s[1]} up=${s[2]} down=${s[3]} lookups=${s[4]} " +
                "lookup_ms=${"%.3f".format(lookupMs)} unknown=${s[6]} errors=${s[7]} pkt_in=${s[8]} pkt_out=${s[9]}" +
                (if (name != "gvisor") " last_error=${RustEngine.nativeLastError()}" else ""),
        )
    }

    /** Called by the engines once per new flow, on a thread of their own. */
    @Suppress("unused")
    fun ownerUid(protocol: Int, source: ByteArray, sourcePort: Int, destination: ByteArray, destinationPort: Int): Int = try {
        connectivity.getConnectionOwnerUid(
            protocol,
            InetSocketAddress(InetAddress.getByAddress(source), sourcePort),
            InetSocketAddress(InetAddress.getByAddress(destination), destinationPort),
        )
    } catch (_: RuntimeException) {
        -1
    }

    /**
     * The untested idea of the circumvention research: connect to a tool's local proxy port, then ask
     * Android who owns each end of that loopback connection. The tool's end names the app behind the
     * port, if Android tells a VPN about a socket on loopback at all.
     */
    private fun loopback(port: Int) = Thread {
        val line = try {
            java.net.Socket().use { socket ->
                socket.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 2_000)
                val mine = socket.localSocketAddress as InetSocketAddress
                val theirs = socket.remoteSocketAddress as InetSocketAddress
                fun owner(local: InetSocketAddress, remote: InetSocketAddress): String {
                    val uid = try {
                        connectivity.getConnectionOwnerUid(android.system.OsConstants.IPPROTO_TCP, local, remote)
                    } catch (e: RuntimeException) {
                        return "${e.javaClass.simpleName}"
                    }
                    val names = if (uid >= 0) packageManager.getPackagesForUid(uid)?.joinToString("|") else null
                    return "$uid(${names ?: "-"})"
                }
                "own=${owner(mine, theirs)} peer=${owner(theirs, mine)}"
            }
        } catch (e: Exception) {
            "error=${e.javaClass.simpleName}:${e.message}"
        }
        Log.i(TAG, "SPIKE_LOOPBACK port=$port engine=${name.ifEmpty { "none" }} $line")
    }.start()

    /** Called by the engines before an upstream socket connects, when the watch app is inside the tunnel. */
    @Suppress("unused")
    fun protectSocket(fd: Int): Boolean = protect(fd)

    override fun onRevoke() {
        stopEngine()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopEngine()
        super.onDestroy()
    }

    companion object {
        const val TAG = "WatchSpike"
        const val ACTION_START = "org.visadahyu.datapavan.watch.spike.START"
        const val ACTION_STOP = "org.visadahyu.datapavan.watch.spike.STOP"
        const val ACTION_STATS = "org.visadahyu.datapavan.watch.spike.STATS"
        const val ACTION_LOOPBACK = "org.visadahyu.datapavan.watch.spike.LOOPBACK"
        const val EXTRA_PORT = "port"
        const val EXTRA_QUIET = "quiet"
        const val EXTRA_ENGINE = "engine"
        const val EXTRA_ALLOW = "allow"
        const val EXTRA_SOCKS = "socks"
        const val LOAD_APP = "org.visadahyu.datapavan.watch.load"
        const val TUN4 = "10.111.0.1"
        const val TUN6 = "fd00:111::1"
        const val MTU = 1500
        const val STATS_EVERY_MS = 5_000L
    }
}
