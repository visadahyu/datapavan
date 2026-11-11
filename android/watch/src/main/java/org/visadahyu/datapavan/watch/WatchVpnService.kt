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
import java.io.IOException
import java.io.PrintWriter
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.visadahyu.datapavan.watch.log.ConnectionLog
import org.visadahyu.datapavan.watch.log.LogRecord

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

        /** The network and DNS server last given to the engine. */
        private var told: Network? = null
        private var toldDns: String? = null

        override fun onAvailable(network: Network) {
            current = network
            setUnderlyingNetworks(arrayOf(network))
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            if (network != current) return
            // A link-local DNS server needs its interface's scope, which the engine does not take.
            val dns = properties.dnsServers.firstOrNull { !it.isLinkLocalAddress }?.hostAddress ?: ""
            // Android reports a network's properties several times after a switch; only a new network
            // closes the engine's UDP flows, and nothing the engine already knows is sent again.
            if (network == told && dns == toldDns) return
            Engine.nativeNetworkChanged(dns, network != told)
            told = network
            toldDns = dns
        }

        override fun onLost(network: Network) {
            if (network != current) return
            current = null
            setUnderlyingNetworks(null)
            Engine.nativeNetworkChanged("", true)
            told = null
            toldDns = null
        }
    }

    /**
     * Follows Private DNS on Watch's own default network, which is its VPN while the tunnel is up:
     * what Android does with the lookups of every app in the tunnel.
     */
    private val ownNetwork = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            dnsState.value = PrivateDns.of(properties)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stop()
            ACTION_APPLY_CHAIN -> if (active) applyChain()
            else -> start(intent)
        }
        return START_NOT_STICKY
    }

    /**
     * Hands the user's chain (W6) to the engine: the tool's proxy where it last answered, its password
     * where the tool takes one, the tool's UID, and the chained apps. It runs before any traffic, from
     * what Watch remembers, so that chained apps never go directly while the tool is looked for again;
     * a tool that is not there leaves them waiting, not going directly.
     */
    private fun applyChain() {
        val settings = org.visadahyu.datapavan.watch.chain.ChainSettings.of(this)
        val remembered = settings.lastTool
        if (!settings.on || remembered == null) {
            Engine.nativeChain("", 0, null, null, 0, null, udp = false, logDestinations = false)
            return
        }
        fun uidOf(packageName: String): Int? = try {
            @Suppress("DEPRECATION")
            packageManager.getApplicationInfo(packageName, 0).uid
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
        val known = try {
            org.visadahyu.datapavan.watch.chain.Tools.table(this).find { it.packageName == remembered.packageName }
        } catch (e: java.io.IOException) {
            null
        }
        val password = settings.password().takeIf { known?.auth != "none" }
        val user = org.visadahyu.datapavan.watch.chain.ChainSettings.userFor(remembered.packageName)
        val apps = if (settings.allApps) null else settings.apps.mapNotNull(::uidOf).toIntArray()
        Engine.nativeChain(
            remembered.host,
            remembered.port,
            password?.let { user.toByteArray() },
            password?.toByteArray(),
            // A tool no longer installed has no UID: no app is taken for it, and nothing goes directly.
            uidOf(remembered.packageName) ?: NO_UID,
            apps,
            udp = remembered.udp,
            logDestinations = settings.logDestinations,
        )
    }

    /** Looks for the tool again off the main thread, and applies the chain again where its proxy moved. */
    private fun refreshChain() {
        if (!org.visadahyu.datapavan.watch.chain.ChainSettings.of(this).on) return
        Thread {
            val search = org.visadahyu.datapavan.watch.chain.Tools.search(this)
            val found = (search as? org.visadahyu.datapavan.watch.chain.ToolSearch.Answering)?.found ?: return@Thread
            val settings = org.visadahyu.datapavan.watch.chain.ChainSettings.of(this)
            val before = settings.lastTool
            settings.remember(found)
            if (settings.lastTool != before && active) applyChain()
        }.apply { name = "watch-chain" }.start()
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
        // Before any app's traffic can go anywhere it should not (W6).
        applyChain()
        active = true
        state.value = true
        refreshChain()
        ConnectionLog.of(this).expire()
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
        connectivity.registerDefaultNetworkCallback(ownNetwork, handler)
    }

    /**
     * Hands the tunnel's descriptor to the engine, which owns it from then on, with the table from
     * address to organisation (ADR 0036) where this build carries it: the engine reads it in place,
     * inside the APK, without loading it.
     */
    private fun startEngine(tunnel: ParcelFileDescriptor): Boolean {
        val fd = tunnel.detachFd()
        var tableFd = -1
        var tableStart = 0L
        var tableLength = 0L
        try {
            assets.openFd(ORGANISATIONS).use { asset ->
                tableFd = asset.parcelFileDescriptor.dup().detachFd()
                tableStart = asset.startOffset
                tableLength = asset.length
            }
        } catch (e: IOException) {
            // This build has no table: flows that nothing else names stay unnamed.
            Log.i(TAG, "No table from address to organisation in this build")
        }
        return Engine.nativeStart(this, fd, MTU, if (debuggable) KEPT_FLOWS else 0, tableFd, tableStart, tableLength)
    }

    private fun stop() {
        close()
        stopSelf()
    }

    private fun close() {
        if (active) {
            for (callback in listOf(network, ownNetwork)) {
                try {
                    connectivity.unregisterNetworkCallback(callback)
                } catch (e: IllegalArgumentException) {
                    Log.w(TAG, "A network callback was not registered", e)
                }
            }
        }
        Engine.nativeStop()
        active = false
        state.value = false
        dnsState.value = null
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

    /** Called by the engine with a batch of finished records for the connection log (ADR 0037). */
    @Suppress("unused")
    fun logRecords(batch: ByteArray) = ConnectionLog.of(this).write(batch)

    /**
     * `adb shell dumpsys activity service org.visadahyu.datapavan.watch/.WatchVpnService`: the
     * engine's counters and Private DNS, and in debug builds the flows it kept and Private DNS's
     * provider, for the end-to-end test (scripts/verify-watch.sh). Release builds print no
     * destination and no provider.
     */
    override fun dump(fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        // Debug builds: the file as it is, before the status line below runs expiry.
        if (debuggable && args.orEmpty().contains("log-raw")) {
            val (records, keys) = ConnectionLog.of(this).stored()
            fun days(counts: Map<Long, Int>) = counts.entries.sortedBy { it.key }.joinToString(",") { "${it.key}:${it.value}" }.ifEmpty { "-" }
            writer.println("log-raw records ${days(records)} keys ${days(keys)}")
            return
        }
        writer.println("running ${state.value}")
        val dns = when (val mode = dnsState.value) {
            null -> "-"
            PrivateDns.Plain -> "plain"
            PrivateDns.Network -> "network"
            is PrivateDns.Strict -> if (debuggable) "strict ${mode.host}" else "strict"
        }
        writer.println("private-dns $dns")
        writer.println("counters ${Engine.nativeCounters().joinToString(" ")}")
        writer.println("organisations ${Engine.nativeOrganisations().ifEmpty { "none" }}")
        val log = ConnectionLog.of(this)
        val counts = log.counts()
        writer.println(
            "log retention ${log.retentionDays} days ${counts.days} records ${counts.records} key-rows ${counts.keys} " +
                "key ${log.hasKey} lock ${log.lockNow().name.lowercase().replace('_', '-')} failures ${log.failures}",
        )
        if (debuggable) {
            // W6's DNS spike (docs/spikes/2026-11-shared-dns-cache.md): answers with a time to live of 0.
            val uncached = args.orEmpty().indexOf("dns-uncached").takeIf { it >= 0 }?.let { args?.getOrNull(it + 1) }
            when (uncached) {
                "on" -> Engine.nativeUncacheAnswers(true).also { writer.println("dns-uncached on") }
                "off" -> Engine.nativeUncacheAnswers(false).also { writer.println("dns-uncached off") }
            }
            debugChain(args.orEmpty().toList(), writer)
            if ("find-tool" in args.orEmpty()) writer.println(describe(org.visadahyu.datapavan.watch.chain.Tools.search(this)))
            Engine.nativeFlows().lineSequence().filter { it.isNotBlank() }.forEach { writer.println("flow $it") }
            debugLog(log, args.orEmpty().toList(), writer)
        }
    }

    /**
     * Debug builds only, for W6's end-to-end test: `chain HOST PORT TOOL_UID udp|no-udp all|UID,UID
     * [USER PASSWORD]` turns chaining on through the SOCKS5 proxy at HOST and PORT, and `unchain` turns
     * it off. Each prints `chain on` or `chain off`; credentials are never printed.
     */
    private fun debugChain(args: List<String>, writer: PrintWriter) {
        if ("unchain" in args) {
            Engine.nativeChain("", 0, null, null, 0, null, udp = false, logDestinations = false)
            writer.println("chain off")
            return
        }
        val at = args.indexOf("chain").takeIf { it >= 0 } ?: return
        val (host, port, tool, udp, apps) = args.drop(at + 1).take(5).takeIf { it.size == 5 } ?: return
        val user = args.getOrNull(at + 6)?.toByteArray()
        val password = args.getOrNull(at + 7)?.toByteArray()
        val uids = if (apps == "all") null else apps.split(',').mapNotNull { it.toIntOrNull() }.toIntArray()
        val on = Engine.nativeChain(
            host,
            port.toIntOrNull() ?: 0,
            user,
            password,
            tool.toIntOrNull() ?: -1,
            uids,
            udp = udp == "udp",
            logDestinations = false,
        )
        writer.println(if (on) "chain on" else "chain off")
    }

    /**
     * Debug builds only, for scripts/verify-log.sh: `log-flush` hands the log every waiting record and
     * each open flow's segment so far, and waits until they are written, `log-today`
     * prints today's records, `log-day N` says whether day N (days since 1970) opens now, `log-test-day N`
     * writes a test record dated day N, `log-put-day N` writes one even past retention (as if put back by
     * hand), `log-retention N` sets retention, `log-raw` (in [dump]) prints the rows by day as the file
     * holds them, `log-wipe` wipes the log, and `log-model SEED STEPS` starts the log's model test
     * ([org.visadahyu.datapavan.watch.log.LogModel]), whose result `log-model-result` prints.
     */
    private fun debugLog(log: ConnectionLog, args: List<String>, writer: PrintWriter) {
        fun after(command: String) = args.indexOf(command).takeIf { it >= 0 }?.let { args.getOrNull(it + 1)?.toLongOrNull() }
        val day = after("log-day")
        val testDay = after("log-test-day") ?: after("log-put-day")
        val retention = after("log-retention")?.toInt()
        when {
            "log-wipe" in args -> {
                val done = java.util.concurrent.CountDownLatch(1)
                var gone = false
                log.wipe {
                    gone = it
                    done.countDown()
                }
                writer.println("log-wiped ${done.await(10, java.util.concurrent.TimeUnit.SECONDS) && gone}")
            }
            "log-retention" in args && retention in ConnectionLog.RETENTION_CHOICES -> {
                log.retentionDays = retention ?: return
                log.settle()
                writer.println("log-retention $retention set")
            }
            "log-model" in args -> {
                val seed = after("log-model") ?: System.nanoTime()
                val steps = args.getOrNull(args.indexOf("log-model") + 2)?.toIntOrNull() ?: 300
                writer.println(org.visadahyu.datapavan.watch.log.LogModel.start(this, seed, steps))
            }
            "log-model-result" in args -> writer.println(org.visadahyu.datapavan.watch.log.LogModel.result())
            "log-flush" in args -> {
                Engine.nativeFlushLog()
                log.settle()
                writer.println("log-flushed")
            }
            "log-today" in args -> log.read(log.today())?.forEach { writer.println("log-record ${describe(it)}") }
            "log-day" in args && day != null -> {
                val records = log.read(day)
                writer.println(if (records == null) "log-day $day locked" else "log-day $day open ${records.size}")
            }
            testDay != null -> {
                val noon = java.time.LocalDate.ofEpochDay(testDay).atTime(12, 0).atZone(java.time.ZoneId.systemDefault()).toInstant().toEpochMilli()
                val record = java.nio.ByteBuffer.allocate(1 + 1 + 4 + 8 + 8 + 4 + 8 + 8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .put(1).put(2).putInt(-1).putLong(noon).putLong(noon).putInt(1).putLong(0).putLong(0).array()
                val batch = java.nio.ByteBuffer.allocate(4 + 2 + record.size).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putInt(1).putShort(record.size.toShort()).put(record).array()
                log.write(batch, pastRetention = "log-put-day" in args)
                log.settle()
                writer.println("${if ("log-put-day" in args) "log-put-day" else "log-test-day"} $testDay written")
            }
        }
    }

    /** Debug builds' `find-tool`: what Watch found of the user's tool, one line, for W6's checks. */
    private fun describe(search: org.visadahyu.datapavan.watch.chain.ToolSearch): String = when (search) {
        org.visadahyu.datapavan.watch.chain.ToolSearch.NoneInstalled -> "tool none"
        is org.visadahyu.datapavan.watch.chain.ToolSearch.NotAnswering ->
            "tool installed ${search.installed.joinToString(",") { it.packageName }} not-answering"
        is org.visadahyu.datapavan.watch.chain.ToolSearch.Answering -> with(search.found) {
            val owner = when (ownerConfirmed) {
                true -> "yes"
                false -> "no"
                null -> "unknown"
            }
            "tool answering ${tool.packageName} $host:$port uid $uid password ${if (needsPassword) "yes" else "no"} owner $owner"
        }
    }

    private fun describe(record: LogRecord): String = when (record) {
        is LogRecord.Segment -> listOf(
            if (record.protocol == 6) "tcp" else "udp", record.uid ?: "-", "${record.address.hostAddress}:${record.port}",
            "up=${record.up}", "down=${record.down}", if (record.continues) "continues" else "ended",
            "wire=${record.wireUp}/${record.wireDown}", record.name.ifEmpty { "-" }, "flow=${record.flow}",
        ).joinToString(" ")
        is LogRecord.Lookups -> "lookups ${record.uid ?: "-"} ${record.count} wire=${record.wireUp}/${record.wireDown}"
    }

    companion object {
        const val ACTION_START = "org.visadahyu.datapavan.watch.START"
        const val ACTION_STOP = "org.visadahyu.datapavan.watch.STOP"

        /** The chain's settings changed: hand them to the engine (W6). */
        const val ACTION_APPLY_CHAIN = "org.visadahyu.datapavan.watch.APPLY_CHAIN"

        /** The UID given for a tool that is not installed: no app has it. */
        private const val NO_UID = Int.MAX_VALUE

        /** Debug builds: a comma-separated list of the only apps to send through the tunnel. */
        const val EXTRA_ONLY_APPS = "only_apps"
        private const val TAG = "Watch"
        private const val MTU = 1500
        private const val KEPT_FLOWS = 512

        /** The asset of the table from address to organisation, stored uncompressed (build.gradle.kts). */
        private const val ORGANISATIONS = "asn.bin"

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

        private val dnsState = MutableStateFlow<PrivateDns?>(null)

        /** Private DNS on Watch's network while the tunnel is up, else null, for Watch's own screens. */
        val privateDns: StateFlow<PrivateDns?> = dnsState.asStateFlow()
    }
}
