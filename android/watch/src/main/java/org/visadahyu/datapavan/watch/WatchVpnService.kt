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
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.FileDescriptor
import java.io.IOException
import java.io.PrintWriter
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.random.Random
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

    /** The tunnel's addresses for this run (ADR 0041): the common ones, unless a network beneath uses them. */
    @Volatile
    private var addresses = TunnelAddresses.COMMON

    /** Debug builds: a set to take whatever the networks beneath, for scripts/verify-watch.sh, which cannot make its network clash. */
    @Volatile
    private var forced: TunnelAddresses.Set? = null

    /**
     * What the tunnel was last established with that decides whether the running engine may take it when
     * it is set up again ([setUpAgain]); [close] forgets it. Main thread only.
     */
    private var setup: TunnelSetup? = null
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val debuggable by lazy { applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }

    /** The network beneath that [network] follows. */
    private var current: Network? = null

    /**
     * The network and DNS server last given to the engine. An engine started on a tunnel set up again
     * goes on with what the one before knew ([setUpAgain]); [close] forgets them, and the next callback of
     * a run tells its engine.
     */
    private var told: Network? = null
    private var toldDns: String? = null

    /** Debug builds: the only apps the end-to-end test sends through the tunnel, for every setup of a run. */
    private var onlyApps: List<String>? = null

    /**
     * The network beneath the tunnel's MTU was last measured on, while the tunnel follows it: within it,
     * the MTU goes down at once and up only ten minutes after the last setup ([TunnelMtu.next]). Main
     * thread only.
     */
    private var measuredOn: Network? = null

    /** When the tunnel was last set up, by [SystemClock.elapsedRealtime]. Main thread only. */
    private var setUpAt = 0L

    /** How this run's tunnel was set up again: handed to the running engine, or to a new one; the dump says it. */
    private var setupsKept = 0
    private var setupsAnew = 0

    /**
     * When the engine's counters began, by [SystemClock.elapsedRealtime]: at Watch's start of its engine,
     * and kept when a new engine takes the tunnel, to which the old one hands its counters. A test that
     * reads a counter twice tells by it an engine started afresh between, whose counters began again at
     * 0, from one that counted nothing (ADR 0044, unit 9b, fix round 2).
     */
    private var countersSince = 0L

    /** The token of the measure posted for when a rise held back may be taken; [close] drops it. */
    private val riseCheck = Any()

    /**
     * The tunnel's MTU for this run (ADR 0044, decision 5 as amended): the first hop's of the network
     * beneath, as [TunnelMtu] chooses it from what the kernel said. Set on the main thread.
     */
    @Volatile
    private var mtu = TunnelMtu.MOST

    /** What the kernel last said of the first hop's MTU of IPv4 and of IPv6, for the dump. */
    @Volatile
    private var firstHops: Pair<Int?, Int?> = null to null

    /**
     * Where the first hop is measured: off the main thread, where StrictMode counts a UDP socket's
     * connect as network access, and one at a time.
     */
    private val measuring: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "watch-mtu").apply { isDaemon = true }
    }

    /**
     * Every start asked for: one that waits for its measure goes ahead only while it is the last, and no
     * stop came since. Main thread only.
     */
    private var starts = 0

    /** Follows the network beneath the tunnel: Wi-Fi, mobile data, or none. */
    private val network = object : ConnectivityManager.NetworkCallback() {

        override fun onAvailable(network: Network) {
            current = network
            setUnderlyingNetworks(arrayOf(network))
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            // A network that now uses the tunnel's addresses itself would lose its router and resolver
            // to the tunnel: the tunnel is set up again with the other set (ADR 0041).
            if ((forced ?: TunnelAddresses.choose(networksBeneath())) !== addresses) {
                main.post { setUpAgain() }
            }
            if (network != current) return
            remeasure(network)
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

    private val main = Handler(Looper.getMainLooper())

    /** Every network beneath the tunnel, VPNs aside, with what it uses of the address space. */
    @Suppress("DEPRECATION") // allNetworks: the choice must see every network, not only the one followed.
    private fun networksBeneath(): List<TunnelAddresses.Network> = connectivity.allNetworks.mapNotNull { network ->
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
        val properties = connectivity.getLinkProperties(network) ?: return@mapNotNull null
        TunnelAddresses.Network(
            addresses = properties.linkAddresses.map { it.address to it.prefixLength },
            others = properties.dnsServers + properties.routes.mapNotNull { it.gateway }.filterNot { it.isAnyLocalAddress },
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stop()
            ACTION_APPLY_CHAIN -> if (active) applyChain()
            // The apps left out are part of the tunnel's own setup: it is set up again.
            ACTION_APPLY_LEFT_OUT -> setUpAgain()
            else -> startMeasured(intent)
        }
        return START_NOT_STICKY
    }

    /**
     * Starts the tunnel with the first hop's MTU of the network beneath, measured off the main thread
     * first. Before the tunnel is up no network beneath is followed yet, and Watch's sockets take the
     * default network.
     */
    private fun startMeasured(intent: Intent?) {
        if (active) return
        val ticket = ++starts
        measuring.execute {
            val chosen = measure(null)
            main.post {
                if (ticket == starts && !active) {
                    mtu = chosen
                    start(intent)
                }
            }
        }
    }

    /**
     * The tunnel's MTU follows the network beneath: [network]'s first hop is measured again, off the
     * main thread, and when it brings another value, by [TunnelMtu.next], the tunnel is set up again with
     * it, as for an address clash (ADR 0041). The apps' own kernels then meet that hop as they would
     * without Watch. Within one network the MTU rises only ten minutes after the last setup, so that a
     * route that flaps cannot set the tunnel up again and again.
     */
    private fun remeasure(network: Network) {
        measuring.execute {
            val measured = measure(network)
            main.post {
                if (!active || network != current) return@post
                val since = SystemClock.elapsedRealtime() - setUpAt
                val same = network == measuredOn
                val next = TunnelMtu.next(mtu, measured, sameNetwork = same, sinceSetUpMs = since)
                measuredOn = network
                if (next != mtu) {
                    mtu = next
                    setUpAgain()
                    return@post
                }
                // A rise held back is measured again once it may be taken: nothing else would ask, on a
                // network whose properties do not change.
                val wait = TunnelMtu.riseWait(mtu, measured, sameNetwork = same, sinceSetUpMs = since) ?: return@post
                main.removeCallbacksAndMessages(riseCheck)
                main.postDelayed({ if (active && network == current) remeasure(network) }, riseCheck, wait)
            }
        }
    }

    /**
     * What the kernel says of the first hop on [network], or the default network when null, and the
     * tunnel's MTU it gives. Each measure connects toward addresses drawn anew, so that no path MTU the
     * kernel keeps for one of them can steer the tunnel's.
     */
    private fun measure(network: Network?): Int {
        val v4 = firstHop(network, TunnelMtu.towardV4(Random.Default))
        val v6 = firstHop(network, TunnelMtu.towardV6(Random.Default))
        firstHops = v4 to v6
        return TunnelMtu.choose(v4, v6)
    }

    /**
     * The first hop's MTU toward [toward] on [network], as the kernel keeps it for the route (`IP_MTU`):
     * a UDP socket bound to the network, or protected where that is refused or no network is known yet,
     * and connected there, which sends nothing. Null when the kernel says nothing, as without a route
     * of that IP version.
     */
    private fun firstHop(network: Network?, toward: InetAddress): Int? {
        val family = if (toward is Inet4Address) OsConstants.AF_INET else OsConstants.AF_INET6
        val socket = try {
            Os.socket(family, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_UDP)
        } catch (e: ErrnoException) {
            return null
        }
        return try {
            ParcelFileDescriptor.dup(socket).use { duplicate ->
                val bound = network != null && try {
                    network.bindSocket(socket)
                    true
                } catch (e: IOException) {
                    false
                }
                if (!bound) protect(duplicate.fd)
                Os.connect(socket, toward, TunnelMtu.PORT)
                Engine.nativeRouteMtu(duplicate.fd).takeIf { it > 0 }
            }
        } catch (e: ErrnoException) {
            null
        } catch (e: IOException) {
            null
        } finally {
            try {
                Os.close(socket)
            } catch (e: ErrnoException) {
                Log.w(TAG, "The MTU probe's socket did not close", e)
            }
        }
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
            udp = settings.carriesUdp(remembered),
            logDestinations = settings.logDestinations,
        )
    }

    /** Looks for the tool again off the main thread, and applies the chain again where its proxy moved. */
    private fun refreshChain() {
        if (!org.visadahyu.datapavan.watch.chain.ChainSettings.of(this).on) return
        Thread {
            val search = org.visadahyu.datapavan.watch.chain.Tools.search(this, "service")
            val found = (search as? org.visadahyu.datapavan.watch.chain.ToolSearch.Answering)?.found ?: return@Thread
            val settings = org.visadahyu.datapavan.watch.chain.ChainSettings.of(this)
            val before = settings.lastTool
            settings.remember(found)
            if (settings.lastTool != before && active) applyChain()
        }.apply { name = "watch-chain" }.start()
    }

    private fun start(intent: Intent?) {
        if (active) return
        onlyApps = intent?.getStringExtra(EXTRA_ONLY_APPS)?.takeIf { debuggable }?.split(',')?.filter { it.isNotBlank() }
        // The chain before the engine, so that a chained app's first packet goes through the tool (W6,
        // ADR 0044, unit 12b), and before the tunnel too: from establish() on the apps' packets wait in
        // it until the engine reads them, and setting the chain reads Watch's settings and the tool table
        // and may use the Keystore. It needs no tunnel: with no engine running, Watch's native side keeps
        // the chain, nativeChain says false, which applyChain does not read, and the first engine starts
        // with it. The screen shows the chain's settings and whether the tunnel runs, neither of which
        // this changes. A start that fails, at establish() or after, stops, which forgets the chain.
        applyChain()
        val established = establish()
        // null: the user's consent is missing or was withdrawn.
        if (established == null || !startEngine(established)) {
            stop()
            return
        }
        setUpAt = SystemClock.elapsedRealtime()
        countersSince = setUpAt
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
     * Sets the tunnel up again for what changed, its MTU, its addresses or the apps left out,
     * make-before-break, so that nothing an app sends, a chained app's included, leaves outside the
     * tunnel meanwhile (re-review of unit 12, major 1). The new tunnel is established while the old
     * engine still runs on the old one: Android's `Vpn.establish` then keeps the VPN network and
     * updates it in place when only addresses or the MTU change, and connects a new network before it
     * disconnects the old one when the apps left out change (AOSP, `updateLinkPropertiesInPlaceIfPossible`
     * and `startNewNetworkAgent`); the old interface is reset only after that.
     *
     * Then, when Android kept the VPN network and the tunnel's addresses are the same ([TunnelSetup]), as
     * for a new MTU, the new tunnel is handed to the running engine, which goes on with it and keeps
     * everything, its connections, mappings, ping sockets, chain and counters among them, and closes the
     * old tunnel once it has read what was still queued there ([swapTunnel], ADR 0044, unit 12b).
     * Otherwise the old engine stops, closing the old tunnel, and one starts on the new tunnel, as when a
     * swap fails. When the apps handed to the Builder differ, as when the apps left out change, Android
     * brings up a new network, and the connections the engine accepted keep the old one's mark, so they
     * would route nowhere once it goes; reset at once by the new engine, the apps open new ones. When the
     * addresses differ, for an address clash (ADR 0041) or the debug `addresses-force`, the apps'
     * connections are bound to the old addresses and cannot go on, nor the engine's listeners and
     * rewriting. The old engine hands the new one, before its first packet, its chain as Watch last set
     * it, the network's resolver, its stand-ins, names and counters (`Engine::hand_over`, re-review of
     * unit 12, major 1), so that no chained app's packet goes directly meanwhile; its flows begin anew.
     * Either way nothing is set on the engine again after, so that no chain read from older settings
     * replaces a newer one. Android leaves the network callbacks as they are, so they are not registered
     * again.
     */
    private fun setUpAgain() {
        if (!active) return
        val before = setup
        val established = establish()
        if (established == null) {
            stop()
            return
        }
        // The same VPN network and addresses: the running engine takes the new tunnel and keeps its flows.
        // Otherwise, or when a swap failed, nativeStart stops the engine that runs, which closes the old
        // tunnel and hands over what it carries, before it starts anew.
        val after = setup
        val sameNetwork = after != null && TunnelSetup.canSwap(before, after)
        val kept = sameNetwork && swapTunnel(established)
        if (!kept && !startEngine(established)) {
            stop()
            return
        }
        if (kept) setupsKept++ else setupsAnew++
        // Which way a setup went is what a stalled connection after it first asks (ADR 0044, unit 12b).
        Log.i(
            TAG,
            when {
                kept -> "Set up again: the running engine took the new tunnel"
                sameNetwork -> "Set up again: the engine refused the new tunnel, a new engine took it"
                else -> "Set up again: another VPN network or other addresses, a new engine took it"
            },
        )
        setUpAt = SystemClock.elapsedRealtime()
    }

    /**
     * Hands the running engine [tunnel], set up again on the same VPN network with the same addresses, in
     * place of the one it reads ([Engine.nativeSwapTunnel]); whether it took it. The engine's read buffer, sized from the
     * first tunnel's MTU and never below 1,500 bytes, holds the new tunnel's packets too, since the
     * tunnel's MTU never goes above 1,500 ([TunnelMtu]). The engine takes a duplicate of the descriptor,
     * so that this one stays for [startEngine] when no engine runs or it could not take it; once it has
     * taken it, this one is closed, and the engine's keeps the tunnel up.
     */
    private fun swapTunnel(tunnel: ParcelFileDescriptor): Boolean {
        val duplicate = try {
            tunnel.dup()
        } catch (e: IOException) {
            Log.w(TAG, "The new tunnel's descriptor could not be duplicated", e)
            return false
        }
        if (!Engine.nativeSwapTunnel(duplicate.detachFd())) return false
        try {
            tunnel.close()
        } catch (e: IOException) {
            Log.w(TAG, "The new tunnel's own descriptor did not close", e)
        }
        return true
    }

    /**
     * A tunnel for this run's addresses, MTU and apps, established: null when the user's consent is
     * missing or was withdrawn, or Android refused it.
     */
    private fun establish(): ParcelFileDescriptor? {
        addresses = forced ?: TunnelAddresses.choose(networksBeneath())
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(mtu)
            // A /32 and a /128: a wider prefix would count as local network on Android 17 (ADR 0034).
            .addAddress(addresses.tun4, 32)
            .addAddress(addresses.tun6, 128)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            // The engine passes queries to this address on to the DNS server of the network beneath.
            .addDnsServer(addresses.dns4)
            .addDnsServer(addresses.dns6)
            // The engine reads until "would block" (spike, finding 8).
            .setBlocking(false)
            // A VPN that targets Android 10 or later is metered unless it says otherwise. Watch is
            // local, so the network keeps the meteredness of the Wi-Fi or mobile network beneath it.
            .setMetered(false)
        // A tunnel set up again keeps the network beneath that the callback named; Android takes the
        // new tunnel's underlying networks from its Builder.
        current?.let { builder.setUnderlyingNetworks(arrayOf(it)) }
        // The apps go to the Builder in sorted order, and the ones it took are kept with the setup: Android
        // compares them as ordered lists to decide whether it keeps the VPN network ([TunnelSetup]).
        var allowed = emptyList<String>()
        var disallowed = emptyList<String>()
        // Debug builds only: the end-to-end test sends only its own apps through the tunnel.
        val only = onlyApps
        if (!only.isNullOrEmpty()) {
            allowed = TunnelSetup.added(only + packageName) { app ->
                try {
                    builder.addAllowedApplication(app)
                    true
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.w(TAG, "Not installed: an app named for the test", e)
                    false
                }
            }
        } else {
            // The apps the user left out go to the internet directly, and Android does not give them the
            // VPN as their network (ADR 0041). Android allows either a list of apps inside or one of apps
            // outside, so the test's list above replaces this one.
            disallowed = TunnelSetup.added(LeftOut.of(this).apps) { app ->
                try {
                    builder.addDisallowedApplication(app)
                    true
                } catch (e: PackageManager.NameNotFoundException) {
                    Log.i(TAG, "An app left out is no longer installed", e)
                    false
                }
            }
        }
        val tunnel = try {
            builder.establish()
        } catch (e: IllegalStateException) {
            Log.w(TAG, "The tunnel could not be set up", e)
            null
        } catch (e: SecurityException) {
            Log.w(TAG, "The tunnel was not allowed", e)
            null
        }
        if (tunnel != null) setup = TunnelSetup(addresses, allowed, disallowed)
        return tunnel
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
        return Engine.nativeStart(
            this, fd, mtu, if (debuggable) KEPT_FLOWS else 0, tableFd, tableStart, tableLength,
            spareAddresses = addresses === TunnelAddresses.SPARE,
        )
    }

    private fun stop() {
        // A start still waiting for its measure does not come after it.
        starts++
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
        main.removeCallbacksAndMessages(riseCheck)
        setup = null
        current = null
        told = null
        toldDns = null
        measuredOn = null
        active = false
        state.value = false
        dnsState.value = null
    }

    /** Another VPN took Android's one VPN slot, or the user turned Watch off in Settings. */
    override fun onRevoke() {
        stop()
    }

    override fun onDestroy() {
        // A first start still waiting for its measure does not start a tunnel on a destroyed service.
        starts++
        close()
        measuring.shutdownNow()
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
     * engine's counters, with when they began ([countersSince]), and Private DNS, and in debug builds the
     * flows it kept and Private DNS's
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
        writer.println("addresses ${addresses.name} ${addresses.tun4} ${addresses.dns4} ${addresses.tun6} ${addresses.dns6}")
        writer.println("mtu $mtu first-hop ${firstHops.first ?: "-"} ${firstHops.second ?: "-"}")
        writer.println("setups kept $setupsKept anew $setupsAnew")
        writer.println("counters ${Engine.nativeCounters().joinToString(" ")}")
        writer.println("counters-since $countersSince")
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
            // The tunnel set up again with the spare or the common addresses, or as the networks choose,
            // by the same path as a network that comes to clash (ADR 0041).
            val force = args.orEmpty().indexOf("addresses-force").takeIf { it >= 0 }?.let { args?.getOrNull(it + 1) }
            if (force != null) {
                forced = when (force) {
                    "spare" -> TunnelAddresses.SPARE
                    "common" -> TunnelAddresses.COMMON
                    else -> null
                }
                main.post { setUpAgain() }
                writer.println("addresses-forced $force")
            }
            // The tunnel set up again with nothing changed, by the path a new MTU takes: the same addresses
            // and apps, so Android keeps its VPN network and the running engine takes the new tunnel and
            // keeps its flows (ADR 0044, unit 12b), which scripts/verify-watch.sh checks on a connection
            // kept open.
            if ("setup-again" in args.orEmpty()) {
                main.post { setUpAgain() }
                writer.println("setup-again")
            }
            debugChain(args.orEmpty().toList(), writer)
            if ("find-tool" in args.orEmpty()) {
                // Android runs dump on the main thread, where sockets are not allowed: the search runs
                // on a thread of its own, and this debug command waits for it.
                var found: org.visadahyu.datapavan.watch.chain.ToolSearch? = null
                Thread { found = org.visadahyu.datapavan.watch.chain.Tools.search(this, "dump") }.apply {
                    start()
                    join(SEARCH_WAIT_MS)
                }
                writer.println(found?.let(::describe) ?: "tool searching")
            }
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

        /** From Watch's screen: the apps left out changed, so the tunnel is set up again if it is up. */
        const val ACTION_APPLY_LEFT_OUT = "org.visadahyu.datapavan.watch.APPLY_LEFT_OUT"

        /** How long the debug command `find-tool` waits for the search. */
        private const val SEARCH_WAIT_MS = 10_000L

        /** The UID given for a tool that is not installed: no app has it. */
        private const val NO_UID = Int.MAX_VALUE

        /** Debug builds: a comma-separated list of the only apps to send through the tunnel. */
        const val EXTRA_ONLY_APPS = "only_apps"
        private const val TAG = "Watch"
        private const val KEPT_FLOWS = 512

        /** The asset of the table from address to organisation, stored uncompressed (build.gradle.kts). */
        private const val ORGANISATIONS = "asn.bin"


        private val state = MutableStateFlow(false)

        /** Whether the tunnel is up, for Watch's own screens. */
        val running: StateFlow<Boolean> = state.asStateFlow()

        private val dnsState = MutableStateFlow<PrivateDns?>(null)

        /** Private DNS on Watch's network while the tunnel is up, else null, for Watch's own screens. */
        val privateDns: StateFlow<PrivateDns?> = dnsState.asStateFlow()
    }
}
