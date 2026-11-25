package org.visadahyu.datapavan.network

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
import org.visadahyu.datapavan.network.activity.ProxyFacts
import org.visadahyu.datapavan.network.log.ConnectionLog
import org.visadahyu.datapavan.network.log.LogRecord

/**
 * The network part's VPN (docs/VPN.md). Every app's traffic enters the tunnel, and the packet engine in Rust
 * ([Engine]) passes it on to where it was going over sockets this service protects, after asking
 * Android whose each flow is. The network part is inside its own tunnel, as the engine needs (ADR 0012).
 *
 * Android starts this service in two ways: from the network screen with [ACTION_START] or [ACTION_STOP],
 * and with [VpnService.SERVICE_INTERFACE] when the user made the network part the always-on VPN. Both start the
 * tunnel. Android binds to the service while the tunnel is up, which keeps it running (ADR 0034).
 */
class NetworkVpnService : VpnService() {
    private var active = false

    /** The tunnel's addresses for this run (ADR 0041): the common ones, unless a network beneath uses them. */
    @Volatile
    private var addresses = TunnelAddresses.COMMON

    /** Debug builds: a set to take whatever the networks beneath, for scripts/verify-network.sh, which cannot make its network clash. */
    @Volatile
    private var forced: TunnelAddresses.Set? = null

    /**
     * What the tunnel was last established with that decides whether the running engine may take it when
     * it is set up again ([setUpAgain]); [close] forgets it. Main thread only.
     */
    private var setup: TunnelSetup? = null
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val debuggable by lazy { applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }

    /** The network beneath that [network] follows; read by [resolveEndpoint] on the engine's resolver thread. */
    @Volatile
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
     * When the engine's counters began, by [SystemClock.elapsedRealtime]: at the network part's start of its engine,
     * and kept when a new engine takes the tunnel, to which the old one hands its counters. A test that
     * reads a counter twice tells by it an engine started afresh between, whose counters began again at
     * 0, from one that counted nothing (ADR 0044, unit 9b, fix round 2).
     */
    private var countersSince = 0L

    /**
     * Reads the apps' states for the engine while the tunnel runs (ADR 0046, decision 1); null while it does
     * not. Set on the main thread, read from the engine's ([statesWanted]).
     */
    @Volatile
    private var tracker: org.visadahyu.datapavan.network.activity.StateTracker? = null

    /** The token of the measure posted for when a rise held back may be taken; [close] drops it. */
    private val riseCheck = Any()

    /**
     * The tunnel's MTU for this run (ADR 0044, the proposal for decision 5): the first hop's of the network
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
        Thread(task, "network-mtu").apply { isDaemon = true }
    }

    /**
     * Every start asked for: one that waits for its measure goes ahead only while it is the last, and no
     * stop came since. Main thread only.
     */
    private var starts = 0

    /**
     * Carries the encrypted resolver's exchanges for the engine (W8, part 1, ADR 0042): DoH, ODoH and DoT over
     * Android's own TLS from sockets protected from the tunnel and bound to the network beneath, or through the
     * user's tool; the network's resolver through Android's own on the network beneath.
     */
    private val exchanger = org.visadahyu.datapavan.network.dns.Exchanger(
        object : org.visadahyu.datapavan.network.dns.Exchanger.Host {
            override fun protect(socket: java.net.Socket): Boolean = this@NetworkVpnService.protect(socket)

            override fun protect(socket: java.net.DatagramSocket): Boolean = this@NetworkVpnService.protect(socket)

            override val network: Network? get() = current

            override val generation: Int get() = networkGeneration

            override val extraRoots: List<java.security.cert.X509Certificate> get() = labRoots()

            override val resolverProxy: org.visadahyu.datapavan.network.dns.ResolverProxy?
                get() = this@NetworkVpnService.resolverProxy
        },
    )

    /**
     * The network beneath's own proxy the resolver follows on purpose (ADR 0042, "Android's proxy";
     * [org.visadahyu.datapavan.network.dns.NetworkProxy]), for the network of its generation; null for none. Set
     * under [resolverProxyLock] by [recomputeResolverProxy].
     */
    @Volatile
    private var resolverProxy: org.visadahyu.datapavan.network.dns.ResolverProxy? = null

    /** Why the resolver follows the proxy it does, for the debug dump's `dns-proxy` line. */
    @Volatile
    private var resolverProxyWhy = org.visadahyu.datapavan.network.dns.NetworkProxy.Why.NONE

    private val resolverProxyLock = Any()

    /** Raised by each recompute, so that a lookup of the proxy's name that ends after a newer one is dropped. */
    private var resolverProxyAsked = 0

    /** Looks a proxy's name up, one at a time, off the main thread and through the network it belongs to. */
    private val resolverProxyLookups = java.util.concurrent.Executors.newSingleThreadExecutor { task ->
        Thread(task, "network-dns-proxy").apply { isDaemon = true }
    }

    /** The data pack's public suffixes, read once, for the network's search domains. */
    private val suffixes by lazy { org.visadahyu.datapavan.network.dns.DnsSettings.suffixes(this) }

    /**
     * Hands tracker blocking to the engine on a thread of its own (W8, part 3a; ADR 0053): the table at each start and
     * when the data pack changes, the setting whole at each start and whenever what it depends on changes.
     */
    private val blocking = org.visadahyu.datapavan.network.blocking.BlockingHandover(this)

    /** Changes with the network beneath, so that each has its own clients and TLS sessions. */
    @Volatile
    private var networkGeneration = 0

    /** Whether Android validated the network beneath, and its search domains, last told to the engine. */
    private var toldValidated: Pair<Boolean, String>? = null

    /**
     * Debug builds: validation as scripts/verify-dns.sh sets it, in place of Android's, since the DNS lab's network
     * resolver knows only the lab's names and Android's own check of the network can never pass there.
     */
    @Volatile
    private var validatedForTests: Boolean? = null

    /** Follows the network beneath the tunnel: Wi-Fi, mobile data, or none. */
    private val network = object : ConnectivityManager.NetworkCallback() {

        override fun onAvailable(network: Network) {
            if (network != current) {
                // The network first, then its generation, then the exchanger: an exchange that reads the new generation
                // binds its sockets to the new network, and what one that read the old generation opens is never kept
                // (the DoT crash's audit, finding 1).
                current = network
                networkGeneration++
                // The new network's proxy before the first client of its generation is built (the resolver's audit, M5).
                recomputeResolverProxy()
                exchanger.networkChanged()
                exchanger.warm()
                // The search domains of the network before go with it, before this one's arrive (review S-C1).
                tellDnsNetwork(null, "")
            }
            setUnderlyingNetworks(arrayOf(network))
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (network != current) return
            // Behind a captive portal Android does not validate the network: the encrypted ways' failures do not
            // count meanwhile (W8, part 1, point 6).
            tellDnsNetwork(capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), null)
        }

        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            // A network that now uses the tunnel's addresses itself would lose its router and resolver
            // to the tunnel: the tunnel is set up again with the other set (ADR 0041).
            if ((forced ?: TunnelAddresses.choose(networksBeneath())) !== addresses) {
                main.post { setUpAgain() }
            }
            if (network != current) return
            remeasure(network)
            // The network's search domains, but for public suffixes (W8's fix round, review S-C1): a name under one
            // goes to the network's resolver only when the encrypted way says it does not exist.
            tellDnsNetwork(null, org.visadahyu.datapavan.network.dns.SearchDomains.accepted(properties.domains.orEmpty(), suffixes))
            // A link-local DNS server needs its interface's scope, which the engine does not take.
            val dns = properties.dnsServers.firstOrNull { !it.isLinkLocalAddress }?.hostAddress ?: ""
            // Android reports a network's properties several times after a switch; only a new network
            // closes the engine's UDP flows, and nothing the engine already knows is sent again.
            // A network's own proxy setting may have changed with its properties (ADR 0052).
            main.post { if (active) applyProxies() }
            recomputeResolverProxy()
            if (network == told && dns == toldDns) return
            Engine.nativeNetworkChanged(dns, network != told)
            told = network
            toldDns = dns
        }

        override fun onLost(network: Network) {
            if (network != current) return
            // In the same order as onAvailable's.
            current = null
            networkGeneration++
            recomputeResolverProxy()
            exchanger.networkChanged()
            setUnderlyingNetworks(null)
            Engine.nativeNetworkChanged("", true)
            told = null
            toldDns = null
        }
    }

    /**
     * Follows Private DNS on the network part's own default network, which is its VPN while the tunnel is up:
     * what Android does with the lookups of every app in the tunnel.
     */
    private val ownNetwork = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
            val was = dnsState.value
            dnsState.value = PrivateDns.of(properties)
            if ((was is PrivateDns.Strict) != (dnsState.value is PrivateDns.Strict)) main.post { if (active) applyProxies() }
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
            // The tunnels' routes before the chain, from the store as it stands: an app the screen moved from the tool
            // to a configuration has its tunnel's route in the engine before it leaves the chain's list, so that it
            // never goes directly in between (fix round, security review M2).
            ACTION_APPLY_CHAIN -> if (active) applyRoutes()
            ACTION_APPLY_TUNNELS -> if (active) applyTunnels()
            // A tap of the undo or the pause reads nothing again; a setting that changes what is covered reads all.
            ACTION_APPLY_BLOCKING -> if (active) blocking.apply(full = intent.getBooleanExtra(EXTRA_FULL, true))
            // The apps left out are part of the tunnel's own setup: it is set up again. The routes first: an app taken
            // back has its tunnel's or the chain's route in the engine before its packets come into the tunnel again,
            // never going directly; an app left out leaves them, as it leaves the network part (fix round, security
            // review M1).
            ACTION_APPLY_LEFT_OUT -> {
                if (active) applyRoutes()
                setUpAgain()
            }
            else -> startMeasured(intent)
        }
        return START_NOT_STICKY
    }

    /**
     * Starts the tunnel with the first hop's MTU of the network beneath, measured off the main thread
     * first. Before the tunnel is up no network beneath is followed yet, and the network part's sockets take the
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
     * without the network part. Within one network the MTU rises only ten minutes after the last setup, so that a
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
     * Hands the engine every app's route again from what the network part keeps, the tunnels' before the chain's: each
     * by its UID as Android has it now. Main thread only.
     */
    private fun applyRoutes() {
        applyTunnels()
        applyChain()
        applyProxies()
        // Who tracker blocking covers follows the apps installed, their UIDs and the user's tool (W8, part 3a).
        blocking.apply(full = true)
    }

    /**
     * Debug builds: packages of this project's own fixtures added to a messenger's clients through the dump (W8, part
     * 2a; `messenger-client FAMILY PACKAGE`), by family code; never a real app's package. Main thread only.
     */
    private val debugClients = mutableMapOf<String, Int>()

    /**
     * Hands the engine the messengers' apps, by the UIDs Android gives their packages now (`data/messengers`, through
     * the engine's own table), and the proxies Android's setting names: the global one and each network's (W8, part
     * 2a, ADR 0052). The engine reads each new flow of those apps for their proxies, and tells Android's setting from
     * an app's own. Main thread only.
     */
    private fun applyProxies() {
        val clients = Engine.nativeMessengerClients().lineSequence().mapNotNull { line ->
            val parts = line.split(' ')
            val family = MESSENGER_FAMILIES.indexOf(parts.firstOrNull())
            if (parts.size == 2 && family >= 0) parts[1] to family else null
        } + debugClients.toList().asSequence()
        val messengers = clients.mapNotNull { (name, family) ->
            try {
                @Suppress("DEPRECATION")
                family to packageManager.getApplicationInfo(name, 0).uid
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
        }.distinct().toList()
        val proxies = buildList {
            connectivity.defaultProxy?.let(::add)
            @Suppress("DEPRECATION")
            for (network in connectivity.allNetworks) connectivity.getLinkProperties(network)?.httpProxy?.let(::add)
        }
        // A proxy given by a PAC file is found by Android on the phone's loopback, which never enters the tunnel.
        val android = proxies.filter { it.host != null && it.port in 1..65535 }.map { "${it.host} ${it.port}" }.distinct()
        Engine.nativeProxies(
            messengers.map { it.first }.toIntArray(),
            messengers.map { it.second }.toIntArray(),
            android.joinToString("\n"),
            // With Private DNS strict, Android's resolver asks its provider over TLS: the network part sees no app's
            // lookups, and a messenger's hello no answer tied is no evidence of its proxy (ADR 0052, fix round's S-M3).
            dnsState.value is PrivateDns.Strict,
        )
    }

    /**
     * Reads the network beneath's own proxy for the resolver (ADR 0042, "Android's proxy"): a literal at once, a name
     * through that network on [resolverProxyLookups], whose answer counts only while it is the latest recompute and the
     * network's generation is unchanged. A proxy the same as the one held keeps it, with what it remembers of a refusal;
     * another one tells the exchanger, which drops the clients built for the one before. Any thread: the network
     * callbacks', the main one, the dump's.
     */
    private fun recomputeResolverProxy() {
        val network = current
        val generation = networkGeneration
        val asked = synchronized(resolverProxyLock) { ++resolverProxyAsked }
        val properties = network?.let { connectivity.getLinkProperties(it) }
        val (setting, why) = org.visadahyu.datapavan.network.dns.NetworkProxy.choose(
            org.visadahyu.datapavan.network.dns.NetworkProxy.of(properties?.httpProxy),
        )
        if (network == null || properties == null || setting == null) return settleResolverProxy(asked, generation, null, emptyList(), why)
        val own = (properties.linkAddresses.map { it.address } + addresses.all.mapNotNull { org.visadahyu.datapavan.network.dns.Exchanger.numeric(it) }).toSet()
        val literal = org.visadahyu.datapavan.network.dns.Exchanger.numeric(org.visadahyu.datapavan.network.dns.NetworkProxy.bare(setting.host))
        if (literal != null) return settleResolverProxy(asked, generation, setting, listOf(literal), why, own)
        resolverProxyLookups.execute {
            val found = try {
                network.getAllByName(setting.host).toList()
            } catch (e: java.net.UnknownHostException) {
                emptyList()
            } catch (e: SecurityException) {
                emptyList()
            }
            settleResolverProxy(asked, generation, setting, found, why, own)
        }
    }

    /** Keeps the proxy [recomputeResolverProxy] read, unless a newer recompute or another network came since. */
    private fun settleResolverProxy(
        asked: Int,
        generation: Int,
        setting: org.visadahyu.datapavan.network.dns.NetworkProxy.Setting?,
        found: List<java.net.InetAddress>,
        why: org.visadahyu.datapavan.network.dns.NetworkProxy.Why,
        own: Set<java.net.InetAddress> = emptySet(),
    ) {
        val changed = synchronized(resolverProxyLock) {
            if (asked != resolverProxyAsked || generation != networkGeneration) return
            val (usable, because) = if (setting == null) {
                emptyList<java.net.InetAddress>() to why
            } else {
                org.visadahyu.datapavan.network.dns.NetworkProxy.usable(found.filterNot(org.visadahyu.datapavan.network.dns.NetworkProxy::zoned)) { it in own }
            }
            val next = if (setting != null && usable.isNotEmpty()) {
                org.visadahyu.datapavan.network.dns.ResolverProxy(generation, setting, usable.map { java.net.InetSocketAddress(it, setting.port) })
            } else {
                null
            }
            resolverProxyWhy = if (next == null && setting != null && usable.isEmpty()) because else why
            val held = resolverProxy
            val same = held != null && next != null && held.generation == next.generation && held.setting == next.setting &&
                held.addresses == next.addresses
            if (same || (held == null && next == null)) {
                false
            } else {
                resolverProxy = next
                true
            }
        }
        if (changed) exchanger.proxyChanged()
    }

    /** The receiver of Android's proxy setting's changes, while the tunnel runs. */
    private var proxyChanges: android.content.BroadcastReceiver? = null

    /** Follows Android's proxy setting while the tunnel runs (ADR 0052): the engine tells it from an app's own. */
    private fun followProxySetting() {
        if (proxyChanges != null) return
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context, intent: Intent) {
                if (active) applyProxies()
                recomputeResolverProxy()
            }
        }
        // A protected broadcast that only the system sends.
        androidx.core.content.ContextCompat.registerReceiver(
            this, receiver, android.content.IntentFilter(android.net.Proxy.PROXY_CHANGE_ACTION),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        proxyChanges = receiver
    }

    /**
     * Follows the apps installed, installed again, updated and removed while the tunnel runs (fix round, security
     * review M1): routes go by UID, and an app installed again (another build in place of the store's) has a new one,
     * so every route is handed to the engine again from the store and the chain's settings, which name apps by
     * package. Without this, such an app went its other way, directly perhaps, until the network part started again.
     */
    private fun followPackages() {
        if (packages != null || packagesOff) return
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context, intent: Intent) {
                if (active) applyRoutes()
            }
        }
        val filter = android.content.IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        androidx.core.content.ContextCompat.registerReceiver(this, receiver, filter, androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED)
        packages = receiver
    }

    /** The receiver of [followPackages], while the tunnel runs. */
    private var packages: android.content.BroadcastReceiver? = null

    /** What [followBlockingFiles] watches while the tunnel runs, and the token of the handover a change posted. */
    private var blockingFiles: List<android.os.FileObserver> = emptyList()
    private val blockingFilesChanged = Any()

    /**
     * Follows the files tracker blocking reads while the tunnel runs (W8, part 3a): the audit's scan of the apps' code
     * (`tracker-scan.tsv`), which decides the rows a code-dependent grade leaves to each app, and the data pack the user
     * imports, which holds the table. Both are written by the audit's process, to a file of their own then moved into
     * place: a change hands blocking over again once the writes settle, since a first scan saves every few apps.
     */
    private fun followBlockingFiles() {
        if (blockingFiles.isNotEmpty()) return
        val pack = java.io.File(noBackupFilesDir, PACK_DIRECTORY)
        val watched = listOf(
            noBackupFilesDir to setOf(org.visadahyu.datapavan.network.blocking.ScanResults.FILE, PACK_DIRECTORY),
            pack to setOf("installed.pack", "installed.chain"),
        )
        blockingFiles = watched.filter { it.first.isDirectory }.map { (directory, names) ->
            val events = android.os.FileObserver.CLOSE_WRITE or android.os.FileObserver.MOVED_TO or
                android.os.FileObserver.DELETE or android.os.FileObserver.CREATE
            object : android.os.FileObserver(directory, events) {
                override fun onEvent(event: Int, path: String?) {
                    if (path == null || path !in names) return
                    main.removeCallbacksAndMessages(blockingFilesChanged)
                    main.postDelayed(
                        {
                            if (!active) return@postDelayed
                            // The pack's folder made since the start, by the first import: followed from now on.
                            if (path == PACK_DIRECTORY && blockingFiles.size < watched.size) {
                                blockingFiles.forEach { it.stopWatching() }
                                blockingFiles = emptyList()
                                followBlockingFiles()
                            }
                            blocking.apply(full = true)
                        },
                        blockingFilesChanged, FILES_SETTLE_MS,
                    )
                }
            }.also { it.startWatching() }
        }
    }

    /** Debug builds: the receiver turned off through the dump (`packages-follow off`), for the check of the ask. */
    private var packagesOff = false

    /**
     * Hands the user's chain (W6) to the engine: the tool's proxy where it last answered, its password
     * where the tool takes one, the tool's UID, and the chained apps. It runs before any traffic, from
     * what the network part remembers, so that chained apps never go directly while the tool is looked for again;
     * a tool that is not there leaves them waiting, not going directly.
     */
    private fun applyChain() {
        val settings = org.visadahyu.datapavan.network.chain.ChainSettings.of(this)
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
            org.visadahyu.datapavan.network.chain.Tools.table(this).find { it.packageName == remembered.packageName }
        } catch (e: java.io.IOException) {
            null
        }
        val password = settings.password().takeIf { known?.auth != "none" }
        val user = org.visadahyu.datapavan.network.chain.ChainSettings.userFor(remembered.packageName)
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

    /**
     * The configurations set in the engine this run, each with what it was set from: its text's file as it stood
     * and its "Local network directly", so that a configuration that did not change is not opened again. Main
     * thread only; [close] forgets them, as stopping the engine forgets its tunnels.
     */
    private val tunnelsSet = mutableMapOf<Int, Pair<Long, Boolean>>()

    /** Whether a configuration waits for the phone's unlock, and the receiver that sets it then. */
    private var unlockWait: android.content.BroadcastReceiver? = null

    /**
     * How many times in a row a configuration could not be opened now (a Keystore error that is not a lost key, or a
     * file that could not be read), and the token of the next try ([TunnelStore.retryAfterMs], fix round, security
     * review m2). Main thread only.
     */
    private var reopenTries = 0
    private val reopen = Any()

    /** The routes last handed to the engine, by UID, for the debug builds' dump. Main thread only. */
    private var routesSet: List<Pair<Int, Int>> = emptyList()

    /**
     * Hands the engine the WireGuard configurations the network part keeps and each app's tunnel (W7, part 2), before
     * any traffic at a start, as the chain is, and again when the screen changes them: each configuration's text is
     * opened only to be set and zeroed at once; a configuration whose wrap cannot be opened, because its key is gone
     * or needs an unlocked phone, is not set, and its apps wait, routed to it, never going directly. The engine
     * keeps them for the engines to come while none runs; the default tunnel goes first.
     */
    private fun applyTunnels() {
        val store = org.visadahyu.datapavan.network.tunnel.TunnelStore.of(this)
        val state = try {
            store.state()
        } catch (e: Exception) {
            if (e !is IOException && e !is java.security.GeneralSecurityException) throw e
            // The engine keeps what it has, every route among it, and the store is read again shortly. At a start,
            // before any route was handed, nothing tells which apps go through a configuration: every app is held,
            // never sent directly, until the state opens (W7, part 2, fix round, the maintainer's decision on key B).
            Log.w(TAG, "The configurations' state could not be read", e)
            if (e is org.visadahyu.datapavan.network.tunnel.TunnelStore.StateLost) {
                // Lost for good, while the store held a configuration or a route: every app is held, also while
                // it runs, until the user chooses on the network screen, which one notification opens (the
                // maintainer's word of 2026-11-20). Trying again would not open it.
                holdEveryApp()
                Notices.show(this, Notices.Kind.LOST, true)
                return
            }
            if (!routesKnown) holdEveryApp()
            tryAgainLater(unavailable = true)
            return
        }
        Notices.show(this, Notices.Kind.LOST, false)
        for (gone in tunnelsSet.keys - state.order.toSet()) {
            Engine.nativeTunnelRemove(gone)
            tunnelsSet.remove(gone)
        }
        var locked = false
        var unavailable = false
        for (slot in state.order) {
            val local = slot in state.local
            val stamp = store.stamp(slot) to local
            if (tunnelsSet[slot] == stamp) continue
            when (val opened = store.text(slot)) {
                is org.visadahyu.datapavan.network.tunnel.Opened.Plain -> try {
                    val why = Engine.nativeTunnelSet(slot, opened.bytes, local)
                    if (why.isEmpty()) tunnelsSet[slot] = stamp else Log.w(TAG, "A configuration was refused: $why")
                } finally {
                    opened.bytes.fill(0)
                }
                org.visadahyu.datapavan.network.tunnel.Opened.Locked -> locked = true
                // Its apps wait, and it is tried again, a few times (m2).
                org.visadahyu.datapavan.network.tunnel.Opened.Unavailable -> unavailable = true
                // Its apps wait: the route stays, and the engine refuses their flows.
                org.visadahyu.datapavan.network.tunnel.Opened.Lost -> Log.w(TAG, "A configuration can no longer be opened")
            }
        }
        // The user's default first, set or not: while it is not set, flows of no app and pings wait for it (m4).
        Engine.nativeTunnelOrder(state.order.toIntArray())
        val routes = org.visadahyu.datapavan.network.tunnel.Routes.forEngine(state.routes, LeftOut.of(this).apps) { app ->
            try {
                @Suppress("DEPRECATION")
                packageManager.getApplicationInfo(app, 0).uid
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }
        }
        // Debug builds: the routes part 1's check set through the dump's hook stay, now that the store's are handed
        // again on more occasions (a chain's change, an app installed); theirs win for their UIDs.
        val handed = (routes.toMap() + debugRoutes).toList()
        Engine.nativeTunnelRoutes(
            handed.map { it.first }.toIntArray(),
            handed.map { it.second }.toIntArray(),
            logDestinations = org.visadahyu.datapavan.network.chain.ChainSettings.of(this).logDestinations,
        )
        routesSet = handed
        routesKnown = true
        // Every installed app's UID, while any app is routed: one installed since is asked of the network part at its
        // first flow (routeOfApp), never sent on a default way before the network part says where (the maintainer,
        // 2026-11-20).
        val chain = org.visadahyu.datapavan.network.chain.ChainSettings.of(this)
        Engine.nativeKnownApps(if (state.routes.isNotEmpty() || (chain.on && chain.lastTool != null)) installedUids() else null)
        if (locked) waitForUnlock() else stopWaitingForUnlock()
        Notices.show(this, Notices.Kind.UNLOCK, locked)
        tryAgainLater(unavailable)
    }

    /** Every installed app's UID. */
    // Every app: Datapavan Advanced holds QUERY_ALL_PACKAGES, the audit's (ADR 0014), which this library's own manifest
    // does not name.
    @android.annotation.SuppressLint("QueryPermissionsNeeded")
    private fun installedUids(): IntArray {
        @Suppress("DEPRECATION")
        return packageManager.getInstalledApplications(0).map { it.uid }.distinct().toIntArray()
    }

    /**
     * Called by the engine, on a thread of its own, for a flow of the app [uid], which the network part did not name
     * when it last handed its routes over (an app installed since, as one installed again with a new UID): where the
     * store sends its packages, `tunnel N`, `tool` or `direct`, by the rules the routes are handed by; empty where the
     * network part cannot say, as while the state cannot be opened, and the engine then refuses the flow. The engine
     * waits for it at most three seconds (`ASK_BOUND`), so nothing here may wait on the main thread.
     */
    @Suppress("unused")
    fun routeOfApp(uid: Int): String {
        val packages = packageManager.getPackagesForUid(uid)?.sorted() ?: return ""
        val state = try {
            org.visadahyu.datapavan.network.tunnel.TunnelStore.of(this).state()
        } catch (e: IOException) {
            return ""
        } catch (e: java.security.GeneralSecurityException) {
            return ""
        }
        val left = LeftOut.of(this).apps
        // As Routes.forEngine: packages that share a UID share a route, the first by name deciding.
        packages.firstOrNull { it !in left && it in state.routes }?.let { return "tunnel ${state.routes.getValue(it)}" }
        val chain = org.visadahyu.datapavan.network.chain.ChainSettings.of(this)
        val tool = chain.lastTool?.packageName
        val chained = chain.on && tool != null && tool !in packages &&
            (chain.allApps || packages.any { it !in left && it in chain.apps })
        return if (chained) "tool" else "direct"
    }

    /** Whether this run handed the engine the routes from the store at least once. Main thread only. */
    private var routesKnown = false

    /**
     * Holds every installed app, routed to a tunnel no configuration has, so that its flows are refused and none goes
     * directly, with flows of no app and pings: while the store's state cannot be opened at a start, nothing tells
     * which apps go through a configuration. The store's routes replace these once it opens.
     */
    // Every app: Datapavan Advanced holds QUERY_ALL_PACKAGES, the audit's (ADR 0014), which this library's own manifest
    // does not name.
    @android.annotation.SuppressLint("QueryPermissionsNeeded")
    private fun holdEveryApp() {
        @Suppress("DEPRECATION")
        val uids = packageManager.getInstalledApplications(0).map { it.uid }.distinct()
        Engine.nativeTunnelOrder(intArrayOf(HOLD_TUNNEL))
        Engine.nativeTunnelRoutes(uids.toIntArray(), IntArray(uids.size) { HOLD_TUNNEL }, logDestinations = false)
        // An app installed meanwhile is asked of the network part, which cannot say: it is held too.
        Engine.nativeKnownApps(uids.toIntArray())
        routesSet = uids.map { it to HOLD_TUNNEL }
        Log.w(TAG, "Every app is held until the configurations' state opens")
    }

    /**
     * A configuration that could not be opened now is tried again after a pause that grows, a few times
     * ([org.visadahyu.datapavan.network.tunnel.TunnelStore.retryAfterMs]); then not until the next change, start or
     * unlock. Its apps wait meanwhile, never going directly.
     */
    private fun tryAgainLater(unavailable: Boolean) {
        main.removeCallbacksAndMessages(reopen)
        if (!unavailable) {
            reopenTries = 0
            return
        }
        val wait = org.visadahyu.datapavan.network.tunnel.TunnelStore.retryAfterMs(reopenTries++) ?: return
        main.postDelayed({ if (active) applyTunnels() }, reopen, wait)
    }

    /** A configuration whose key needs an unlocked phone waits for the unlock, and is set then. */
    private fun waitForUnlock() {
        if (unlockWait != null) return
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context, intent: Intent) {
                unlocksSeen++
                if (active) afterUnlock(0)
            }
        }
        // Exported: the unlock is told by the keyguard in SystemUI's process, whose broadcast a receiver that is not
        // exported never gets, as the emulator showed (part 2's code waited forever); USER_PRESENT is a protected
        // broadcast, which no app can send.
        androidx.core.content.ContextCompat.registerReceiver(
            this, receiver, android.content.IntentFilter(Intent.ACTION_USER_PRESENT), androidx.core.content.ContextCompat.RECEIVER_EXPORTED,
        )
        unlockWait = receiver
    }

    private fun stopWaitingForUnlock() {
        unlockWait?.let { unregisterReceiver(it) }
        unlockWait = null
        main.removeCallbacksAndMessages(unlocking)
    }

    /**
     * The phone was unlocked: the configurations that waited for it are set. Android may tell the unlock a moment
     * before the Keystore lets a key that needs it be used, so a configuration still closed is tried again a few
     * times, after 1, 2, 4 and 8 s.
     */
    private fun afterUnlock(attempt: Int) {
        applyTunnels()
        if (unlockWait == null) return
        val wait = UNLOCK_RETRIES_MS.getOrNull(attempt) ?: return
        main.postDelayed({ if (active) afterUnlock(attempt + 1) }, unlocking, wait)
    }

    /** The token of [afterUnlock]'s tries, and how many unlocks this run saw, for the dump. Main thread only. */
    private val unlocking = Any()
    private var unlocksSeen = 0

    /** Looks for the tool again off the main thread, and applies the chain again where its proxy moved. */
    private fun refreshChain() {
        if (!org.visadahyu.datapavan.network.chain.ChainSettings.of(this).on) return
        Thread {
            val search = org.visadahyu.datapavan.network.chain.Tools.search(this, "service")
            val found = (search as? org.visadahyu.datapavan.network.chain.ToolSearch.Answering)?.found ?: return@Thread
            val settings = org.visadahyu.datapavan.network.chain.ChainSettings.of(this)
            val before = settings.lastTool
            settings.remember(found)
            // On the main thread, behind any change the screen sent, the tunnels' routes first (M2).
            if (settings.lastTool != before) main.post { if (active) applyRoutes() }
        }.apply { name = "network-chain" }.start()
    }

    private fun start(intent: Intent?) {
        if (active) return
        onlyApps = intent?.getStringExtra(EXTRA_ONLY_APPS)?.takeIf { debuggable }?.split(',')?.filter { it.isNotBlank() }
        // The chain before the engine, so that a chained app's first packet goes through the tool (W6,
        // ADR 0044, unit 12b), and before the tunnel too: from establish() on the apps' packets wait in
        // it until the engine reads them, and setting the chain reads the network part's settings and the tool table
        // and may use the Keystore. It needs no tunnel: with no engine running, the network part's native side keeps
        // the chain, nativeChain says false, which applyChain does not read, and the first engine starts
        // with it. The screen shows the chain's settings and whether the tunnel runs, neither of which
        // this changes. A start that fails, at establish() or after, stops, which forgets the chain.
        applyChain()
        // The WireGuard configurations and their apps' routes likewise (W7, part 2): a tunnelled app's first packet
        // goes through its tunnel, or waits for it, and never directly. A photo of a QR code a crash left goes too.
        org.visadahyu.datapavan.network.tunnel.qr.Capture.deleteLeftovers(this, keep = MainActivity.pendingCapture)
        applyTunnels()
        // The messengers' apps and Android's proxy setting likewise (W8, part 2a): a messenger's first flow is read
        // for its proxy.
        applyProxies()
        // Tracker blocking's table and setting (W8, part 3a), off the main thread, since they read the data pack, the
        // apps and the audit's scan: the engine's first flows may come before them, and are then not blocked; the
        // library keeps the setting for the engine that starts.
        blocking.apply(full = true, fresh = true)
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
        tracker = org.visadahyu.datapavan.network.activity.StateTracker(this) { Engine.nativeStates(it) }.also { it.start() }
        followPackages()
        followProxySetting()
        followBlockingFiles()
        refreshChain()
        ConnectionLog.of(this).expire()
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val handler = Handler(Looper.getMainLooper())
        // The network part is inside its own tunnel, so its default network is its own VPN. From Android 12 the
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
     * rewriting. The old engine hands the new one, before its first packet, its chain as the network part last set
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
            // A VPN that targets Android 10 or later is metered unless it says otherwise. The network part is
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
        // The encrypted resolver before the engine's first packet: no direct app's lookup goes to the network's
        // resolver while it is set (W8, part 1). The first exchange's client and roots, and the public suffixes for the
        // network's search domains, are made ready meanwhile (W8's fix round).
        org.visadahyu.datapavan.network.dns.DnsSettings.apply(this)
        recomputeResolverProxy()
        exchanger.warm()
        suffixes.known
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
        val started = Engine.nativeStart(
            this, fd, mtu, if (debuggable) KEPT_FLOWS else 0, tableFd, tableStart, tableLength,
            spareAddresses = addresses === TunnelAddresses.SPARE,
        )
        // The trackers' table, off the main thread, for the marks a proxied flow keeps while its names are left out
        // (ADR 0052): "Now" reads it again when it opens.
        if (started) measuring.execute { NowActivity.loadTables(this) }
        return started
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
        // A last reading of the states, so that what the engine holds is placed before it stops.
        tracker?.stop()
        tracker = null
        Engine.nativeStop()
        // The encrypted resolver's connections go with the run, closed off the main thread: the engine is gone.
        exchanger.stop()
        // Stopping the engine forgot its tunnels: the next start sets them again.
        tunnelsSet.clear()
        routesSet = emptyList()
        routesKnown = false
        Notices.show(this, Notices.Kind.UNLOCK, false)
        Notices.show(this, Notices.Kind.LOST, false)
        Notices.show(this, Notices.Kind.DNS_FALLBACK, false)
        toldValidated = null
        stopWaitingForUnlock()
        packages?.let { unregisterReceiver(it) }
        packages = null
        proxyChanges?.let { unregisterReceiver(it) }
        proxyChanges = null
        blockingFiles.forEach { it.stopWatching() }
        blockingFiles = emptyList()
        main.removeCallbacksAndMessages(blockingFilesChanged)
        main.removeCallbacksAndMessages(reopen)
        reopenTries = 0
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

    /** Another VPN took Android's one VPN slot, or the user turned the network part off in Settings. */
    override fun onRevoke() {
        stop()
    }

    override fun onCreate() {
        super.onCreate()
        exchangerNow = exchanger
    }

    override fun onDestroy() {
        if (exchangerNow === exchanger) exchangerNow = null
        // A first start still waiting for its measure does not start a tunnel on a destroyed service.
        starts++
        close()
        measuring.shutdownNow()
        blocking.shutdown()
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
     * Called by the engine, on a thread of its own, for a WireGuard endpoint's name (W7, the maintainer's answer
     * 4 of 2026-11-19): asked of Android's own resolver on the network beneath the tunnel, never through the
     * tunnel, so that the user's Private DNS applies to it. Returns `encrypted` or `plain`, as Android says it
     * resolves on that network, then the addresses; null where there is no network beneath, and the engine then
     * asks the network's resolver itself, in plain DNS, and says so. Android's "automatic" mode may fall back
     * to plain DNS when the server's DNS over TLS fails (ADR 0035).
     */
    @Suppress("unused")
    fun resolveEndpoint(name: String): String? {
        val network = current ?: return null
        val encrypted = connectivity.getLinkProperties(network)?.isPrivateDnsActive == true
        val word = if (encrypted) "encrypted" else "plain"
        return try {
            (listOf(word) + network.getAllByName(name).mapNotNull { it.hostAddress }).joinToString(" ")
        } catch (e: java.net.UnknownHostException) {
            word
        } catch (e: SecurityException) {
            null
        }
    }

    /**
     * Called by the engine, on its own thread, for each exchange of its encrypted resolver (W8, part 1): hands it to
     * the exchanger and returns at once; the reply goes back by [Engine.nativeExchanged].
     */
    @Suppress("unused")
    fun exchange(ticket: Long, carry: Int, texts: String, user: ByteArray, password: ByteArray, body: ByteArray): Boolean {
        // The URL, the host, the addresses, the pins and the proxy, by line breaks, as the bridge packs them.
        val (url, host, addresses, pins, proxy) = (texts.split('\n', limit = 5) + List(5) { "" }).take(5)
        return exchanger.exchange(ticket, carry, url, host, addresses, pins, proxy, user, password, body)
    }

    /**
     * Called by the engine when the way direct apps' names go changed kind (W8, part 1): the fallback's notification,
     * if the user turned it on, is shown or taken away on the main thread. Returns at once.
     */
    @Suppress("unused")
    fun dnsChanged() {
        main.post(::showDnsNotice)
    }

    /** The fallback's notification, while names go to the network's resolver and the user asked for it. */
    private fun showDnsNotice() {
        if (!active) return
        val status = org.visadahyu.datapavan.network.dns.DnsStatus.parse(Engine.nativeDnsStatus())
        val on = org.visadahyu.datapavan.network.dns.DnsSettings.of(this).notify && status.fallbackSeconds != null
        Notices.show(this, Notices.Kind.DNS_FALLBACK, on)
    }

    /** Tells the engine what changed of the network beneath: validated, its search domains. */
    private fun tellDnsNetwork(validated: Boolean?, domains: String?) {
        val before = toldValidated ?: (true to "")
        val now = (validatedForTests ?: validated ?: before.first) to (domains ?: before.second)
        if (now == toldValidated) return
        toldValidated = now
        Engine.nativeDnsNetwork(now.first, now.second)
    }

    /**
     * Debug builds: the DNS lab's test root that scripts/verify-dns.sh put in the network part's files; none in release
     * builds.
     */
    private fun labRoots(): List<java.security.cert.X509Certificate> {
        if (!debuggable) return emptyList()
        val file = java.io.File(java.io.File(filesDir, org.visadahyu.datapavan.network.dns.DnsSettings.LAB_DIR), "ca.pem")
        if (!file.isFile) return emptyList()
        return try {
            file.inputStream().use { input ->
                java.security.cert.CertificateFactory.getInstance("X.509").generateCertificates(input)
                    .filterIsInstance<java.security.cert.X509Certificate>()
            }
        } catch (e: java.security.cert.CertificateException) {
            emptyList()
        }
    }

    /** Called by the engine with a batch of finished records for the connection log (ADR 0037). */
    @Suppress("unused")
    fun logRecords(batch: ByteArray) = ConnectionLog.of(this).write(batch)

    /**
     * Called by the engine, from its thread, when it would have the apps' states read: a flow opened, or
     * bytes have waited for their state (ADR 0046, decision 1). The tracker reads when its rules allow,
     * on its own thread; this returns at once.
     */
    @Suppress("unused")
    fun statesWanted() {
        tracker?.wanted()
    }

    /**
     * `adb shell dumpsys activity service org.visadahyu.datapavan.advanced/org.visadahyu.datapavan.network.NetworkVpnService`:
     * the engine's counters, with when they began ([countersSince]), and Private DNS, and in debug builds
     * the flows it kept and Private DNS's provider, for the end-to-end test (scripts/verify-network.sh).
     * Release builds print no destination and no provider.
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
        // The encrypted resolver's way now (W8, part 1); release builds only its kind, never which resolver.
        Engine.nativeDnsStatus().lineSequence().filter { it.isNotBlank() }.forEach { line ->
            val shown = if (debuggable || !line.startsWith("way ")) line else "way " + line.removePrefix("way ").substringBefore(' ')
            writer.println("dns-$shown")
        }
        writer.println("dns-notify ${if (org.visadahyu.datapavan.network.dns.DnsSettings.of(this).notify) "on" else "off"}")
        writer.println("addresses ${addresses.name} ${addresses.tun4} ${addresses.dns4} ${addresses.tun6} ${addresses.dns6}")
        writer.println("mtu $mtu first-hop ${firstHops.first ?: "-"} ${firstHops.second ?: "-"}")
        writer.println("setups kept $setupsKept anew $setupsAnew")
        writer.println("counters ${ProxyFacts.dumpedCounters(Engine.nativeCounters(), debuggable).joinToString(" ")}")
        writer.println("counters-since $countersSince")
        writer.println("organisations ${Engine.nativeOrganisations().ifEmpty { "none" }}")
        val log = ConnectionLog.of(this)
        val counts = log.counts()
        writer.println(
            "log retention ${log.retentionDays} days ${counts.days} records ${counts.records} key-rows ${counts.keys} " +
                "key ${log.hasKey} lock ${log.lockNow().name.lowercase().replace('_', '-')} failures ${log.failures} " +
                "skipped ${log.skippedRecords}",
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
            // keeps its flows (ADR 0044, unit 12b), which scripts/verify-network.sh checks on a connection
            // kept open.
            if ("setup-again" in args.orEmpty()) {
                main.post { setUpAgain() }
                writer.println("setup-again")
            }
            debugDns(args.orEmpty().toList(), writer)
            debugChain(args.orEmpty().toList(), writer)
            debugTunnels(args.orEmpty().toList(), writer)
            if ("find-tool" in args.orEmpty()) {
                // Android runs dump on the main thread, where sockets are not allowed: the search runs
                // on a thread of its own, and this debug command waits for it.
                var found: org.visadahyu.datapavan.network.chain.ToolSearch? = null
                Thread { found = org.visadahyu.datapavan.network.chain.Tools.search(this, "dump") }.apply {
                    start()
                    join(SEARCH_WAIT_MS)
                }
                writer.println(found?.let(::describe) ?: "tool searching")
            }
            Engine.nativeFlows().lineSequence().filter { it.isNotBlank() }.forEach { writer.println("flow $it") }
            debugBlocking(args.orEmpty().toList(), writer)
            debugProxies(args.orEmpty().toList(), writer)
            debugActivity(args.orEmpty().toList(), writer)
            debugLog(log, args.orEmpty().toList(), writer)
        }
    }

    /**
     * Debug builds only, for part 3a's emulator check (W8; ADR 0053): `blocking-set on|off` turns "Block trackers" on or
     * off and `blocking-browsers on|off` "Also block in browsers", as the screen's switches do, and each waits until the
     * engine has the setting. Then, always: `blocking on|off paused-ms N table ROWS BLOCK KEEP CODE covered N` (the
     * table as the engine read it, zeros for none or one refused, and how many UIDs are covered), one `blocking-browser
     * PACKAGE` for each browser found, one `blocking-allowed PACKAGE UNTIL` for each app allowed (the end of its hour,
     * in milliseconds since 1970), one `blocking-allowed-entry PACKAGE HOST` for each row allowed in an app until blocked
     * again, and one `blocked UID HOST LOOKUPS CONNECTIONS` for each count the engine holds in memory. The hosts are the
     * table's rows, never a destination an app reached; nothing of it goes to logcat.
     */
    private fun debugBlocking(args: List<String>, writer: PrintWriter) {
        val settings = org.visadahyu.datapavan.network.blocking.BlockingSettings.of(this)
        fun after(command: String) = args.indexOf(command).takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }
        var changed = false
        after("blocking-set")?.takeIf { it == "on" || it == "off" }?.let {
            settings.on = it == "on"
            changed = true
        }
        after("blocking-browsers")?.takeIf { it == "on" || it == "off" }?.let {
            settings.browsers = it == "on"
            changed = true
        }
        if (changed) {
            // Android runs dump on the main thread: the handover runs on its own, and this debug command waits for it.
            try {
                blocking.apply(full = true).get(BLOCKING_WAIT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                writer.println("blocking-waiting")
            } catch (e: java.util.concurrent.ExecutionException) {
                writer.println("blocking-failed")
            }
        }
        val facts = org.visadahyu.datapavan.network.blocking.BlockingState.facts.value
            ?: org.visadahyu.datapavan.network.blocking.BlockingFacts.NONE
        val now = System.currentTimeMillis()
        val paused = settings.pausedUntil(now)?.let {
            org.visadahyu.datapavan.network.blocking.Allowances.left(it, now, org.visadahyu.datapavan.network.blocking.BlockingSettings.PAUSE_MS)
        } ?: 0L
        val counts = facts.counts.takeIf { it.size == 4 } ?: IntArray(4)
        writer.println(
            "blocking ${if (settings.on) "on" else "off"} paused-ms $paused table ${counts.joinToString(" ")} covered ${facts.covered.size}",
        )
        facts.browsers.forEach { writer.println("blocking-browser $it") }
        settings.appsAllowed(now).toSortedMap().forEach { (name, until) -> writer.println("blocking-allowed $name $until") }
        settings.entriesAllowed().sortedWith(compareBy({ it.first }, { it.second }))
            .forEach { (name, host) -> writer.println("blocking-allowed-entry $name $host") }
        org.visadahyu.datapavan.network.blocking.Tallies.parse(Engine.nativeBlocked())
            .forEach { writer.println("blocked ${it.uid} ${it.host} ${it.lookups} ${it.connections}") }
    }

    /**
     * Debug builds only, for scripts/verify-proxies.sh (ADR 0052): `messenger-client FAMILY PACKAGE` adds a package of
     * this project's own (`org.visadahyu.datapavan.` and after) to the clients of `telegram`, `whatsapp` or `signal`,
     * and refuses any other, so that a real app is never read as another's; `messenger-clear` takes them away. Then,
     * always, the kept flows that went through a proxy, one `flow-proxy` line each (no credential: none is kept).
     */
    private fun debugProxies(args: List<String>, writer: PrintWriter) {
        val at = args.indexOf("messenger-client")
        if (at >= 0) {
            val family = MESSENGER_FAMILIES.indexOf(args.getOrNull(at + 1))
            val name = args.getOrNull(at + 2).orEmpty()
            if (family >= 0 && name.startsWith("org.visadahyu.datapavan.")) {
                main.post {
                    debugClients[name] = family
                    if (active) applyProxies()
                }
                writer.println("messenger-client ${MESSENGER_FAMILIES[family]} $name")
            } else {
                writer.println("messenger-client refused")
            }
        }
        // "Log where these apps connect", as the screen's switch sets it, for the check that an app's own proxy follows it.
        when (args.indexOf("log-destinations").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }) {
            "on", "off" -> {
                val on = args[args.indexOf("log-destinations") + 1] == "on"
                main.post {
                    org.visadahyu.datapavan.network.chain.ChainSettings.of(this).logDestinations = on
                    if (active) applyRoutes()
                }
                writer.println("log-destinations ${if (on) "on" else "off"}")
            }
        }
        if ("messenger-clear" in args) {
            main.post {
                debugClients.clear()
                if (active) applyProxies()
            }
            writer.println("messenger-clear")
        }
        Engine.nativeFlowProxies().lineSequence().filter { it.isNotBlank() }.forEach { writer.println("flow-proxy $it") }
    }

    /**
     * Debug builds only, for scripts/verify-activity.sh (ADR 0046): `activity-read` has the tracker read the
     * apps' states now and waits until the engine has them. Then, always, what the live view would draw,
     * with no destination: `activity-states` says what the last reading knew (`states`, `no-access`,
     * `locked`, or `none-yet`), how far it told, how many readings the tracker told, and the screen;
     * `activity-late` how many usage events came later than a reading's margin, and the latest by how much; one
     * `activity-app` line for each app, its UID (`-` for flows of no app), its state now (an
     * [org.visadahyu.datapavan.network.log.AppState] name, which says why where there is none), whether it is
     * the user's tool and whether it went through it, how many destinations it reached, and its bytes up and
     * down in each window (`10m`, `1h`, `screen`, and `off`, while the screen was off), for each column: no
     * state, in use, with its notification, in the background, not told yet, then the bytes in no state by
     * why (no usage access, no events, told too late, no app, not told); and `activity-off` the window while
     * the screen was off, when the screen went off and came on again (0 for none, and while still off).
     * `activity-clear` first clears the live view's memory, as ADR 0047's profile will at each screen-off,
     * and says so; `activity-tracker [HOST PORT]` reads the table of trackers from the data pack, says how many
     * trackers, alternatives and refused alternatives it holds, and which trackers it finds for the host given,
     * a test's own (W5's third part).
     */
    private fun debugActivity(args: List<String>, writer: PrintWriter) {
        if ("activity-read" in args) {
            writer.println("activity-read ${tracker?.readNow(ACTIVITY_READ_WAIT_MS) ?: false}")
        }
        if ("activity-clear" in args) {
            Engine.nativeClearActivity()
            writer.println("activity-cleared")
        }
        // The table of trackers from the data pack the audit verifies, as "Now" reads it, and what it finds for
        // one host and port given (W5's third part): no destination of any app is printed.
        val asked = args.indexOf("activity-tracker").takeIf { it >= 0 }
        if (asked != null) {
            val read = NowActivity.loadTables(this)
            writer.println("activity-trackers ${read.joinToString(" ").ifEmpty { "none" }}")
            val host = args.getOrNull(asked + 1)
            val port = args.getOrNull(asked + 2)
            if (host != null && port != null) {
                val matches = NowActivity.matchTrackers(listOf("$host\t$port")).values.flatten()
                writer.println("activity-tracker ${matches.map { it.name }.distinct().joinToString(",").ifEmpty { "-" }}")
            }
        }
        val snapshot = org.visadahyu.datapavan.network.activity.Snapshot.parse(Engine.nativeActivity()) ?: return
        val known = when (snapshot.known) {
            org.visadahyu.datapavan.network.activity.Snapshot.STATES -> "states"
            org.visadahyu.datapavan.network.activity.Snapshot.NO_ACCESS -> "no-access"
            org.visadahyu.datapavan.network.activity.Snapshot.LOCKED -> "locked"
            else -> "none-yet"
        }
        val screen = when (snapshot.screen) {
            org.visadahyu.datapavan.network.activity.Snapshot.SCREEN_ON -> "on"
            org.visadahyu.datapavan.network.activity.Snapshot.SCREEN_OFF -> "off"
            else -> "unknown"
        }
        writer.println(
            "activity-states $known told-until ${snapshot.toldUntil} readings ${tracker?.readings ?: 0} " +
                "screen $screen since ${snapshot.screenOnSince}",
        )
        // The usage events that came into Android's record later than a reading's margin, and the latest by
        // how much, for the lab's measure of how late they come (review b3 of W5's second part, fresh, m1).
        val (late, latest) = tracker?.late ?: (0 to 0L)
        writer.println("activity-late $late latest-ms $latest")
        writer.println("activity-off ${snapshot.offFrom} ${snapshot.offUntil}")
        val windows = listOf("10m", "1h", "screen", "off")
        for (app in snapshot.apps) {
            val bytes = windows.indices.joinToString(" ") { window ->
                windows[window] + "=" + (0 until org.visadahyu.datapavan.network.activity.Snapshot.COLUMNS)
                    .joinToString(",") { "${app.up(window, it)}/${app.down(window, it)}" }
            }
            writer.println(
                "activity-app ${app.uid ?: "-"} now=${org.visadahyu.datapavan.network.log.AppState.name(app.now)} " +
                    "tool=${if (app.isTool) 1 else 0} through-tool=${if (app.throughTool) 1 else 0} " +
                    "places=${app.destinations.size} $bytes",
            )
            // An app's own proxies as "Now" holds them (ADR 0052): its kind, what was asked and the proxy's name where kept,
            // and the place's bytes up and down in the last 10 minutes, by which scripts/verify-proxies.sh tells a flow
            // opened after the switch went off from an earlier one that reached the same first hop.
            for (place in app.destinations) {
                val proxy = place.proxy ?: continue
                val tenMinutes = org.visadahyu.datapavan.network.activity.Snapshot.TEN_MINUTES * 2
                writer.println(
                    "activity-proxy ${app.uid ?: "-"} ${proxyWords(proxy, place.shownOnly)} " +
                        "${place.address.hostAddress}:${place.port} " +
                        "named-by=${place.namedBy} ${place.name.ifEmpty { "-" }} " +
                        "10m=${place.bytes[tenMinutes]}/${place.bytes[tenMinutes + 1]}",
                )
            }
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

    /** Debug builds only: the apps routed through a tunnel by [debugTunnels], with their tunnels' numbers. */
    private val debugRoutes = mutableMapOf<Int, Int>()

    /**
     * Debug builds only, for W7's emulator check (scripts/verify-wireguard.sh): `tunnel-add ID FILE [local]`
     * sets the WireGuard configuration in the file FILE of the network part's private storage (its files directory,
     * which `run-as` writes) as the tunnel ID, "Local network directly" on with `local`, and prints `tunnel-set
     * ID` and a `tunnel-apps ID only|except PACKAGE` line for each app the configuration names, or `tunnel-refused
     * ID WHY`; `tunnel-remove ID` removes its configuration, its routes kept, so that its apps wait;
     * `tunnel-route UID ID` sends the app UID through the tunnel ID, or its other way with ID 0, and prints
     * `tunnel-routed UID ID`. Then, always, one `tunnel` line for each tunnel's state, with no key, address or
     * endpoint, and a `flow-route UID ROUTE COUNT` line for each app and way its kept flows went. The file's
     * bytes are zeroed once handed over; part 2 brings the import and the Keystore.
     */
    /**
     * Debug builds only, for scripts/verify-dns.sh (W8, part 1): `dns-strict on|off`, `dns-only on|off`, `dns-choice
     * odoh`, `dns-choice preset ID`, `dns-choice doh|dot AT ADDRS`, `dns-pairs SPEC|default`, `dns-notify on|off` and
     * `dns-refresh LOW HIGH|off` (seconds a target's key fetch waits after a 401) set the user's setting; `dns-apply`
     * hands the engine the tables again (the lab's, where the check put them in the network part's files) and prints
     * what it read; every one of them applies the setting. `dns-search DOMAINS` (by commas) hands the engine those
     * search domains as Android's would be, through the public suffix list, and prints `dns-search-set` and what it
     * kept. `dns-network-resolver ADDRESS:PORT|android` asks the network's resolver there in plain DNS, for the lab, in
     * place of Android's resolver of the network ([org.visadahyu.datapavan.network.dns.Exchanger.networkResolverForTests]).
     * `dns-times-clear` forgets the durations the engine kept, so that the dump's `dns-latency` lines read only the
     * exchanges after it (the speed budget's check, ADR 0039), and prints `dns-times-cleared`. For the DoT crash's
     * check: `dns-network-changed` raises the network beneath's generation, then tells the exchanger the network
     * changed ([org.visadahyu.datapavan.network.dns.Exchanger.networkChanged]), on the dump's own thread, which is the
     * main one, as onAvailable does on a new network (the network itself stays), and prints `dns-network-changed done`;
     * an open in flight then is not kept, and the next exchange opens a connection of the new generation.
     * `dot-connections` prints `dot-connections OPEN OPENING`, the DoT connections that take queries and the DoT opens
     * in flight;
     * `network-generation` prints `network-generation N`, the network beneath's generation.
     */
    private fun debugDns(args: List<String>, writer: PrintWriter) {
        fun after(command: String, n: Int) = args.indexOf(command).takeIf { it >= 0 }?.let { args.drop(it + 1).take(n) }
        val settings = org.visadahyu.datapavan.network.dns.DnsSettings.of(this)
        if ("dns-times-clear" in args) {
            Engine.nativeDnsTimesClear()
            writer.println("dns-times-cleared")
        }
        if ("dns-network-changed" in args) {
            // On this thread, the main one, on purpose: closing a DoT connection here is what crashed the network part.
            // As onAvailable does, but for the network itself: a debug build has no other one to set.
            networkGeneration++
            recomputeResolverProxy()
            exchanger.networkChanged()
            writer.println("dns-network-changed done")
        }
        if ("dot-connections" in args) {
            val (open, opening) = exchanger.dotConnections()
            writer.println("dot-connections $open $opening")
        }
        if ("network-generation" in args) writer.println("network-generation $networkGeneration")
        if ("dns-proxy" in args) {
            val route = resolverProxy
            writer.println("dns-proxy ${route?.generation ?: networkGeneration} ${route?.toString() ?: "none"} ${resolverProxyWhy.word}")
        }
        var changed = "dns-apply" in args
        after("dns-strict", 1)?.let {
            settings.strict = it.firstOrNull() == "on"
            changed = true
        }
        after("dns-notify", 1)?.let {
            settings.notify = it.firstOrNull() == "on"
            changed = true
        }
        after("dns-only", 1)?.let {
            settings.only = it.firstOrNull() == "on"
            changed = true
        }
        after("dns-refresh", 2)?.let {
            val (low, high) = (it + listOf("", "")).take(2).map { n -> n.toIntOrNull() }
            settings.refreshForTests = if (low != null && high != null) "$low $high" else ""
            changed = true
        }
        after("dns-network-resolver", 1)?.let {
            exchanger.networkResolverForTests = it.firstOrNull()?.let(org.visadahyu.datapavan.network.dns.Exchanger::parseAddress)
            writer.println("dns-network-resolver-set ${exchanger.networkResolverForTests ?: "android"}")
        }
        after("dns-search", 1)?.let {
            val kept = org.visadahyu.datapavan.network.dns.SearchDomains.accepted(it.firstOrNull().orEmpty(), suffixes)
            main.post { tellDnsNetwork(null, kept) }
            writer.println("dns-search-set $kept")
        }
        after("dns-pairs", 1)?.let {
            settings.pairs = it.firstOrNull()?.takeIf { p -> p != "default" }.orEmpty()
            changed = true
        }
        after("dns-validated", 1)?.let {
            validatedForTests = when (it.firstOrNull()) {
                "on" -> true
                "off" -> false
                else -> null
            }
            main.post { tellDnsNetwork(validatedForTests ?: true, null) }
            writer.println("dns-validated-set ${validatedForTests ?: "android"}")
        }
        after("dns-choice", 3)?.let {
            settings.choice = org.visadahyu.datapavan.network.dns.DnsSettings.Choice.read(it.joinToString(" "))
            changed = true
        }
        if (changed) {
            val read = org.visadahyu.datapavan.network.dns.DnsSettings.apply(this)
            writer.println("dns-applied ${read.joinToString(" ")}")
            main.post(::showDnsNotice)
        }
    }

    private fun debugTunnels(args: List<String>, writer: PrintWriter) {
        fun after(command: String, n: Int) = args.indexOf(command).takeIf { it >= 0 }?.let { args.drop(it + 1).take(n) }
        after("tunnel-add", 3)?.let { given ->
            val id = given.getOrNull(0)?.toIntOrNull() ?: return@let
            val name = given.getOrNull(1)?.takeIf { it.matches(Regex("[A-Za-z0-9._-]+")) } ?: return@let
            val text = java.io.File(filesDir, name).takeIf { it.isFile }?.readBytes()
            if (text == null) {
                writer.println("tunnel-refused $id no-file")
                return@let
            }
            try {
                val why = Engine.nativeTunnelSet(id, text, localNetwork = given.getOrNull(2) == "local")
                writer.println(if (why.isEmpty()) "tunnel-set $id" else "tunnel-refused $id $why")
                if (why.isEmpty()) {
                    // The apps' lines alone: the rest of the description names the endpoint and the addresses,
                    // which the dump never prints.
                    Engine.nativeTunnelParse(text).lineSequence().drop(1)
                        .filter { it.startsWith("only ") || it.startsWith("except ") }
                        .forEach { writer.println("tunnel-apps $id $it") }
                }
            } finally {
                text.fill(0)
            }
        }
        after("tunnel-remove", 1)?.firstOrNull()?.toIntOrNull()?.let { id ->
            // The routes stay, in the engine and here: the apps wait for the tunnel.
            Engine.nativeTunnelRemove(id)
            writer.println("tunnel-removed $id")
        }
        after("tunnel-route", 2)?.takeIf { it.size == 2 }?.let { (uid, id) ->
            val (app, tunnel) = (uid.toIntOrNull() ?: return@let) to (id.toIntOrNull() ?: return@let)
            if (tunnel == 0) debugRoutes.remove(app) else debugRoutes[app] = tunnel
            val routes = debugRoutes.entries.toList()
            Engine.nativeTunnelRoutes(
                routes.map { it.key }.toIntArray(),
                routes.map { it.value }.toIntArray(),
                logDestinations = false,
            )
            writer.println("tunnel-routed $app $tunnel")
        }
        Engine.nativeTunnelStates().lineSequence().filter { it.isNotBlank() }.forEach { writer.println("tunnel $it") }
        Engine.nativeFlowRoutes().lineSequence().filter { it.isNotBlank() }.forEach { writer.println("flow-route $it") }
        debugStore(args, writer)
    }

    /**
     * Debug builds only, for W7's second emulator check (scripts/verify-wireguard-import.sh): `tunnel-store` prints a
     * `tunnel-slot N default|other local|- name STATE set|unset routes K` line for each configuration the store keeps
     * (STATE `known`, `locked`, `unavailable`, `lost` or `removed`; `set` when this run set it in the engine), a
     * `tunnel-waiting N routes K` line for each removed slot apps still wait for, a `tunnel-engine-route UID N` line
     * for each route last handed to the engine, a `tunnel-key-of N a|b` line for each configuration's key, `tunnel-profile
     * on|off notice shown|none`, and `tunnel-key HOME`; `tunnel-profile on|off` turns ADR 0047's profile on or off and
     * wraps every configuration again under its key, printing `tunnel-profile on|off moved K unmoved L`; no name, key,
     * address or
     * endpoint. `tunnel-key-time` opens each configuration as a start does and prints `tunnel-opened N MS` (zeroed at
     * once). `tunnel-key-probe make|open|clear` measures a key that needs an unlocked phone, as ADR 0035 asks of
     * `setUnlockedDeviceRequired`: `make` makes one (alias `network-tunnels-probe`) and wraps 32 random bytes in the
     * network part's files, `open` unwraps them and prints `tunnel-key-probe open ok|locked|lost MS`, `clear` deletes
     * both. `qr-decode FILE` hands the file FILE of the network part's files directory to the QR decoder's isolated
     * process and prints `qr-decoded BYTES MS` or `qr-failed WHY MS`, never the text.
     */
    private fun debugStore(args: List<String>, writer: PrintWriter) {
        val store = org.visadahyu.datapavan.network.tunnel.TunnelStore.of(this)
        if ("tunnel-store" in args) {
            writer.println("tunnel-lost notice ${if (Notices.shown(this, Notices.Kind.LOST)) "shown" else "none"}")
            for (answer in Engine.nativeAppAnswers().lines().filter { it.isNotBlank() }) writer.println("tunnel-asked $answer")
            writer.println("packages-follow ${if (packages != null) "on" else "off"}")
            val state = try {
                store.state()
            } catch (e: org.visadahyu.datapavan.network.tunnel.TunnelStore.StateLost) {
                writer.println("tunnel-state lost")
                return
            } catch (e: java.security.GeneralSecurityException) {
                writer.println("tunnel-state closed")
                return
            }
            for (slot in state.order) {
                val name = when (store.name(slot)) {
                    is org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Known -> "known"
                    org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Locked -> "locked"
                    org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Unavailable -> "unavailable"
                    org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Lost -> "lost"
                    org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Removed -> "removed"
                }
                writer.println(
                    "tunnel-slot $slot ${if (slot == state.default) "default" else "other"} ${if (slot in state.local) "local" else "-"} " +
                        "name $name ${if (slot in tunnelsSet) "set" else "unset"} routes ${state.routes.count { it.value == slot }}",
                )
            }
            for (slot in state.routes.values.distinct().filter { it !in state.order }) {
                writer.println("tunnel-waiting $slot routes ${state.routes.count { it.value == slot }}")
            }
            // What the engine was last handed, by UID: an app installed again is routed by its new one (M1).
            for ((uid, slot) in routesSet) writer.println("tunnel-engine-route $uid $slot")
            // Which key wraps each configuration, and the profile (the maintainer's decision on key B).
            for (slot in state.order) writer.println("tunnel-key-of $slot ${store.keyOf(slot)?.name?.lowercase() ?: "-"}")
            writer.println("tunnel-profile ${if (state.profile) "on" else "off"} notice ${if (Notices.shown(this, Notices.Kind.UNLOCK)) "shown" else "none"}")
            writer.println("tunnel-unlock waiting ${if (unlockWait != null) "yes" else "no"} seen $unlocksSeen")
            writer.println("tunnel-key ${store.home().name.lowercase()}")
        }
        // The package receiver off and on again, for the check that an app installed again is asked of the network part
        // at its first flow (the maintainer, 2026-11-20); and key A deleted, as a Keystore reset would, for the check
        // of a state lost for good.
        when (args.indexOf("packages-follow").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }) {
            "off" -> {
                packagesOff = true
                packages?.let { unregisterReceiver(it) }
                packages = null
                writer.println("packages-follow off")
            }
            "on" -> {
                packagesOff = false
                if (active) followPackages()
                writer.println("packages-follow ${if (packages != null) "on" else "off"}")
            }
        }
        if (args.indexOf("tunnel-key-delete").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) } == "a") {
            org.visadahyu.datapavan.network.tunnel.KeystoreWrap().destroy()
            writer.println("tunnel-key-deleted a")
        }
        // ADR 0047's profile, which W9's switch turns on and off: every configuration wrapped again under its key.
        val profile = args.indexOf("tunnel-profile").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }
        if (profile == "on" || profile == "off") {
            val moved = store.setProfile(profile == "on")
            writer.println("tunnel-profile $profile moved ${moved.moved.size} unmoved ${moved.unmoved.size}")
            main.post { if (active) applyTunnels() }
        }
        if ("tunnel-key-time" in args) {
            for (slot in store.state().order) {
                val started = SystemClock.elapsedRealtimeNanos()
                val opened = store.text(slot)
                (opened as? org.visadahyu.datapavan.network.tunnel.Opened.Plain)?.bytes?.fill(0)
                writer.println("tunnel-opened $slot ${(SystemClock.elapsedRealtimeNanos() - started) / 1_000_000}")
            }
        }
        val probe = args.indexOf("tunnel-key-probe").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }
        if (probe != null) {
            // The store sets how the network part tells a locked phone; the probe's key is read the same way.
            org.visadahyu.datapavan.network.tunnel.TunnelStore.of(this)
            val wrap = org.visadahyu.datapavan.network.tunnel.KeystoreWrap(PROBE_ALIAS, unlockedOnly = true)
            val file = java.io.File(filesDir, "tunnel-key-probe")
            val started = SystemClock.elapsedRealtimeNanos()
            val said = when (probe) {
                "make" -> {
                    wrap.destroy()
                    val plain = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                    file.writeBytes(wrap.wrap(1, org.visadahyu.datapavan.network.tunnel.Wrap.Part.TEXT, plain))
                    plain.fill(0)
                    "made ${wrap.home().name.lowercase()}"
                }
                "open" -> when (val opened = wrap.unwrap(1, org.visadahyu.datapavan.network.tunnel.Wrap.Part.TEXT, file.takeIf { it.isFile }?.readBytes() ?: ByteArray(0))) {
                    is org.visadahyu.datapavan.network.tunnel.Opened.Plain -> "open ok".also { opened.bytes.fill(0) }
                    org.visadahyu.datapavan.network.tunnel.Opened.Locked -> "open locked"
                    org.visadahyu.datapavan.network.tunnel.Opened.Unavailable -> "open unavailable"
                    org.visadahyu.datapavan.network.tunnel.Opened.Lost -> "open lost"
                }
                else -> {
                    wrap.destroy()
                    file.delete()
                    "cleared"
                }
            }
            writer.println("tunnel-key-probe $said ${(SystemClock.elapsedRealtimeNanos() - started) / 1_000_000} ${wrap.lastError ?: "-"}")
        }
        val picture = args.indexOf("qr-decode").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }
            ?.takeIf { it.matches(Regex("[A-Za-z0-9._-]+")) }
        if (picture != null) {
            val file = java.io.File(filesDir, picture)
            val started = SystemClock.elapsedRealtimeNanos()
            var result: org.visadahyu.datapavan.network.tunnel.qr.QrDecode.Result? = null
            // The binding's callbacks come on a thread of their own; this one waits for the answer.
            Thread {
                result = try {
                    org.visadahyu.datapavan.network.tunnel.qr.QrClient.decode(
                        this,
                        ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY),
                    )
                } catch (e: java.io.FileNotFoundException) {
                    org.visadahyu.datapavan.network.tunnel.qr.QrDecode.Result.Failed(org.visadahyu.datapavan.network.tunnel.qr.QrDecode.Failure.NOT_A_PICTURE)
                }
            }.apply {
                start()
                join(QR_WAIT_MS)
            }
            val ms = (SystemClock.elapsedRealtimeNanos() - started) / 1_000_000
            when (val read = result) {
                is org.visadahyu.datapavan.network.tunnel.qr.QrDecode.Result.Text -> {
                    writer.println("qr-decoded ${read.bytes.size} $ms")
                    read.bytes.fill(0)
                }
                is org.visadahyu.datapavan.network.tunnel.qr.QrDecode.Result.Failed -> writer.println("qr-failed ${read.why.name.lowercase()} $ms")
                null -> writer.println("qr-failed waiting $ms")
            }
        }
    }

    /**
     * Debug builds only, for scripts/verify-log.sh: `log-flush` hands the log every waiting record and
     * each open flow's segment so far, and waits until they are written, `log-today`
     * prints today's records, `log-day N` says whether day N (days since 1970) opens now, `log-test-day N`
     * writes a test record dated day N, `log-put-day N` writes one even past retention (as if put back by
     * hand), `log-retention N` sets retention, `log-raw` (in [dump]) prints the rows by day as the file
     * holds them, `log-wipe` wipes the log, and `log-model SEED STEPS` starts the log's model test
     * ([org.visadahyu.datapavan.network.log.LogModel]), whose result `log-model-result` prints.
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
                writer.println(org.visadahyu.datapavan.network.log.LogModel.start(this, seed, steps))
            }
            "log-model-result" in args -> writer.println(org.visadahyu.datapavan.network.log.LogModel.result())
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
                val record = java.nio.ByteBuffer.allocate(1 + 1 + 4 + 8 + 8 + 4 + 8 + 8 + 1).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .put(LogRecord.VERSION).put(2).putInt(-1).putLong(noon).putLong(noon).putInt(1).putLong(0).putLong(0)
                    .put(org.visadahyu.datapavan.network.log.AppState.NO_APP.toByte()).array()
                val batch = java.nio.ByteBuffer.allocate(4 + 2 + record.size).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                    .putInt(1).putShort(record.size.toShort()).put(record).array()
                log.write(batch, pastRetention = "log-put-day" in args)
                log.settle()
                writer.println("${if ("log-put-day" in args) "log-put-day" else "log-test-day"} $testDay written")
            }
        }
    }

    /** Debug builds' `find-tool`: what the network part found of the user's tool, one line, for W6's checks. */
    private fun describe(search: org.visadahyu.datapavan.network.chain.ToolSearch): String = when (search) {
        org.visadahyu.datapavan.network.chain.ToolSearch.NoneInstalled -> "tool none"
        is org.visadahyu.datapavan.network.chain.ToolSearch.NotAnswering ->
            "tool installed ${search.installed.joinToString(",") { it.packageName }} not-answering"
        is org.visadahyu.datapavan.network.chain.ToolSearch.Answering -> with(search.found) {
            val owner = when (ownerConfirmed) {
                true -> "yes"
                false -> "no"
                null -> "unknown"
            }
            "tool answering ${tool.packageName} $host:$port uid $uid password ${if (needsPassword) "yes" else "no"} owner $owner"
        }
    }

    /**
     * A record as `log-today` prints it: the DNS answer's name, where it differs from the connection's own,
     * whether the flow came in, and the app's state (ADR 0046) last, so that the fields before keep their
     * places, and the record's start and end, in milliseconds since 1970, after them.
     */
    /**
     * A proxy as the debug builds' dump writes it: `kind:how:flags:asked:proxy-name`, `-` for none; no credential is
     * kept. The flag `v`, a first hop "Now" shows only, is given by the caller: a record of the log never has it.
     */
    private fun proxyWords(proxy: LogRecord.Proxy, shownOnly: Boolean = false): String {
        val kind = listOf("-", "socks5", "socks4", "connect", "forward", "mtproto", "whatsapp", "signal").getOrElse(proxy.kind) { "?" }
        val flags = listOfNotNull(
            "s".takeIf { proxy.setting }, "p".takeIf { proxy.password }, "o".takeIf { proxy.outsideMaker }, "l".takeIf { proxy.leftOut },
            "v".takeIf { shownOnly },
        ).joinToString("").ifEmpty { "-" }
        val asked = if (proxy.askedPort >= 0) "${proxy.asked}@${proxy.askedPort}" else "-"
        return "$kind:${if (proxy.declared) "read" else "inferred"}:$flags:$asked:${proxy.proxyName.ifEmpty { "-" }}"
    }

    private fun describe(record: LogRecord): String = when (record) {
        is LogRecord.Segment -> listOfNotNull(
            if (record.protocol == 6) "tcp" else "udp", record.uid ?: "-", "${record.address.hostAddress}:${record.port}",
            "up=${record.up}", "down=${record.down}", if (record.continues) "continues" else "ended",
            "wire=${record.wireUp}/${record.wireDown}", record.name.ifEmpty { "-" }, "flow=${record.flow}",
            record.dnsName.takeIf { it.isNotEmpty() }?.let { "dns-name=$it" }, "came-in".takeIf { record.cameIn },
            "state=${org.visadahyu.datapavan.network.log.AppState.name(record.state)}", "at=${record.start}-${record.end}",
            record.proxy?.let { "proxy=${proxyWords(it)}" },
            // Version 6 (W8, part 3a): a flow tracker blocking refused, by its row's SDK, never a host.
            "blocked=${record.blockedSdk.ifEmpty { "-" }}".takeIf { record.blocked },
        ).joinToString(" ")
        is LogRecord.Lookups ->
            "lookups ${record.uid ?: "-"} ${record.count} wire=${record.wireUp}/${record.wireDown} " +
                "state=${org.visadahyu.datapavan.network.log.AppState.name(record.state)}"
    }

    companion object {
        /** The messengers' families, by the code the engine takes (`nativeProxies`), and as its table names them. */
        private val MESSENGER_FAMILIES = listOf("telegram", "whatsapp", "signal")

        const val ACTION_START = "org.visadahyu.datapavan.network.START"
        const val ACTION_STOP = "org.visadahyu.datapavan.network.STOP"

        /** The chain's settings changed: hand them to the engine (W6). */
        const val ACTION_APPLY_CHAIN = "org.visadahyu.datapavan.network.APPLY_CHAIN"

        /** From the network screen: the WireGuard configurations or their apps changed (W7, part 2). */
        const val ACTION_APPLY_TUNNELS = "org.visadahyu.datapavan.network.APPLY_TUNNELS"

        /** From the network screen: the apps left out changed, so the tunnel is set up again if it is up. */
        const val ACTION_APPLY_LEFT_OUT = "org.visadahyu.datapavan.network.APPLY_LEFT_OUT"

        /**
         * From the network screens: tracker blocking changed (W8, part 3a), handed to the engine again; [EXTRA_FULL]
         * false for a tap of the undo or the pause, which reads nothing of the phone again, true (the default) for a
         * setting that changes what is covered.
         */
        const val ACTION_APPLY_BLOCKING = "org.visadahyu.datapavan.network.APPLY_BLOCKING"
        const val EXTRA_FULL = "full"

        /** How long the debug commands `blocking-set` and `blocking-browsers` wait for the handover. */
        private const val BLOCKING_WAIT_MS = 10_000L

        /** How long blocking waits after a change of the scan or the pack before it hands over again: writes come in bursts. */
        private const val FILES_SETTLE_MS = 2_000L

        /** The folder of the imported data pack in the app's no-backup files (DataPackStore). */
        private const val PACK_DIRECTORY = "datapack"

        /** How long the debug command `activity-read` waits for the reading. */
        private const val ACTIVITY_READ_WAIT_MS = 10_000L

        /** How long the debug command `find-tool` waits for the search. */
        private const val SEARCH_WAIT_MS = 10_000L

        /** How long the debug command `qr-decode` waits for the decoder. */
        private const val QR_WAIT_MS = 20_000L

        /** The debug builds' key that needs an unlocked phone, for the measure of `setUnlockedDeviceRequired`. */
        private const val PROBE_ALIAS = "network-tunnels-probe"

        /** When a configuration still closed after an unlock is tried again. */
        private val UNLOCK_RETRIES_MS = listOf(1_000L, 2_000L, 4_000L, 8_000L)

        /** The tunnel no configuration has, that every app is held to while the store's state cannot be opened. */
        private const val HOLD_TUNNEL = Int.MAX_VALUE

        /** The UID given for a tool that is not installed: no app has it. */
        private const val NO_UID = Int.MAX_VALUE

        /** Debug builds: a comma-separated list of the only apps to send through the tunnel. */
        const val EXTRA_ONLY_APPS = "only_apps"
        private const val TAG = "Network"
        private const val KEPT_FLOWS = 512

        /** The asset of the table from address to organisation, stored uncompressed (build.gradle.kts). */
        private const val ORGANISATIONS = "asn.bin"


        private val state = MutableStateFlow(false)

        /** Whether the tunnel is up, for the network part's own screens. */
        val running: StateFlow<Boolean> = state.asStateFlow()

        private val dnsState = MutableStateFlow<PrivateDns?>(null)

        /**
         * Private DNS on the network part's network while the tunnel is up, else null, for the network part's own
         * screens.
         */
        val privateDns: StateFlow<PrivateDns?> = dnsState.asStateFlow()

        /** The exchanger of the service that runs, for the screen's check of a resolver ([Exchanger.probe]); else null. */
        @Volatile
        internal var exchangerNow: org.visadahyu.datapavan.network.dns.Exchanger? = null
            private set
    }
}
