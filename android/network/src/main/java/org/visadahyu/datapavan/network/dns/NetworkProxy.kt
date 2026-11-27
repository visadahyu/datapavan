package org.visadahyu.datapavan.network.dns

import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * The proxy the network part's resolver takes on purpose (ADR 0042, "Android's proxy"): the network beneath's own
 * direct proxy where it has one; else Android's global proxy, the whole phone's, where it is a direct one (the
 * maintainer's decision of 2026-11-25); never the process's, which Android gives a process at its start and so depends
 * on whether the network part started before its own VPN (measurements 7.1, point 3). Either is only the second way,
 * after directly ([ResolverProxy]), and the global one only on a network closed to the resolver ([DirectReach]).
 *
 * A PAC gives none, and so do a proxy on the loopback, on one of the phone's own addresses or on a link-local one: such
 * a proxy is a tool's or a filter's local port, through which the resolver would loop through the tunnel or reach the
 * tool by another door than the engine's choice. A server the proxy's exclusion list names goes directly, as Android's
 * own selector sends it. The rule is pure, over plain values, so that the JVM tests hold it; [of] reads Android's
 * `ProxyInfo` into it.
 */
object NetworkProxy {
    /**
     * A proxy as Android's settings give it, the network's or the global one: [host] and [port], whether a PAC file is
     * set, its exclusions.
     */
    data class Setting(val host: String, val port: Int, val pac: Boolean, val exclusions: List<String>)

    /** Why the resolver uses the proxy it does, for the debug dump's `dns-proxy` line. */
    enum class Why(val word: String) {
        /** The network beneath's own proxy. */
        NETWORK("network"),

        /** Android's global proxy, where the network beneath has no direct one of its own. */
        GLOBAL("global"),
        NONE("none"),
        PAC("pac"),
        LOOPBACK("loopback"),
        LINK_LOCAL("link-local"),
        OWN("own"),
        UNRESOLVED("unresolved"),

        /**
         * A proxy on the local network while Datapavan lacks Android 17's local-network grant, which would refuse its
         * connection (the proxy record's unit S2; [withoutGrant]).
         */
        LOCAL_NO_GRANT("local-no-grant"),
    }

    /** At most this many of a proxy name's addresses are kept; a way through the proxy takes one, the next after one that could not be reached. */
    const val MAX_ADDRESSES = 2

    /**
     * The resolver's proxy, or the reason there is none, from the network beneath's own [network] setting and Android's
     * [global] one: the network's own direct proxy where it has one ([Why.NETWORK]), even one whose addresses [usable]
     * then leaves out, since the network's own stays the only one where the network has one; else the global one where
     * it is a direct one ([Why.GLOBAL]); else none, [Why.PAC] for a PAC file, the network's or the global one, whatever
     * its host and port (Android reports a PAC as `localhost` and its handler's port, which must never read as a direct
     * proxy), [Why.NONE] for nothing set. The global one is a third party's (a device owner's, or one set by `adb` or by
     * an app granted `WRITE_SECURE_SETTINGS`), so it is a way only once the network is closed to the resolver
     * ([DirectReach]): its operator then learns of the resolver only where the network lets nothing through directly,
     * such as the managed phone whose device owner forces that proxy and sees the phone's traffic already.
     */
    fun choose(network: Setting?, global: Setting? = null): Pair<Setting?, Why> {
        direct(network)?.let { return it to Why.NETWORK }
        direct(global)?.let { return it to Why.GLOBAL }
        return null to if (network?.pac == true || global?.pac == true) Why.PAC else Why.NONE
    }

    /** [setting] where it is a direct proxy: no PAC file, told before its host and port, a host and a port. */
    private fun direct(setting: Setting?): Setting? =
        setting?.takeIf { !it.pac && it.host.isNotBlank() && it.port in 1..65535 }

    /**
     * The addresses of a chosen proxy that the resolver may use, with [chosen], the choice's reason ([Why.NETWORK] or
     * [Why.GLOBAL]), or the reason there are none: [own] says whether an address is one of the phone's own (the
     * tunnel's, the network's link addresses). Loopback, link-local and the phone's own addresses are left out, the
     * global proxy's as the network's; at most [MAX_ADDRESSES] are kept, in the order given.
     */
    fun usable(addresses: List<InetAddress>, chosen: Why = Why.NETWORK, own: (InetAddress) -> Boolean): Pair<List<InetAddress>, Why> {
        if (addresses.isEmpty()) return emptyList<InetAddress>() to Why.UNRESOLVED
        val kept = addresses.filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isAnyLocalAddress && !own(it) }
        if (kept.isNotEmpty()) return kept.take(MAX_ADDRESSES) to chosen
        val why = when {
            addresses.any { it.isLoopbackAddress || it.isAnyLocalAddress } -> Why.LOOPBACK
            addresses.any { it.isLinkLocalAddress } -> Why.LINK_LOCAL
            else -> Why.OWN
        }
        return emptyList<InetAddress>() to why
    }

    /**
     * Whether [server], a host name or an address, is in [exclusions], by the rules Android gives a proxy's exclusion
     * list (it becomes the process's `http.nonProxyHosts`): ASCII letters in either case; `*` matches any run of
     * characters, so `*.example.com` takes the subdomains of `example.com` and `10.*` the addresses that start so; a
     * leading `.` takes the subdomains too; any other entry takes that host itself. The engine's `connect::excluded` is
     * its twin, and both read core/net/testdata/proxy-exclusions.tsv (the proxy record's unit S2): only ASCII letters
     * fold, since a host asked about is a DNS name or an address, so that the Kelvin sign is no `k` on either side; and
     * only the code points up to U+0020 are trimmed ([trimmed]).
     */
    fun excluded(server: String, exclusions: List<String>): Boolean {
        val host = folded(trimmed(server).trimEnd('.').removePrefix("[").removeSuffix("]"))
        if (host.isEmpty()) return false
        return exclusions.any { raw ->
            val entry = folded(trimmed(raw).trimEnd('.'))
            when {
                entry.isEmpty() -> false
                '*' in entry -> glob(entry).matches(host)
                entry.startsWith(".") -> host.endsWith(entry)
                else -> host == entry
            }
        }
    }

    /**
     * [text] without the code points up to U+0020 at either end, the controls and the space, as Java's `String.trim`
     * and the engine's `connect::trimmed`: Kotlin's own `trim` takes Java's white space, U+001C to U+001F and U+2028
     * among it, and Rust's `str::trim` Unicode's, U+0085 among it, so that each alone would read a rare list otherwise
     * than the other.
     */
    internal fun trimmed(text: String): String = text.trim { it <= ' ' }

    /** [text] with its ASCII letters in lower case, and nothing else changed. */
    internal fun folded(text: String): String = buildString(text.length) {
        for (c in text) append(if (c in 'A'..'Z') c + ('a' - 'A') else c)
    }

    private fun glob(entry: String): Regex =
        Regex(entry.split('*').joinToString(".*") { Regex.escape(it) }, RegexOption.DOT_MATCHES_ALL)

    /**
     * Whether Android 17 would refuse the network part's own connection to a proxy at [address] for want of the
     * local-network grant (the proxy record's unit S2, section 6; ADR 0034, decision 5): never with [granted]; else an
     * address within the network's own prefixes ([onLink]), multicast or broadcast; and on Wi-Fi, Ethernet or a network
     * of unknown transport ([transport] 1, 2 or 0, as `Engine.nativeProxies` codes them) also 10/8, 172.16/12,
     * 192.168/16, 100.64/10 and the link-local ranges. On cellular and other networks only their own subnets are local.
     */
    fun withoutGrant(address: InetAddress, transport: Int, onLink: Boolean, granted: Boolean): Boolean {
        if (granted) return false
        val bytes = address.address
        if (onLink || address.isMulticastAddress || bytes.all { it == 0xff.toByte() }) return true
        if (transport !in 0..2) return false
        if (address.isLinkLocalAddress) return true
        if (bytes.size != 4) return false
        val (first, second) = bytes[0].toInt() and 0xff to (bytes[1].toInt() and 0xff)
        return first == 10 || (first == 172 && second in 16..31) || (first == 192 && second == 168) ||
            (first == 100 && second in 64..127)
    }

    /**
     * [addresses] less those Android 17 would refuse the network part ([refused], by [withoutGrant]), with [why]; none
     * left gives [Why.LOCAL_NO_GRANT]. For the resolver's `ProxySocket` and the engine's connections alike, sockets of
     * the same UID (the proxy record's unit S2, section 6).
     */
    fun granted(addresses: List<InetAddress>, why: Why, refused: (InetAddress) -> Boolean): Pair<List<InetAddress>, Why> {
        if (addresses.isEmpty()) return addresses to why
        val kept = addresses.filterNot(refused)
        return kept to if (kept.isEmpty()) Why.LOCAL_NO_GRANT else why
    }

    /**
     * The engine's proxy (the proxy record's unit S2) from the resolver's settle, which [chosen] ([choose]'s reason) and
     * [settled] (the reason after [usable] and [granted]) describe: its [addresses] only for the network's own proxy,
     * never Android's global one ([Why.GLOBAL], audit M3), which would carry apps that ignore it further than Android
     * does; else none, with the reason the dump's `beneath-proxy` line gives.
     */
    fun forEngine(addresses: List<InetSocketAddress>, chosen: Why, settled: Why): Pair<List<InetSocketAddress>, Why> = when {
        chosen == Why.GLOBAL -> emptyList<InetSocketAddress>() to Why.GLOBAL
        chosen != Why.NETWORK || addresses.isEmpty() -> emptyList<InetSocketAddress>() to settled
        else -> addresses to Why.NETWORK
    }

    /**
     * Whether the network beneath has IPv6 for the engine (the proxy record's unit S2, audit C2): a global unicast address
     * (2000::/3) among its [addresses] and an IPv6 default route ([defaultRoute]). Without, an IPv6 destination never
     * goes to its proxy.
     */
    fun ipv6(addresses: List<InetAddress>, defaultRoute: Boolean): Boolean =
        defaultRoute && addresses.any { it is Inet6Address && (it.address[0].toInt() and 0xe0) == 0x20 }

    /** [addresses] as `Engine.nativeBeneathProxy` takes them: one `address port` a line, never a zone. */
    fun engineAddresses(addresses: List<InetSocketAddress>): String =
        addresses.joinToString("\n") { "${it.address.hostAddress.orEmpty().substringBefore('%')} ${it.port}" }

    /** A host as Android's setting writes it, with an IPv6 literal's brackets taken off. */
    fun bare(host: String): String = host.trim().removePrefix("[").removeSuffix("]")

    /** Whether [address] is an IPv6 address with a zone, which the resolver does not carry. */
    fun zoned(address: InetAddress): Boolean = address is Inet6Address && address.scopeId != 0

    /**
     * Every address of the phone's own interfaces as the kernel lists them: the networks' (Wi-Fi, mobile data), a
     * hotspot's, USB tethering's, Wi-Fi Direct's and the tunnel's, which no network's link properties name all of
     * (the global proxy's review, m2). Empty when the list cannot be read.
     */
    fun phoneAddresses(): Set<InetAddress> = try {
        java.net.NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().flatMap { it.inetAddresses.toList() }.toSet()
    } catch (e: java.net.SocketException) {
        emptySet()
    }

    /**
     * [Setting] from Android's `ProxyInfo` of the network beneath or the global one, or null for none: a PAC file is told
     * by its URL, which is not `Uri.EMPTY`, before its host and port are read.
     */
    fun of(info: android.net.ProxyInfo?): Setting? {
        info ?: return null
        val pac = info.pacFileUrl != null && info.pacFileUrl != android.net.Uri.EMPTY
        return Setting(info.host.orEmpty(), info.port, pac, info.exclusionList?.toList().orEmpty())
    }
}

/**
 * The proxy the resolver may take, the network beneath's own or the global one ([NetworkProxy.choose], [global]), for
 * the network of [generation] only: [setting] as read, and [addresses] usable for it. An exchange tries two ways within
 * one deadline ([ways]): the first, then the other when the first gave no HTTP answer at all. Which comes first is
 * learned only from an answer ([answeredBy]): after the other way answered where the first gave none, that other way
 * comes first on this network for [PREFERRED_MS], then the default order again. A failure alone teaches nothing, since
 * the server, not the way, may have failed.
 *
 * The global proxy is a way only while the network is closed to the resolver ([DirectReach.closure]): until then an
 * exchange goes directly alone, and what it learned counts only in the closing it was learned in, so that a direct
 * connection made, which opens the network again, forgets it (the global proxy's review, M1). The network's own proxy
 * is a way whatever the network does with direct connections.
 */
class ResolverProxy(
    val generation: Int,
    val setting: NetworkProxy.Setting,
    val addresses: List<InetSocketAddress>,
    val global: Boolean = false,
) {
    private val next = AtomicInteger(0)

    @Volatile
    private var turnedUntil = NEVER

    /** The closing of the network the turn was learned in, for the global proxy. */
    @Volatile
    private var turnedIn: Int? = null

    /**
     * The ways of an exchange now, the first first: directly (null) and through the proxy's address in turn. For the
     * global proxy, [closure] is the network's closing to the resolver ([DirectReach.closure]): directly alone while it
     * is open (null).
     */
    fun ways(now: Long = System.nanoTime(), closure: Int? = null): List<InetSocketAddress?> {
        if (global && closure == null) return listOf(null)
        val turned = turnedUntil.let { it != NEVER && now - it < 0 } && (!global || turnedIn == closure)
        return if (PROXY_FIRST != turned) listOf(proxy(), null) else listOf(null, proxy())
    }

    /** The proxy's address tried next. */
    fun proxy(): InetSocketAddress = addresses[Math.floorMod(next.get(), addresses.size)]

    /** Whether the proxy comes first now, for the debug dump. */
    fun proxyFirst(now: Long = System.nanoTime(), closure: Int? = null): Boolean = ways(now, closure).first() != null

    /**
     * The second way [via] answered where the first gave no answer: it comes first on this network for a while. Null
     * for directly. The global proxy learns only while the network is closed to the resolver, in [closure].
     */
    fun answeredBy(via: InetSocketAddress?, now: Long = System.nanoTime(), closure: Int? = null) {
        if (global && closure == null) return
        if (via == ways(now, closure).first()) return
        // The way that answered is the default first one again, or the other, which comes first for a while.
        val defaultFirst = (via != null) == PROXY_FIRST
        turnedIn = closure
        turnedUntil = if (defaultFirst) NEVER else now + PREFERRED_MS * 1_000_000
    }

    /** The proxy at [address] could not be reached: its next address is the one tried next. */
    fun unreachable(address: InetSocketAddress) {
        val i = addresses.indexOf(address)
        if (i >= 0) next.compareAndSet(i, i + 1)
    }

    /**
     * Whether [other] is the same proxy, its addresses in whatever order: of the same setting too, the network's or the
     * global one, since the global one's ways follow the network's closing and the network's do not.
     */
    fun same(other: ResolverProxy): Boolean = generation == other.generation && global == other.global &&
        setting == other.setting && addresses.toSet() == other.addresses.toSet()

    override fun toString(): String = addresses.joinToString(",") { "${it.address.hostAddress}:${it.port}" }

    companion object {
        /**
         * Whether the proxy is the first way of an exchange by default. Directly first (the resolver unit's review,
         * 2026-11-25): no proxy's operator learns when or where the resolver asks while the network lets it go
         * directly; a network that requires its proxy costs the first exchanges after each change one failed direct try,
         * and then the proxy comes first there.
         */
        const val PROXY_FIRST = false

        /** How long a way learned from an answer comes first, on the same network and setting. */
        const val PREFERRED_MS = 600_000L

        private const val NEVER = Long.MIN_VALUE
    }
}

/**
 * Whether the network beneath is closed to the resolver, for the global proxy's rule (ADR 0042, "Android's proxy"; the
 * global proxy's review, M1): the global proxy is a way only on a network that lets nothing through directly, so that
 * its operator learns of the resolver only there.
 *
 * Closed once the direct exchanges with at least [SERVERS] servers, at different addresses, found no connection on the
 * network of one generation: each failed at the connection itself (refused, unreachable, reset, or no TCP connection
 * within the try's time, [refused]), with no direct connection made since it began ([failed]), and none made since. A
 * TLS failure, a slow or failed HTTP answer and a server's own error come after a connection was made, and so open it,
 * as any direct connection made does. A server counts by its exchange, not by an address: one address refused beside
 * another that connects, as IPv6 on a network without it, or Happy Eyeballs' loser, says nothing. The exchange's end and
 * its socket's refusal may come in either order (a connect cut short when the exchange's time ran out ends after the
 * exchange did): whichever comes second, within [RACE_MS], counts the server. Each closing has a number of its own
 * ([closure]), so that what was learned while closed counts only in that closing.
 */
class DirectReach {
    private var generation = Int.MIN_VALUE

    /** Each server's latest direct connection that failed at the connection itself: its address, and when. */
    private val refusals = HashMap<String, Pair<InetAddress, Long>>()

    /** The servers whose exchanges found no direct connection since the last one made, by the address that refused. */
    private val failed = HashMap<InetAddress, String>()

    /** The servers whose direct exchange ended with no answer before any refusal of its came: when it began, and ended. */
    private val ended = HashMap<String, Pair<Long, Long>>()

    private var connectedAt = NEVER
    private var closed = false
    private var closings = 0

    /** The number of the network's current closing to the resolver on the network of [generation], or null while open. */
    @Synchronized
    fun closure(generation: Int): Int? = if (generation == this.generation && closed) closings else null

    /** A direct connection was made on the network of [generation], at [now]: it is open. Whether it was closed. */
    @Synchronized
    fun connected(generation: Int, now: Long = System.nanoTime()): Boolean {
        if (!at(generation)) return false
        connectedAt = now
        refusals.clear()
        failed.clear()
        ended.clear()
        return closed.also { closed = false }
    }

    /**
     * A direct connection to [server] at [address] failed at the connection itself on the network of [generation], at
     * [now]. Whether this closed the network to the resolver: when the server's exchange had already ended ([failed]).
     */
    @Synchronized
    fun refused(generation: Int, server: String, address: InetAddress, now: Long = System.nanoTime()): Boolean {
        if (!at(generation)) return false
        refusals[server] = address to now
        val (began, end) = ended.remove(server) ?: return false
        return now - end <= RACE_MS * 1_000_000 && count(server, began)
    }

    /**
     * A direct exchange with [server], begun at [began] on the network of [generation], ended with no answer at [now]. It
     * counts when one of the server's connections failed at the connection itself since [began] and none was made since
     * then, by this exchange or another. Whether this closed the network to the resolver.
     */
    @Synchronized
    fun failed(generation: Int, server: String, began: Long, now: Long = System.nanoTime()): Boolean {
        if (!at(generation)) return false
        val refusedAt = refusals[server]?.second
        if (refusedAt == null || refusedAt - began < 0) {
            // Its refusal may come yet.
            ended[server] = began to now
            return false
        }
        return count(server, began)
    }

    /** The server's exchange begun at [began] found no connection: one more server, unless one was made since. */
    private fun count(server: String, began: Long): Boolean {
        val address = refusals[server]?.first ?: return false
        // A connection was made while this exchange was tried: the network was open.
        if (connectedAt != NEVER && connectedAt - began >= 0) return false
        failed[address] = server
        if (closed || failed.values.toSet().size < SERVERS) return false
        closed = true
        closings++
        return true
    }

    /** Whether [generation] is the current one, after moving to it when it is newer; an older one's word is dropped. */
    private fun at(generation: Int): Boolean {
        if (generation < this.generation) return false
        if (generation > this.generation) {
            this.generation = generation
            refusals.clear()
            failed.clear()
            ended.clear()
            connectedAt = NEVER
            closed = false
        }
        return true
    }

    companion object {
        /** How many servers' direct exchanges must find no connection before the network counts as closed. */
        const val SERVERS = 2

        /** How long after an exchange ended its socket's refusal may still come and count. */
        const val RACE_MS = 500L

        private const val NEVER = Long.MIN_VALUE
    }
}
