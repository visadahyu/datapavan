package org.visadahyu.datapavan.network.dns

import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * The proxy the network part's resolver takes on purpose (ADR 0042, "Android's proxy"): the network beneath's own
 * direct proxy, never the process's, which Android gives a process at its start and so depends on whether the network
 * part started before its own VPN (measurements 7.1, point 3).
 *
 * A PAC gives none, and so do a proxy on the loopback, on one of the phone's own addresses or on a link-local one: such
 * a proxy is a tool's or a filter's local port, through which the resolver would loop through the tunnel or reach the
 * tool by another door than the engine's choice. A server the proxy's exclusion list names goes directly, as Android's
 * own selector sends it. The rule is pure, over plain values, so that the JVM tests hold it; [of] reads Android's
 * `ProxyInfo` into it.
 */
object NetworkProxy {
    /** A network's proxy as Android's settings give it: [host] and [port], whether a PAC file is set, its exclusions. */
    data class Setting(val host: String, val port: Int, val pac: Boolean, val exclusions: List<String>)

    /** Why the resolver uses the proxy it does, for the debug dump's `dns-proxy` line. */
    enum class Why(val word: String) {
        NETWORK("network"),
        NONE("none"),
        PAC("pac"),
        LOOPBACK("loopback"),
        LINK_LOCAL("link-local"),
        OWN("own"),
        UNRESOLVED("unresolved"),
    }

    /** At most this many of a proxy name's addresses are kept; a way through the proxy takes one, the next after one that could not be reached. */
    const val MAX_ADDRESSES = 2

    /**
     * The proxy of a network beneath, or the reason there is none, from its [setting]: null with [Why.NONE] for no
     * proxy, [Why.PAC] for a PAC file, whatever its host and port (Android reports a PAC as `localhost` and its
     * handler's port, which must never read as a direct proxy).
     */
    fun choose(setting: Setting?): Pair<Setting?, Why> = when {
        setting == null -> null to Why.NONE
        setting.pac -> null to Why.PAC
        setting.host.isBlank() || setting.port !in 1..65535 -> null to Why.NONE
        else -> setting to Why.NETWORK
    }

    /**
     * The addresses of a chosen proxy that the resolver may use, or the reason there are none: [own] says whether an
     * address is one of the phone's own (the tunnel's, the network's link addresses). Loopback, link-local and the
     * phone's own addresses are left out; at most [MAX_ADDRESSES] are kept, in the order given.
     */
    fun usable(addresses: List<InetAddress>, own: (InetAddress) -> Boolean): Pair<List<InetAddress>, Why> {
        if (addresses.isEmpty()) return emptyList<InetAddress>() to Why.UNRESOLVED
        val kept = addresses.filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isAnyLocalAddress && !own(it) }
        if (kept.isNotEmpty()) return kept.take(MAX_ADDRESSES) to Why.NETWORK
        val why = when {
            addresses.any { it.isLoopbackAddress || it.isAnyLocalAddress } -> Why.LOOPBACK
            addresses.any { it.isLinkLocalAddress } -> Why.LINK_LOCAL
            else -> Why.OWN
        }
        return emptyList<InetAddress>() to why
    }

    /**
     * Whether [server], a host name or an address, is in [exclusions], by the rules Android gives a proxy's exclusion
     * list (it becomes the process's `http.nonProxyHosts`): case-insensitive; `*` matches any run of characters, so
     * `*.example.com` takes the subdomains of `example.com` and `10.*` the addresses that start so; a leading `.` takes
     * the subdomains too; any other entry takes that host itself.
     */
    fun excluded(server: String, exclusions: List<String>): Boolean {
        val host = server.trim().trimEnd('.').removePrefix("[").removeSuffix("]").lowercase()
        if (host.isEmpty()) return false
        return exclusions.any { raw ->
            val entry = raw.trim().trimEnd('.').lowercase()
            when {
                entry.isEmpty() -> false
                '*' in entry -> glob(entry).matches(host)
                entry.startsWith(".") -> host.endsWith(entry)
                else -> host == entry
            }
        }
    }

    private fun glob(entry: String): Regex = Regex(entry.split('*').joinToString(".*") { Regex.escape(it) })

    /** A host as Android's setting writes it, with an IPv6 literal's brackets taken off. */
    fun bare(host: String): String = host.trim().removePrefix("[").removeSuffix("]")

    /** Whether [address] is an IPv6 address with a zone, which the resolver does not carry. */
    fun zoned(address: InetAddress): Boolean = address is Inet6Address && address.scopeId != 0

    /**
     * [Setting] from Android's `ProxyInfo` of the network beneath, or null for none: a PAC file is told by its URL, which
     * is not `Uri.EMPTY`, before its host and port are read.
     */
    fun of(info: android.net.ProxyInfo?): Setting? {
        info ?: return null
        val pac = info.pacFileUrl != null && info.pacFileUrl != android.net.Uri.EMPTY
        return Setting(info.host.orEmpty(), info.port, pac, info.exclusionList?.toList().orEmpty())
    }
}

/**
 * The network beneath's proxy the resolver may take, for the network of [generation] only: [setting] as read, and
 * [addresses] usable for it. An exchange tries two ways within one deadline ([ways]): the first, then the other when
 * the first gave no HTTP answer at all. Which comes first is learned only from an answer ([answeredBy]): after the
 * other way answered where the first gave none, that other way comes first on this network for [PREFERRED_MS], then
 * the default order again. A failure alone teaches nothing, since the server, not the way, may have failed.
 */
class ResolverProxy(val generation: Int, val setting: NetworkProxy.Setting, val addresses: List<InetSocketAddress>) {
    private val next = AtomicInteger(0)

    @Volatile
    private var turnedUntil = NEVER

    /** The two ways of an exchange now, the first first: directly (null) and through the proxy's address in turn. */
    fun ways(now: Long = System.nanoTime()): List<InetSocketAddress?> {
        val proxy = addresses[Math.floorMod(next.get(), addresses.size)]
        val turned = turnedUntil.let { it != NEVER && now - it < 0 }
        return if (PROXY_FIRST != turned) listOf(proxy, null) else listOf(null, proxy)
    }

    /** Whether the proxy comes first now, for the debug dump. */
    fun proxyFirst(now: Long = System.nanoTime()): Boolean = ways(now).first() != null

    /**
     * The second way [via] answered where the first gave no answer: it comes first on this network for a while. Null
     * for directly.
     */
    fun answeredBy(via: InetSocketAddress?, now: Long = System.nanoTime()) {
        if (via == ways(now).first()) return
        // The way that answered is the default first one again, or the other, which comes first for a while.
        val defaultFirst = (via != null) == PROXY_FIRST
        turnedUntil = if (defaultFirst) NEVER else now + PREFERRED_MS * 1_000_000
    }

    /** The proxy at [address] could not be reached: its next address is the one tried next. */
    fun unreachable(address: InetSocketAddress) {
        val i = addresses.indexOf(address)
        if (i >= 0) next.compareAndSet(i, i + 1)
    }

    /** Whether [other] is the same proxy, its addresses in whatever order. */
    fun same(other: ResolverProxy): Boolean =
        generation == other.generation && setting == other.setting && addresses.toSet() == other.addresses.toSet()

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
