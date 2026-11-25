package org.visadahyu.datapavan.network.dns

import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The proxy the network part's resolver follows on purpose (ADR 0042, "Android's proxy"): the network beneath's own
 * direct proxy, never the process's, which Android gives a process at its start and so depends on whether the network
 * part started before its own VPN (measurements 7.1, point 3).
 *
 * Only the network beneath's own proxy, never the global one: the network's proxy sees what the network sees anyway,
 * the servers' addresses, while a global proxy is a third party (a device owner's cloud proxy, or one set over adb)
 * that would learn when and how often the resolver is used. A PAC gives none, and so do a proxy on the loopback, on one
 * of the phone's own addresses or on a link-local one: such a proxy is a tool's or a filter's local port, through which
 * the resolver would loop through the tunnel or reach the tool by another door than the engine's choice. A server the
 * proxy's exclusion list names goes directly, as Android's own selector sends it. The rule is pure, over plain values,
 * so that the JVM tests hold it; [of] reads Android's `ProxyInfo` into it.
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

    /** At most this many of a proxy name's addresses are tried, one an exchange, before it goes directly. */
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
     * Whether [server], a host name or an address, is in [exclusions], by Android's rules for a proxy's exclusion list:
     * case-insensitive; `*.example.com` and `.example.com` take the subdomains of `example.com`; any other entry takes
     * that host itself.
     */
    fun excluded(server: String, exclusions: List<String>): Boolean {
        val host = server.trim().trimEnd('.').removePrefix("[").removeSuffix("]").lowercase()
        if (host.isEmpty()) return false
        return exclusions.any { raw ->
            val entry = raw.trim().trimEnd('.').lowercase()
            when {
                entry.isEmpty() -> false
                entry.startsWith("*.") -> host.endsWith(entry.substring(1))
                entry.startsWith(".") -> host.endsWith(entry)
                else -> host == entry
            }
        }
    }

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
 * The network beneath's proxy the resolver follows, for the network of [generation] only: [setting] as read, and
 * [addresses] usable for it. It remembers a refusal ([refuse]): an address that failed is not tried again, and once no
 * address is left, or the proxy refused at the TLS step, the resolver goes directly on this network until
 * [REFUSED_MS] has passed or the proxy changes, which makes a new one.
 */
class ResolverProxy(val generation: Int, val setting: NetworkProxy.Setting, val addresses: List<InetSocketAddress>) {
    private val next = AtomicInteger(0)
    private val refusedAt = AtomicLong(NEVER)

    /** The address to try now, or null to go directly. */
    fun address(now: Long = System.nanoTime()): InetSocketAddress? {
        val at = refusedAt.get()
        if (at != NEVER && now - at < REFUSED_MS * 1_000_000) return null
        if (at != NEVER) {
            refusedAt.compareAndSet(at, NEVER)
            next.set(0)
        }
        return addresses.getOrNull(next.get())
    }

    /** [address] failed: the next one is tried, or, with none left or [all], the resolver goes directly for a while. */
    fun refuse(address: InetSocketAddress?, all: Boolean, now: Long = System.nanoTime()) {
        if (!all) {
            val i = addresses.indexOf(address)
            if (i >= 0) next.compareAndSet(i, i + 1)
            if (next.get() < addresses.size) return
        }
        refusedAt.set(now)
    }

    /** Whether the resolver goes directly on this network now, after a refusal. */
    fun refused(now: Long = System.nanoTime()): Boolean = address(now) == null

    override fun toString(): String = addresses.joinToString(",") { "${it.address.hostAddress}:${it.port}" }

    companion object {
        /** How long a refusing proxy is not asked again, on the same network and setting. */
        const val REFUSED_MS = 600_000L

        private const val NEVER = Long.MIN_VALUE
    }
}
