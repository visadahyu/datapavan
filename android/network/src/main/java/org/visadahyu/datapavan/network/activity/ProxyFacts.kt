package org.visadahyu.datapavan.network.activity

import java.net.Inet6Address
import java.net.InetAddress
import org.visadahyu.datapavan.network.log.LogRecord

/**
 * What "Now" and each app's history say of an app's own proxy (W8, part 2a; ADR 0052), as a pure function the JVM
 * tests hold: the proxy's kind, how the network part knows it (read from the connection, or inferred from where and how
 * it connects), where it is, and the facts beside it. Never who runs it: an address's organisation hosts it, it does
 * not run it (ADR 0036, decision 4); never whether the user chose it; never a password, which the engine never keeps.
 */
object ProxyFacts {
    /** Where a proxy's address is: on the user's local network, in a network the organisation table names, or neither. */
    enum class Where { LOCAL, NETWORK, UNKNOWN }

    /**
     * The kinds as the screens name them: a SOCKS5, SOCKS4 or HTTP (`CONNECT`) proxy, whose reply confirmed it, or a
     * messenger's; and [REQUEST], a plain HTTP request in the absolute form a proxy takes, which nothing confirms:
     * origin servers take that form too, so its row says what the request asked for, never that the server is a
     * proxy (fix round of W8 part 2a).
     */
    enum class Kind { SOCKS5, SOCKS4, HTTP, REQUEST, MTPROTO, WHATSAPP, SIGNAL }

    /**
     * What a row says of its proxy. [kept] is false when the engine left the flow's own address and names out for
     * the switch ([LogRecord.Proxy.leftOut], never read from an address of zeros): then only the kind and the facts
     * that name nothing are shown. [at] is the proxy's own name or its address, with its port; [asked] the
     * destination asked for, with its port, for a declared proxy, and empty for a plain request's while the switch
     * is off ([askedLeftOut]); [maker] the company whose network the address is not, where the network part can tell;
     * [cover] and [coverOwner] the name an inferred proxy's hello sent and, where the owners' table names both, the
     * company it belongs to beside the network's; [shownOnly] whether "Now" shows this first hop only for its window,
     * as the engine marks it (snapshot version 5), never in the history.
     */
    data class Facts(
        val kind: Kind,
        val declared: Boolean,
        val kept: Boolean,
        val at: String,
        val asked: String,
        val where: Where,
        val organisation: String,
        val maker: String,
        val setting: Boolean,
        val password: Boolean,
        val cover: String,
        val coverOwner: Pair<String, String>?,
        val shownOnly: Boolean = false,
    ) {
        /** Whether a plain request's destination asked for was left out for the switch, its server kept. */
        val askedLeftOut: Boolean get() = kind == Kind.REQUEST && asked.isEmpty()
    }

    /**
     * The facts of [proxy] at [address] and [port]. [appMaker] is the app's company group's name, where the owners'
     * table knows it, and [networkGroup] and [coverGroup] give the company group of a network by its AS number and of
     * a host name, with [groupName] naming a group; for an inferred proxy outside its maker's network the maker is
     * the messenger's own name. [shownOnly] is the snapshot's mark of a first hop "Now" shows only; a record of the
     * history never has it.
     */
    fun of(
        proxy: LogRecord.Proxy,
        address: InetAddress,
        port: Int,
        asn: Long = 0,
        appMaker: String? = null,
        networkGroup: (Long) -> String? = { null },
        coverGroup: (String) -> String? = { null },
        groupName: (String) -> String = { it },
        shownOnly: Boolean = false,
    ): Facts {
        val kind = when (proxy.kind) {
            LogRecord.PROXY_SOCKS5 -> Kind.SOCKS5
            LogRecord.PROXY_SOCKS4 -> Kind.SOCKS4
            LogRecord.PROXY_CONNECT -> Kind.HTTP
            LogRecord.PROXY_FORWARD -> Kind.REQUEST
            LogRecord.PROXY_MTPROTO -> Kind.MTPROTO
            LogRecord.PROXY_WHATSAPP -> Kind.WHATSAPP
            else -> Kind.SIGNAL
        }
        val kept = proxy.kept
        val where = when {
            isLocal(address) -> Where.LOCAL
            proxy.organisation.isNotEmpty() -> Where.NETWORK
            else -> Where.UNKNOWN
        }
        val network = networkGroup(asn).takeIf { asn != 0L }
        val maker = when {
            !proxy.declared && proxy.outsideMaker -> when (kind) {
                Kind.MTPROTO -> "Telegram"
                Kind.WHATSAPP -> "WhatsApp"
                else -> ""
            }
            // A declared proxy's network is said not to be the app maker's only where the owners' table names both
            // companies, and they differ.
            appMaker != null && network != null && groupName(network) != appMaker -> appMaker
            else -> ""
        }
        val coverOwner = proxy.cover.takeIf { it.isNotEmpty() }?.let(coverGroup)?.let { cover ->
            network?.takeIf { it != cover }?.let { groupName(cover) to groupName(it) }
        }
        val at = proxy.proxyName.ifEmpty { address.hostAddress.orEmpty() }
        return Facts(
            kind = kind,
            declared = proxy.declared,
            kept = kept,
            at = if (kept) hostPort(at, port) else "",
            asked = if (proxy.askedPort >= 0) hostPort(proxy.asked, proxy.askedPort) else "",
            where = where,
            organisation = proxy.organisation,
            maker = maker,
            setting = proxy.setting,
            password = proxy.password,
            cover = proxy.cover,
            coverOwner = coverOwner,
            shownOnly = shownOnly,
        )
    }

    /** The engine's counters of apps' own proxies (ADR 0052): declared, with a password, inferred, substituted, taken back, covers. */
    val COUNTERS = 61..66

    /**
     * The engine's counters as the network part's dump writes them: all of them in a debuggable build; in a release,
     * the proxies' as `-`, in their places, since they say that apps on the phone used proxies of their own, which ADR
     * 0047's searched phone must not show (fix round of W8 part 2a, S-m5).
     */
    fun dumpedCounters(counters: LongArray, debuggable: Boolean): List<String> =
        counters.mapIndexed { i, n -> if (debuggable || i !in COUNTERS) n.toString() else "-" }

    /** A host and port as people write them: an IPv6 address in brackets. */
    fun hostPort(host: String, port: Int): String = if (':' in host) "[$host]:$port" else "$host:$port"

    /**
     * Whether an address is on the user's own network: private (10/8, 172.16/12, 192.168/16), link-local, or IPv6's
     * unique local addresses (fc00::/7). Loopback never reaches the network part: a proxy on the phone itself is not
     * seen.
     */
    fun isLocal(address: InetAddress): Boolean = address.isSiteLocalAddress || address.isLinkLocalAddress ||
        (address is Inet6Address && (address.address[0].toInt() and 0xfe) == 0xfc)
}
