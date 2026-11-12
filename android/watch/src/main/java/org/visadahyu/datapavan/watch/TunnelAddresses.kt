package org.visadahyu.datapavan.watch

import java.net.Inet4Address
import java.net.InetAddress

/**
 * The tunnel's addresses (ADR 0041, decision 3), the same two sets as the engine's `Addresses` in
 * core/net/src/engine.rs; [TunnelAddressesTest] reads that file and fails if they drift apart.
 *
 * Any app can read the tunnel's address and prefix. Watch takes the ones that NetGuard, TrackerControl
 * and InviZible Pro give their tunnels ([COMMON]): an app that reads them finds a local firewall, the
 * kind of app Watch is, not Watch itself. The project stays open about what it is; the phone does not
 * tell other apps which tool its user chose.
 *
 * A network that uses those addresses itself, as Comcast Business gateways do with 10.1.10.1, would lose
 * its router and resolver to the tunnel, so there Watch takes its earlier, rarer addresses ([SPARE]).
 */
object TunnelAddresses {
    /** One set: the tunnel's own address (a /32 or a /128), the engine's fake peer, and its DNS server. */
    class Set(
        val name: String,
        val tun4: String,
        val fake4: String,
        val dns4: String,
        val tun6: String,
        val fake6: String,
        val dns6: String,
    ) {
        /** Every address of the set, each of which must stay off the network beneath. */
        val all: List<String> get() = listOf(tun4, fake4, dns4, tun6, fake6, dns6)
    }

    val COMMON = Set(
        name = "common",
        tun4 = "10.1.10.1",
        fake4 = "10.1.10.2",
        dns4 = "10.1.10.3",
        tun6 = "fd00:1:fd00:1:fd00:1:fd00:1",
        fake6 = "fd00:1:fd00:1:fd00:1:fd00:2",
        dns6 = "fd00:1:fd00:1:fd00:1:fd00:3",
    )

    val SPARE = Set(
        name = "spare",
        tun4 = "10.215.173.1",
        fake4 = "10.215.173.2",
        dns4 = "10.215.173.3",
        tun6 = "fd7a:6470:7761::1",
        fake6 = "fd7a:6470:7761::2",
        dns6 = "fd7a:6470:7761::3",
    )

    /** What a network beneath the tunnel uses: its own addresses with their prefixes, its gateways and DNS servers. */
    class Network(val addresses: List<Pair<InetAddress, Int>>, val others: List<InetAddress>)

    /** The set for the networks beneath: [COMMON], unless one of them uses one of its addresses and [SPARE] is free. */
    fun choose(networks: List<Network>): Set = if (clashes(COMMON, networks) && !clashes(SPARE, networks)) SPARE else COMMON

    /** Whether any address of [set] lies in a network's own subnet, or is its gateway or DNS server. */
    fun clashes(set: Set, networks: List<Network>): Boolean = set.all.map(::address).any { ours ->
        networks.any { network ->
            network.others.any { it == ours } ||
                network.addresses.any { (theirs, prefix) -> sameSubnet(ours, theirs, prefix) }
        }
    }

    private fun address(text: String): InetAddress = InetAddress.getByName(text)

    /** Whether [a] and [b] share their first [prefix] bits; addresses of different families never do. */
    private fun sameSubnet(a: InetAddress, b: InetAddress, prefix: Int): Boolean {
        if ((a is Inet4Address) != (b is Inet4Address)) return false
        val x = a.address
        val y = b.address
        val bits = prefix.coerceIn(0, x.size * 8)
        for (i in 0 until bits) {
            val mask = 0x80 ushr (i % 8)
            if ((x[i / 8].toInt() and mask) != (y[i / 8].toInt() and mask)) return false
        }
        return true
    }
}
