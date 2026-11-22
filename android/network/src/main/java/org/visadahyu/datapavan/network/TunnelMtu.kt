package org.visadahyu.datapavan.network

import java.net.InetAddress
import kotlin.random.Random

/**
 * The tunnel's MTU (ADR 0044, decision 5 as amended): the first hop's of the network beneath, as the
 * phone's kernel reports it, so that each app's own kernel meets that hop as it would without Watch.
 * A datagram larger than the hop is then fragmented by the app's kernel, which the engine puts
 * together again, or refused by it at once, by the app socket's own setting. An MTU the engine had to
 * answer for itself, as a router does, would lose datagrams of connected sockets and of sockets that
 * ignore path MTU (the second review of unit 12).
 *
 * `LinkProperties.getMtu()` is 0 on most networks, so the kernel is asked instead: a UDP socket of
 * each IP version, bound to the network beneath, connected toward an address only a default route
 * covers ([towardV4], [towardV6]), and its `IP_MTU` read. Connecting a UDP socket sends nothing.
 *
 * Android's `Builder.setMtu` takes one MTU for both IP versions, so the tunnel takes the smaller of the
 * two first hops': on a network whose IPv4 and IPv6 hops differ, the wider version meets the narrower
 * MTU in the tunnel, not its own hop's.
 */
object TunnelMtu {
    /** IPv6's least MTU (RFC 8200): a tunnel with IPv6 routes takes no less. */
    const val LEAST = 1280

    /**
     * Ethernet's and Wi-Fi's, and the tunnel's before this unit: no more. The engine reads no datagram
     * larger than this as QUIC's (`quic::LARGEST_DATAGRAM`), which a Rust test holds to this value: raise
     * one, and the other must follow (ADR 0044, unit 9b, fix round 4).
     */
    const val MOST = 1500

    /**
     * An address in 192.0.2.0/24 (RFC 5737), which no network routes on its own, to connect the IPv4
     * probe toward: drawn anew at each measure, from .2 to .254. One address used every time could have
     * a path MTU of its own in the kernel, which an app that sends there and a host that forges a "too
     * big" for it could set, and so steer the tunnel's MTU (re-review of unit 12, minor 4). .1 is left
     * to the checks that send there (scripts/verify-network.sh).
     */
    fun towardV4(random: Random): InetAddress =
        InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, random.nextInt(2, 255).toByte()))

    /**
     * And one in 2001:db8::/32 (RFC 3849), drawn anew from 2^96 at each measure, its fifth byte never 0,
     * so never in 2001:db8::/40, where 2001:db8::1 and the other addresses checks send to lie.
     */
    fun towardV6(random: Random): InetAddress {
        val address = random.nextBytes(16)
        byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte()).copyInto(address)
        address[4] = random.nextInt(1, 256).toByte()
        return InetAddress.getByAddress(address)
    }

    /** The port the probe's sockets are connected to; nothing is sent there. */
    const val PORT = 9

    /**
     * The tunnel's MTU for what the kernel said of the first hop of IPv4 and of IPv6, each null where
     * its socket did not answer, as on a network without IPv6: the smaller, within [LEAST] and [MOST];
     * [MOST] when neither answered, as before this unit.
     */
    fun choose(v4: Int?, v6: Int?): Int =
        (listOfNotNull(v4, v6).filter { it > 0 }.minOrNull() ?: MOST).coerceIn(LEAST, MOST)

    /** How long after the tunnel was last set up its MTU may rise within one network: ten minutes. */
    const val RISE_AFTER_MS = 10 * 60 * 1_000L

    /**
     * The tunnel's MTU once a measure gave [measured], where it was [current]: a new network takes its
     * own; within the same network ([sameNetwork]) a lower value is taken at once, and a higher one only
     * once [RISE_AFTER_MS] have passed since the tunnel was last set up ([sinceSetUpMs]). So a reading
     * low for a moment, as while a network's IPv6 or its CLAT comes up, does not keep the tunnel narrow
     * for the network's whole life, and a route that flaps sets the tunnel up again at most once in ten
     * minutes for each rise, and once for each fall that follows it.
     */
    fun next(current: Int, measured: Int, sameNetwork: Boolean, sinceSetUpMs: Long): Int = when {
        !sameNetwork || measured <= current -> measured
        sinceSetUpMs >= RISE_AFTER_MS -> measured
        else -> current
    }

    /**
     * How long until a rise that [next] held back may be taken, so that the first hop is measured again
     * then, with no change of the network's properties needed to ask (fourth check of unit 12, minor 2);
     * null when none is held back.
     */
    fun riseWait(current: Int, measured: Int, sameNetwork: Boolean, sinceSetUpMs: Long): Long? =
        if (sameNetwork && measured > current && sinceSetUpMs < RISE_AFTER_MS) RISE_AFTER_MS - sinceSetUpMs else null
}
