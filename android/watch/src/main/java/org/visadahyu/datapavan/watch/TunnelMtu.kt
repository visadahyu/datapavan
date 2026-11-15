package org.visadahyu.datapavan.watch

import java.net.InetAddress

/**
 * The tunnel's MTU (ADR 0044, decision 5 as amended): the first hop's of the network beneath, as the
 * phone's kernel reports it, so that each app's own kernel meets that hop as it would without Watch.
 * A datagram larger than the hop is then fragmented by the app's kernel, which the engine puts
 * together again, or refused by it at once, by the app socket's own setting. An MTU the engine had to
 * answer for itself, as a router does, would lose datagrams of connected sockets and of sockets that
 * ignore path MTU (the second review of unit 12).
 *
 * `LinkProperties.getMtu()` is 0 on most networks, so the kernel is asked instead: a UDP socket of
 * each IP version, bound to the network beneath, connected toward [TOWARD_V4] or [TOWARD_V6], which
 * only a default route covers, and its `IP_MTU` read. Connecting a UDP socket sends nothing.
 */
object TunnelMtu {
    /** IPv6's least MTU (RFC 8200): a tunnel with IPv6 routes takes no less. */
    const val LEAST = 1280

    /** Ethernet's and Wi-Fi's, and the tunnel's before this unit: no more. */
    const val MOST = 1500

    /** Documentation addresses (RFC 5737, RFC 3849), which no network routes on its own. */
    val TOWARD_V4: InetAddress = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1))
    val TOWARD_V6: InetAddress = InetAddress.getByAddress(
        byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
    )

    /** The port the probe's sockets are connected to; nothing is sent there. */
    const val PORT = 9

    /**
     * The tunnel's MTU for what the kernel said of the first hop of IPv4 and of IPv6, each null where
     * its socket did not answer, as on a network without IPv6: the smaller, within [LEAST] and [MOST];
     * [MOST] when neither answered, as before this unit.
     */
    fun choose(v4: Int?, v6: Int?): Int =
        (listOfNotNull(v4, v6).filter { it > 0 }.minOrNull() ?: MOST).coerceIn(LEAST, MOST)
}
