package org.visadahyu.datapavan.watch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet4Address
import java.net.Inet6Address
import kotlin.random.Random

class TunnelMtuTest {
    @Test
    fun theSmallerFirstHopWithinIpv6sLeastAndEthernets() {
        assertEquals("Wi-Fi, both versions", 1500, TunnelMtu.choose(1500, 1500))
        assertEquals("a mobile network narrower for IPv6, by its router advertisements", 1420, TunnelMtu.choose(1500, 1420))
        assertEquals("narrower for IPv4", 1400, TunnelMtu.choose(1400, 1500))
        assertEquals("no IPv6 on the network", 1460, TunnelMtu.choose(1460, null))
        assertEquals("IPv6 only", 1280, TunnelMtu.choose(null, 1280))
        assertEquals("neither answered: as before", 1500, TunnelMtu.choose(null, null))
        assertEquals("a kernel that says 0 says nothing", 1500, TunnelMtu.choose(0, null))
        assertEquals("never below IPv6's least, which a tunnel with IPv6 routes needs", 1280, TunnelMtu.choose(576, 1500))
        assertEquals("never above Ethernet's: a loopback or a jumbo-frame link", 1500, TunnelMtu.choose(65535, 9000))
        assertEquals("at the edges", 1280, TunnelMtu.choose(1280, 1281))
        assertEquals("at the edges", 1499, TunnelMtu.choose(1499, 1501))
    }

    @Test
    fun theProbesAddressesAreDrawnFromTheDocumentationRangesButNotWhereChecksSend() {
        val random = Random(2026_11_15)
        val v4 = List(5_000) { TunnelMtu.towardV4(random) }
        assertTrue(v4.all { it is Inet4Address })
        val last = v4.map { it.address[3].toInt() and 0xff }
        assertTrue("192.0.2.2 to .254", v4.all { it.address.take(3) == listOf(192.toByte(), 0, 2) })
        assertEquals("every one of .2 to .254, and no other", (2..254).toSet(), last.toSet())
        val v6 = List(2_000) { TunnelMtu.towardV6(random) }
        assertTrue(v6.all { it is Inet6Address })
        assertTrue("2001:db8::/32", v6.all { it.address.take(4) == listOf<Byte>(0x20, 0x01, 0x0d, 0xb8.toByte()) })
        assertTrue("never 2001:db8::/40, where checks send", v6.none { it.address[4] == 0.toByte() })
        assertEquals("drawn anew each time", 2_000, v6.toSet().size)
    }

    @Test
    fun withinOneNetworkTheMtuOnlyGoesDown() {
        assertEquals("lower on the same network: taken", 1400, TunnelMtu.next(1500, 1400, sameNetwork = true))
        assertEquals("higher on the same network: waits", 1400, TunnelMtu.next(1400, 1500, sameNetwork = true))
        assertEquals("the same", 1500, TunnelMtu.next(1500, 1500, sameNetwork = true))
        assertEquals("a new network takes its own, higher", 1500, TunnelMtu.next(1400, 1500, sameNetwork = false))
        assertEquals("or lower", 1280, TunnelMtu.next(1500, 1280, sameNetwork = false))
    }
}
