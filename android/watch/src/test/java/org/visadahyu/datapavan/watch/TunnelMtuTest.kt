package org.visadahyu.datapavan.watch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

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
    fun theProbeAddressesAreTheDocumentationOnes() {
        assertEquals(InetAddress.getByName("192.0.2.1"), TunnelMtu.TOWARD_V4)
        assertEquals(InetAddress.getByName("2001:db8::1"), TunnelMtu.TOWARD_V6)
        assertTrue(TunnelMtu.TOWARD_V4 is Inet4Address && TunnelMtu.TOWARD_V6 is Inet6Address)
    }
}
