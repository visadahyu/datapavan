package org.visadahyu.datapavan.network.dns

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The network beneath's own proxy as the resolver follows it (ADR 0042, "Android's proxy"; the resolver unit's audit):
 * a PAC in Android's own shape gives none, so do a loopback, a link-local and one of the phone's own addresses; the
 * exclusion list by Android's rules; a refusal remembered; and the `CONNECT` by address that carries nothing but
 * `Host`.
 */
class NetworkProxyTest {
    private val servers = mutableListOf<ServerSocket>()

    @After
    fun closeServers() = servers.forEach { it.close() }

    private fun address(text: String) = InetAddress.getByName(text)

    @Test
    fun aPacInAndroidsOwnShapeIsNoDirectProxy() {
        // Android reports a PAC as its URL with `localhost` and the handler's port.
        val pac = NetworkProxy.Setting("localhost", 34567, pac = true, exclusions = emptyList())
        assertEquals(null to NetworkProxy.Why.PAC, NetworkProxy.choose(pac))
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(null))
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(NetworkProxy.Setting("", 3128, false, emptyList())))
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(NetworkProxy.Setting("proxy.example", 0, false, emptyList())))
        val direct = NetworkProxy.Setting("proxy.example", 3128, false, listOf("*.corp.example"))
        assertEquals(direct to NetworkProxy.Why.NETWORK, NetworkProxy.choose(direct))
    }

    @Test
    fun aProxyOnTheLoopbackALinkLocalOrThePhonesOwnAddressIsNotUsed() {
        val none = { _: InetAddress -> false }
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.usable(listOf(address("127.0.0.1")), none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.usable(listOf(address("::1")), none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LINK_LOCAL, NetworkProxy.usable(listOf(address("169.254.1.1")), none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LINK_LOCAL, NetworkProxy.usable(listOf(address("fe80::1")), none))
        val own = address("192.168.1.20")
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.OWN, NetworkProxy.usable(listOf(own)) { it == own })
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.UNRESOLVED, NetworkProxy.usable(emptyList(), none))
        // The usable ones are kept in order, at most two.
        val many = listOf(address("127.0.0.1"), address("10.0.0.1"), address("2001:db8::1"), address("10.0.0.2"))
        assertEquals(listOf(address("10.0.0.1"), address("2001:db8::1")) to NetworkProxy.Why.NETWORK, NetworkProxy.usable(many, none))
    }

    @Test
    fun theExclusionListTakesAndroidsForms() {
        val list = listOf("*.corp.example", ".lan.example", "dns.example", " Mixed.Example ")
        assertTrue(NetworkProxy.excluded("dns.corp.example", list))
        assertTrue(NetworkProxy.excluded("a.b.lan.example", list))
        assertTrue(NetworkProxy.excluded("DNS.example.", list))
        assertTrue(NetworkProxy.excluded("mixed.example", list))
        assertFalse(NetworkProxy.excluded("corp.example.net", list))
        assertFalse(NetworkProxy.excluded("sub.dns.example", list))
        assertFalse(NetworkProxy.excluded("cloudflare-dns.com", list))
        assertFalse(NetworkProxy.excluded("", list))
        // Android's wildcards anywhere in an entry.
        assertTrue(NetworkProxy.excluded("10.1.2.3", listOf("10.*")))
        assertFalse(NetworkProxy.excluded("110.1.2.3", listOf("10.*")))
        assertTrue(NetworkProxy.excluded("host-7.corp.example", listOf("host-*.corp.example")))
        assertEquals("2001:db8::1", NetworkProxy.bare("[2001:db8::1]"))
    }

    @Test
    fun aWayComesFirstOnlyAfterItAnsweredWhereTheOtherGaveNone() {
        val one = InetSocketAddress(address("10.0.0.1"), 3128)
        val two = InetSocketAddress(address("10.0.0.2"), 3128)
        val route = ResolverProxy(3, NetworkProxy.Setting("proxy.example", 3128, false, emptyList()), listOf(one, two))
        val start = 1_000_000_000L
        // Directly first, by default.
        assertEquals(listOf(null, one), route.ways(start))
        // The proxy answered where directly gave nothing: it comes first on this network, for a while.
        route.answeredBy(one, start)
        assertEquals(listOf(one, null), route.ways(start))
        assertTrue(route.proxyFirst(start + 1))
        val later = start + ResolverProxy.PREFERRED_MS * 1_000_000 + 1
        assertEquals(listOf(null, one), route.ways(later))
        // Directly answered where the proxy gave nothing: the default order again at once.
        route.answeredBy(one, later)
        route.answeredBy(null, later)
        assertEquals(listOf(null, one), route.ways(later))
        // A way that answered first teaches nothing new.
        route.answeredBy(null, later)
        assertEquals(listOf(null, one), route.ways(later))
        // A proxy address that could not be reached gives way to the next one.
        route.unreachable(one)
        assertEquals(listOf(null, two), route.ways(later))
        // The same proxy, its addresses in another order.
        assertTrue(route.same(ResolverProxy(3, route.setting, listOf(two, one))))
        assertFalse(route.same(ResolverProxy(4, route.setting, listOf(one, two))))
    }

    @Test
    fun theConnectAsksForTheAddressWithHostAloneAndReadsTheAnswer() {
        val proxy = ServerSocket(0, 8, InetAddress.getLoopbackAddress()).also { servers += it }
        val seen = ArrayBlockingQueue<String>(2)
        Thread {
            try {
                proxy.accept().use { socket ->
                    seen.put(ProxySocket.head(socket.getInputStream()))
                    socket.getOutputStream().apply {
                        write("HTTP/1.1 200 Connection established\r\nVia: test\r\n\r\nhello".toByteArray())
                        flush()
                    }
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true; start() }
        val socket = ProxySocket(InetSocketAddress(InetAddress.getLoopbackAddress(), proxy.localPort), 5_000)
        socket.connect(InetSocketAddress(address("192.0.2.9"), 443), 5_000)
        assertEquals("CONNECT 192.0.2.9:443 HTTP/1.1\r\nHost: 192.0.2.9:443\r\n\r\n", seen.poll(5, TimeUnit.SECONDS))
        assertEquals(address("192.0.2.9"), socket.inetAddress)
        assertEquals(443, socket.port)
        // Nothing of the tunnel after the blank line was taken.
        assertEquals("hello", String(DataInputStream(socket.getInputStream()).let { ByteArray(5).also(it::readFully) }))
        socket.close()
    }

    @Test
    fun anAnswerButA2xxAndAProxyNotListeningAreRefusals() {
        for ((answer, status) in listOf("HTTP/1.1 403 Forbidden\r\n\r\n" to 403, "HTTP/1.0 407 Proxy Authentication Required\r\n\r\n" to 407, "nonsense\r\n\r\n" to 0)) {
            val proxy = ServerSocket(0, 8, InetAddress.getLoopbackAddress()).also { servers += it }
            Thread {
                try {
                    proxy.accept().use { socket ->
                        ProxySocket.head(socket.getInputStream())
                        socket.getOutputStream().apply { write(answer.toByteArray()); flush() }
                    }
                } catch (_: Exception) {
                }
            }.apply { isDaemon = true; start() }
            val refused = runCatching {
                ProxySocket(InetSocketAddress(InetAddress.getLoopbackAddress(), proxy.localPort), 5_000)
                    .connect(InetSocketAddress(address("192.0.2.9"), 443), 5_000)
            }.exceptionOrNull()
            assertTrue("$answer: $refused", refused is ProxySocket.Refused)
            assertEquals(status, (refused as ProxySocket.Refused).status)
        }
        val closed = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).let { it.localPort.also { _ -> it.close() } }
        val refused = runCatching {
            ProxySocket(InetSocketAddress(InetAddress.getLoopbackAddress(), closed), 1_000)
                .connect(InetSocketAddress(address("192.0.2.9"), 443), 5_000)
        }.exceptionOrNull()
        assertTrue("$refused", refused is ProxySocket.Refused)
        assertEquals(0, (refused as ProxySocket.Refused).status)
        assertTrue(Exchanger.refusal(java.io.IOException("wrapped", refused)) === refused)
    }

    @Test
    fun anIpv6AddressIsWrittenInBracketsAndAStatusLineIsRead() {
        // In brackets, as the JVM or Android writes the address inside them (both forms are the same address).
        val six = ProxySocket.literal(address("2001:db8::1"))
        assertTrue(six, six.startsWith("[") && six.endsWith("]"))
        assertEquals(address("2001:db8::1"), address(six.removePrefix("[").removeSuffix("]")))
        // Never with a zone, which a `CONNECT`'s authority cannot carry.
        assertFalse(ProxySocket.literal(address("fe80::1%1")).contains('%'))
        assertEquals("192.0.2.1", ProxySocket.literal(address("192.0.2.1")))
        assertEquals(200, ProxySocket.status("HTTP/1.1 200 OK\r\n\r\n"))
        assertEquals(0, ProxySocket.status("HTTP/2 200\r\n\r\n"))
        assertEquals(0, ProxySocket.status("HTTP/1.1 2000 OK\r\n\r\n"))
        val tooLong = ByteArrayInputStream(ByteArray(ProxySocket.MAX_HEAD + 1) { 'a'.code.toByte() })
        assertTrue(runCatching { ProxySocket.head(tooLong) }.exceptionOrNull() is java.io.IOException)
    }
}
