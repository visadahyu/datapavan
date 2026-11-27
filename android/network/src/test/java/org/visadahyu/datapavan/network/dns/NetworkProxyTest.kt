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
 * The network beneath's own proxy as the resolver follows it, and Android's global one where the network has none (ADR
 * 0042, "Android's proxy"; the resolver unit's audit; the maintainer's decision of 2026-11-25): a PAC in Android's own
 * shape gives none, so do a loopback, a link-local and one of the phone's own addresses; the exclusion list by
 * Android's rules; a refusal remembered; and the `CONNECT` by address that carries nothing but `Host`.
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

    /**
     * The maintainer's decision of 2026-11-25: the network beneath's own direct proxy where it has one, Android's global
     * one only where the network has none, a PAC of the network's included, since the resolver cannot evaluate one.
     */
    @Test
    fun theNetworksOwnProxyComesFirstAndTheGlobalOneOnlyWhereTheNetworkHasNone() {
        val network = NetworkProxy.Setting("10.0.0.1", 3128, pac = false, exclusions = emptyList())
        val global = NetworkProxy.Setting("proxy.corp.example", 8080, pac = false, exclusions = emptyList())
        assertEquals(network to NetworkProxy.Why.NETWORK, NetworkProxy.choose(network, global))
        assertEquals(network to NetworkProxy.Why.NETWORK, NetworkProxy.choose(network, null))
        assertEquals(global to NetworkProxy.Why.GLOBAL, NetworkProxy.choose(null, global))
        // A network's PAC is no direct proxy of its own; nor is Android's empty setting.
        val networkPac = NetworkProxy.Setting("localhost", 34567, pac = true, exclusions = emptyList())
        assertEquals(global to NetworkProxy.Why.GLOBAL, NetworkProxy.choose(networkPac, global))
        assertEquals(global to NetworkProxy.Why.GLOBAL, NetworkProxy.choose(NetworkProxy.Setting("", 0, false, emptyList()), global))
        // A network's own direct proxy stays the only one, even one its addresses then leave out.
        val networkLoopback = NetworkProxy.Setting("127.0.0.1", 8118, pac = false, exclusions = emptyList())
        assertEquals(networkLoopback to NetworkProxy.Why.NETWORK, NetworkProxy.choose(networkLoopback, global))
        assertEquals(
            emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK,
            NetworkProxy.usable(listOf(address("127.0.0.1")), NetworkProxy.Why.NETWORK) { false },
        )
        assertEquals("global", NetworkProxy.Why.GLOBAL.word)
        assertEquals("network", NetworkProxy.Why.NETWORK.word)
    }

    @Test
    fun aGlobalPacIsNoDirectProxy() {
        // Android reports a PAC set for the whole phone as its URL with `localhost` and the handler's port, as a network's.
        val globalPac = NetworkProxy.Setting("localhost", 41234, pac = true, exclusions = emptyList())
        assertEquals(null to NetworkProxy.Why.PAC, NetworkProxy.choose(null, globalPac))
        assertEquals(null to NetworkProxy.Why.PAC, NetworkProxy.choose(NetworkProxy.Setting("localhost", 34567, true, emptyList()), null))
        assertEquals(null to NetworkProxy.Why.PAC, NetworkProxy.choose(NetworkProxy.Setting("localhost", 34567, true, emptyList()), globalPac))
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(null, null))
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(null, NetworkProxy.Setting("", 0, false, emptyList())))
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(null, NetworkProxy.Setting("proxy.example", 0, false, emptyList())))
    }

    @Test
    fun aGlobalProxyOnTheLoopbackALinkLocalOrThePhonesOwnAddressIsNotUsed() {
        val global = NetworkProxy.Setting("127.0.0.1", 8080, pac = false, exclusions = emptyList())
        assertEquals(global to NetworkProxy.Why.GLOBAL, NetworkProxy.choose(null, global))
        val none = { _: InetAddress -> false }
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.usable(listOf(address("127.0.0.1")), NetworkProxy.Why.GLOBAL, none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.usable(listOf(address("::1")), NetworkProxy.Why.GLOBAL, none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LINK_LOCAL, NetworkProxy.usable(listOf(address("169.254.7.7")), NetworkProxy.Why.GLOBAL, none))
        val own = address("10.0.2.16")
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.OWN, NetworkProxy.usable(listOf(own), NetworkProxy.Why.GLOBAL) { it == own })
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.UNRESOLVED, NetworkProxy.usable(emptyList(), NetworkProxy.Why.GLOBAL, none))
        // A usable one is kept as the global proxy's.
        assertEquals(listOf(address("10.0.2.2")) to NetworkProxy.Why.GLOBAL, NetworkProxy.usable(listOf(address("10.0.2.2")), NetworkProxy.Why.GLOBAL, none))
    }

    @Test
    fun theGlobalProxysExclusionListIsHonoured() {
        val global = NetworkProxy.Setting("proxy.corp.example", 3128, pac = false, exclusions = listOf("*.corp.example", "dns.example"))
        val (chosen, why) = NetworkProxy.choose(null, global)
        assertEquals(NetworkProxy.Why.GLOBAL, why)
        val exclusions = chosen!!.exclusions
        assertTrue(NetworkProxy.excluded("doh.corp.example", exclusions))
        assertTrue(NetworkProxy.excluded("dns.example", exclusions))
        assertFalse(NetworkProxy.excluded("cloudflare-dns.com", exclusions))
        assertFalse(NetworkProxy.excluded("odoh-relay.numa.rs", exclusions))
        // The network's own proxy, where it has one, brings its own list, never the global one's.
        val network = NetworkProxy.Setting("10.0.0.1", 3128, pac = false, exclusions = emptyList())
        assertFalse(NetworkProxy.excluded("doh.corp.example", NetworkProxy.choose(network, global).first!!.exclusions))
    }

    /**
     * The choice at each change of either setting, and whether the proxy it gives is the same one as the proxy held,
     * which [ResolverProxy.same] tells and a recompute keeps, with what it learned: the same values of the same setting
     * are; other values are not; nor are equal values from the other setting, since the global proxy's ways follow the
     * network's closing to the resolver and the network's own do not. The recompute itself reads Android's settings and
     * is measured on the emulator (scripts/measure-proxy-settings.sh, passes 3 and 6).
     */
    @Test
    fun aChangeOfEitherSettingChangesTheChoice() {
        val proxy = InetSocketAddress(address("10.0.2.2"), 3128)
        val global = NetworkProxy.Setting("10.0.2.2", 3128, pac = false, exclusions = emptyList())
        val network = NetworkProxy.Setting("10.0.2.2", 3128, pac = false, exclusions = listOf("*.lan.example"))
        // The global proxy set, on a network with none.
        val first = NetworkProxy.choose(null, global)
        assertEquals(NetworkProxy.Why.GLOBAL, first.second)
        val held = ResolverProxy(2, first.first!!, listOf(proxy), global = true)
        assertTrue(held.same(ResolverProxy(2, NetworkProxy.choose(null, global).first!!, listOf(proxy), global = true)))
        // The network gains its own, with other values: that one, in place of the global one.
        val second = NetworkProxy.choose(network, global)
        assertEquals(NetworkProxy.Why.NETWORK, second.second)
        assertFalse(held.same(ResolverProxy(2, second.first!!, listOf(proxy))))
        // The network gains its own with the global one's values: still another one.
        val equal = NetworkProxy.choose(global.copy(), global)
        assertEquals(global to NetworkProxy.Why.NETWORK, equal)
        assertFalse(held.same(ResolverProxy(2, equal.first!!, listOf(proxy))))
        // Both gone: none.
        assertEquals(null to NetworkProxy.Why.NONE, NetworkProxy.choose(null, null))
        // The global one becomes a PAC: none.
        assertEquals(null to NetworkProxy.Why.PAC, NetworkProxy.choose(null, global.copy(host = "localhost", port = 41234, pac = true)))
    }

    /**
     * The global proxy's review, M1: the network is closed to the resolver only once the direct exchanges with two
     * servers, at different addresses, found no connection on one network, each refused at the connection, with none
     * made since.
     */
    @Test
    fun theNetworkClosesOnlyWhenTwoServersCannotBeReachedAndNothingConnected() {
        val reach = DirectReach()
        val t = 1_000_000_000L
        // One server's outage, both its addresses refused, again and again: open.
        repeat(3) { n ->
            val began = t + n * 100
            assertFalse(reach.refused(4, "relay-a.example", address("192.0.2.1"), began + 1))
            assertFalse(reach.refused(4, "relay-a.example", address("2001:db8::1"), began + 2))
            assertFalse(reach.failed(4, "relay-a.example", began, began + 3))
        }
        assertNull(reach.closure(4))
        // A second server: closed, in a closing of its own.
        assertFalse(reach.refused(4, "relay-b.example", address("192.0.2.2"), t + 401))
        assertTrue(reach.failed(4, "relay-b.example", t + 400, t + 402))
        val closure = reach.closure(4)
        assertTrue(closure != null)
        assertNull(reach.closure(5))
        // More failures keep it closed, the same closing.
        reach.refused(4, "relay-c.example", address("192.0.2.3"), t + 501)
        assertFalse(reach.failed(4, "relay-c.example", t + 500, t + 502))
        assertEquals(closure, reach.closure(4))
        // A direct connection made opens it; the next closing has another number.
        assertTrue(reach.connected(4, t + 600))
        assertNull(reach.closure(4))
        assertFalse(reach.connected(4, t + 601))
        reach.refused(4, "relay-a.example", address("192.0.2.1"), t + 701)
        assertFalse(reach.failed(4, "relay-a.example", t + 700, t + 702))
        reach.refused(4, "relay-b.example", address("192.0.2.2"), t + 711)
        assertTrue(reach.failed(4, "relay-b.example", t + 710, t + 712))
        assertTrue(reach.closure(4) != null && reach.closure(4) != closure)
    }

    /**
     * A server counts by its exchange: an address refused beside another that connects, as IPv6 on a network without
     * it, or Happy Eyeballs' loser, says nothing; nor does an exchange that found no refusal, as one on a connection kept
     * from before, nor one while another connection was made, nor an older network's word.
     */
    @Test
    fun anAddressRefusedBesideOneThatConnectsSaysNothing() {
        val reach = DirectReach()
        val t = 1_000_000_000L
        // relay-a's IPv6 refused at once, its IPv4 connected: the exchange then fails at TLS.
        reach.refused(7, "relay-a.example", address("2001:db8::1"), t + 1)
        reach.connected(7, t + 2)
        assertFalse(reach.failed(7, "relay-a.example", t, t + 3))
        // relay-b likewise, while relay-c's exchange, begun before, failed at its only address.
        reach.refused(7, "relay-c.example", address("192.0.2.3"), t + 11)
        reach.refused(7, "relay-b.example", address("2001:db8::2"), t + 12)
        reach.connected(7, t + 13)
        assertFalse(reach.failed(7, "relay-b.example", t + 10, t + 14))
        assertFalse(reach.failed(7, "relay-c.example", t + 10, t + 15))
        assertNull(reach.closure(7))
        // An exchange that met no refusal of its own counts nothing, however it ended.
        assertFalse(reach.failed(7, "relay-d.example", t + 20, t + 21))
        assertFalse(reach.failed(7, "relay-e.example", t + 20, t + 22))
        assertNull(reach.closure(7))
        // The network before's word is dropped; a new network starts afresh.
        reach.refused(6, "relay-a.example", address("192.0.2.1"), t + 31)
        assertFalse(reach.failed(6, "relay-a.example", t + 30, t + 32))
        reach.refused(8, "relay-a.example", address("192.0.2.1"), t + 41)
        assertFalse(reach.failed(8, "relay-a.example", t + 40, t + 42))
        assertNull(reach.closure(8))
        assertNull(reach.closure(7))
    }

    /**
     * The exchange's end and its socket's refusal in either order: a connect cut short when the exchange's time ran out
     * ends after the exchange did, and still counts the server, within [DirectReach.RACE_MS].
     */
    @Test
    fun aRefusalThatComesAfterTheExchangeEndedStillCounts() {
        val reach = DirectReach()
        val t = 1_000_000_000L
        val ms = 1_000_000L
        assertFalse(reach.failed(2, "relay-a.example", t, t + 1_500 * ms))
        assertFalse(reach.refused(2, "relay-a.example", address("192.0.2.1"), t + 1_501 * ms))
        assertFalse(reach.failed(2, "relay-b.example", t + 2_000 * ms, t + 3_500 * ms))
        assertTrue(reach.refused(2, "relay-b.example", address("192.0.2.2"), t + 3_502 * ms))
        assertTrue(reach.closure(2) != null)
        // Too late after the end, it does not.
        val late = DirectReach()
        late.refused(2, "relay-a.example", address("192.0.2.1"), t + 1)
        assertFalse(late.failed(2, "relay-a.example", t, t + 2))
        assertFalse(late.failed(2, "relay-b.example", t + 10, t + 20))
        assertFalse(late.refused(2, "relay-b.example", address("192.0.2.2"), t + 20 + (DirectReach.RACE_MS + 1) * ms))
        assertNull(late.closure(2))
    }

    /**
     * The global proxy is a way only while the network is closed, and what it learned counts only in that closing; the
     * network's own proxy is a way whatever the network does.
     */
    @Test
    fun theGlobalProxyIsAWayOnlyWhileTheNetworkIsClosed() {
        val one = InetSocketAddress(address("10.0.2.2"), 3128)
        val setting = NetworkProxy.Setting("10.0.2.2", 3128, false, emptyList())
        val global = ResolverProxy(3, setting, listOf(one), global = true)
        val start = 1_000_000_000L
        assertEquals(listOf<InetSocketAddress?>(null), global.ways(start, closure = null))
        assertEquals(listOf(null, one), global.ways(start, closure = 1))
        // Learned only while closed.
        global.answeredBy(one, start, closure = null)
        assertEquals(listOf(null, one), global.ways(start, closure = 1))
        global.answeredBy(one, start, closure = 1)
        assertEquals(listOf(one, null), global.ways(start + 1, closure = 1))
        assertTrue(global.proxyFirst(start + 1, closure = 1))
        // Open again, then closed again: what was learned before is forgotten.
        assertEquals(listOf<InetSocketAddress?>(null), global.ways(start + 2, closure = null))
        assertEquals(listOf(null, one), global.ways(start + 3, closure = 2))
        // The network's own proxy: both ways, open or not, as before.
        val network = ResolverProxy(3, setting, listOf(one))
        assertEquals(listOf(null, one), network.ways(start, closure = null))
        network.answeredBy(one, start, closure = null)
        assertEquals(listOf(one, null), network.ways(start + 1, closure = null))
        assertFalse(global.same(network))
    }

    /**
     * The phone's own addresses are every interface's, the loopback's included, as this machine's kernel lists them: each
     * address listed both before and after the reading, since a busy machine's interfaces come and go.
     */
    @Test
    fun thePhonesOwnAddressesAreEveryInterfaces() {
        fun listed() = java.net.NetworkInterface.getNetworkInterfaces().toList().flatMap { it.inetAddresses.toList() }.toSet()
        val before = listed()
        val own = NetworkProxy.phoneAddresses()
        val stayed = before.intersect(listed())
        assertTrue(stayed.isNotEmpty())
        assertTrue(own.containsAll(stayed))
        assertTrue(own.any { it.isLoopbackAddress })
    }

    @Test
    fun aProxyOnTheLoopbackALinkLocalOrThePhonesOwnAddressIsNotUsed() {
        val none = { _: InetAddress -> false }
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.usable(listOf(address("127.0.0.1")), own = none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.usable(listOf(address("::1")), own = none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LINK_LOCAL, NetworkProxy.usable(listOf(address("169.254.1.1")), own = none))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LINK_LOCAL, NetworkProxy.usable(listOf(address("fe80::1")), own = none))
        val own = address("192.168.1.20")
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.OWN, NetworkProxy.usable(listOf(own)) { it == own })
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.UNRESOLVED, NetworkProxy.usable(emptyList(), own = none))
        // The usable ones are kept in order, at most two.
        val many = listOf(address("127.0.0.1"), address("10.0.0.1"), address("2001:db8::1"), address("10.0.0.2"))
        assertEquals(listOf(address("10.0.0.1"), address("2001:db8::1")) to NetworkProxy.Why.NETWORK, NetworkProxy.usable(many, own = none))
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

    /**
     * The proxy record's unit S2: the shared vectors (core/net/testdata/proxy-exclusions.tsv), which the engine's
     * `connect::excluded` reads too, so that the resolver and the engine never disagree on an exclusion list; only ASCII
     * letters fold.
     */
    @Test
    fun theExclusionListReadsAsTheEnginesDoes() {
        val rows = java.io.File("../../core/net/testdata/proxy-exclusions.tsv").readLines()
            .filter { it.isNotEmpty() && !it.startsWith("#") }
        assertTrue(rows.size >= 40)
        for (row in rows) {
            val (host, list, excluded) = row.split('\t')
            val entries = if (list == "-") emptyList() else list.split(',')
            assertEquals(row, excluded == "1", NetworkProxy.excluded(host, entries))
        }
        assertFalse("the Kelvin sign", NetworkProxy.excluded("k.example", listOf("\u212a.example")))
    }

    /**
     * S2, section 6: Android 17 refuses the network part a proxy on the local network without its grant: on Wi-Fi,
     * Ethernet or an unknown transport the private, shared and link-local ranges and the network's own prefixes; on
     * cellular only the network's own prefixes; multicast and broadcast anywhere; nothing with the grant.
     */
    @Test
    fun aLocalProxyWithoutTheGrantIsRefused() {
        for (transport in listOf(0, 1, 2)) {
            for (local in listOf("10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.20", "100.64.0.1", "100.127.255.255", "169.254.1.1", "fe80::1")) {
                assertTrue("$local on $transport", NetworkProxy.withoutGrant(address(local), transport, onLink = false, granted = false))
                assertFalse("$local granted", NetworkProxy.withoutGrant(address(local), transport, onLink = false, granted = true))
            }
            for (public in listOf("172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1", "192.169.0.1", "203.0.113.7", "2001:db8::7", "fd00::7")) {
                assertFalse("$public on $transport", NetworkProxy.withoutGrant(address(public), transport, onLink = false, granted = false))
            }
        }
        assertFalse(NetworkProxy.withoutGrant(address("10.0.0.5"), 3, onLink = false, granted = false))
        assertTrue(NetworkProxy.withoutGrant(address("10.0.0.5"), 3, onLink = true, granted = false))
        assertTrue(NetworkProxy.withoutGrant(address("fd00::7"), 1, onLink = true, granted = false))
        assertTrue(NetworkProxy.withoutGrant(address("224.0.0.1"), 3, onLink = false, granted = false))
        assertTrue(NetworkProxy.withoutGrant(address("255.255.255.255"), 4, onLink = false, granted = false))
        assertFalse(NetworkProxy.withoutGrant(address("224.0.0.1"), 3, onLink = true, granted = true))
    }

    /**
     * S2: the addresses Android 17 would refuse leave, the others stay, and none left says why; the engine takes the
     * network's own proxy alone, never the global one (audit M3): global only gives none, with its reason, both set the
     * network's, and a network's proxy without a usable address none, with the settle's reason.
     */
    @Test
    fun theEngineTakesTheNetworksOwnProxyAloneAndNoAddressRefusedForTheGrant() {
        val local = address("192.168.1.5")
        val public = address("203.0.113.7")
        val refused = { a: InetAddress -> a == local }
        assertEquals(listOf(public) to NetworkProxy.Why.NETWORK, NetworkProxy.granted(listOf(local, public), NetworkProxy.Why.NETWORK, refused))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOCAL_NO_GRANT, NetworkProxy.granted(listOf(local), NetworkProxy.Why.NETWORK, refused))
        assertEquals(emptyList<InetAddress>() to NetworkProxy.Why.LOOPBACK, NetworkProxy.granted(emptyList(), NetworkProxy.Why.LOOPBACK, refused))
        assertEquals("local-no-grant", NetworkProxy.Why.LOCAL_NO_GRANT.word)

        val at = listOf(InetSocketAddress(public, 3128))
        val network = NetworkProxy.Setting("proxy.corp.example", 3128, false, emptyList())
        val global = NetworkProxy.Setting("203.0.113.9", 8080, false, emptyList())
        // Global only: the resolver may follow it; the engine never does.
        val (_, globalWhy) = NetworkProxy.choose(null, global)
        assertEquals(emptyList<InetSocketAddress>() to NetworkProxy.Why.GLOBAL, NetworkProxy.forEngine(at, globalWhy, globalWhy))
        // Both set: the network's.
        val (chosen, why) = NetworkProxy.choose(network, global)
        assertEquals(network, chosen)
        assertEquals(at to NetworkProxy.Why.NETWORK, NetworkProxy.forEngine(at, why, why))
        assertEquals(emptyList<InetSocketAddress>() to NetworkProxy.Why.LOCAL_NO_GRANT, NetworkProxy.forEngine(emptyList(), why, NetworkProxy.Why.LOCAL_NO_GRANT))
        assertEquals(emptyList<InetSocketAddress>() to NetworkProxy.Why.PAC, NetworkProxy.forEngine(emptyList(), NetworkProxy.Why.PAC, NetworkProxy.Why.PAC))
    }

    /** S2: IPv6 for the engine needs a global unicast address and an IPv6 default route; the addresses as the JNI reads them. */
    @Test
    fun theNetworksIpv6AndTheEnginesAddressesAreAsTheEngineTakesThem() {
        assertTrue(NetworkProxy.ipv6(listOf(address("192.168.1.5"), address("2001:db8::5")), defaultRoute = true))
        assertFalse(NetworkProxy.ipv6(listOf(address("2001:db8::5")), defaultRoute = false))
        assertFalse(NetworkProxy.ipv6(listOf(address("fe80::5"), address("fd00::5"), address("192.168.1.5")), defaultRoute = true))
        assertEquals(
            "192.0.2.8 3128\n2001:db8:0:0:0:0:0:8 8080",
            NetworkProxy.engineAddresses(listOf(InetSocketAddress(address("192.0.2.8"), 3128), InetSocketAddress(address("2001:db8::8"), 8080))),
        )
        assertEquals("", NetworkProxy.engineAddresses(emptyList()))
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
