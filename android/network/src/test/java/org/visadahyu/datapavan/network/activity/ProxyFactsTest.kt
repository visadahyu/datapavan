package org.visadahyu.datapavan.network.activity

import java.io.File
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.log.LogRecord

/** What "Now" and each app's history say of an app's own proxy (W8, part 2a; ADR 0052). */
class ProxyFactsTest {
    private val hetzner = InetAddress.getByName("203.0.113.5")

    @Test
    fun aDeclaredProxySaysWhatItWasAskedForWhereItIsAndNeverWhoRunsIt() {
        val proxy = LogRecord.Proxy(
            LogRecord.PROXY_SOCKS5, setting = true, password = true, asked = "example.org", askedPort = 443,
            proxyName = "proxy.example.net", organisation = "Hetzner Online GmbH",
        )
        val facts = ProxyFacts.of(proxy, hetzner, 1080)
        assertEquals(ProxyFacts.Kind.SOCKS5 to true, facts.kind to facts.declared)
        assertEquals("proxy.example.net:1080" to "example.org:443", facts.at to facts.asked)
        assertEquals(ProxyFacts.Where.NETWORK to "Hetzner Online GmbH", facts.where to facts.organisation)
        assertEquals(true to true, facts.setting to facts.password)
        // No company of the network is known: nothing is said of the app's maker.
        assertEquals("", ProxyFacts.of(proxy, hetzner, 1080, asn = 24_940, appMaker = "Mozilla").maker)
        // The owners' table names both, and they differ: the network is not the maker's.
        val known = ProxyFacts.of(proxy, hetzner, 1080, asn = 16_509, appMaker = "Mozilla", networkGroup = { "amazon" }, groupName = { "Amazon" })
        assertEquals("Mozilla", known.maker)
        val same = ProxyFacts.of(proxy, hetzner, 1080, asn = 15_169, appMaker = "Google", networkGroup = { "google" }, groupName = { "Google" })
        assertEquals("", same.maker)
    }

    @Test
    fun anInferredProxyOutsideItsMakersNetworkNamesTheMakerAndItsCover() {
        val proxy = LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, organisation = "Example Net", cover = "www.google.com")
        val facts = ProxyFacts.of(
            proxy, hetzner, 443, asn = 24_940, networkGroup = { "hetzner" }, coverGroup = { "google" }, groupName = { it.replaceFirstChar(Char::uppercase) },
        )
        assertEquals(ProxyFacts.Kind.MTPROTO to false, facts.kind to facts.declared)
        assertEquals("Telegram" to "203.0.113.5:443", facts.maker to facts.at)
        assertEquals("" to "www.google.com", facts.asked to facts.cover)
        assertEquals("Google" to "Hetzner", facts.coverOwner)
        // A cover of the network's own company says nothing more.
        assertEquals(null, ProxyFacts.of(proxy, hetzner, 443, asn = 15_169, networkGroup = { "google" }, coverGroup = { "google" }).coverOwner)
        assertEquals("WhatsApp", ProxyFacts.of(proxy.copy(kind = LogRecord.PROXY_WHATSAPP), hetzner, 5222).maker)
        // Signal has no network of its own: nothing is said of a maker.
        assertEquals("", ProxyFacts.of(proxy.copy(kind = LogRecord.PROXY_SIGNAL, outsideMaker = false), hetzner, 443).maker)
    }

    @Test
    fun aProxyOnTheLocalNetworkOrOfNoKnownNetworkIsSaidSo() {
        val proxy = LogRecord.Proxy(LogRecord.PROXY_CONNECT, asked = "2001:db8:0:0:0:0:0:7", askedPort = 8443)
        for (local in listOf("10.0.2.2", "192.168.1.2", "172.16.0.1", "fe80::1", "fd00::5")) {
            assertEquals(local, ProxyFacts.Where.LOCAL, ProxyFacts.of(proxy, InetAddress.getByName(local), 3128).where)
        }
        val unknown = ProxyFacts.of(proxy, hetzner, 3128)
        assertEquals(ProxyFacts.Where.UNKNOWN to ProxyFacts.Kind.HTTP, unknown.where to unknown.kind)
        assertEquals("[2001:db8:0:0:0:0:0:7]:8443", unknown.asked)
    }

    /**
     * A plain request in a proxy's absolute form is its own kind, never an HTTP proxy's: nothing confirms the server is
     * one (fix round of W8 part 2a). With the switch off it keeps its server and leaves out only what it asked for.
     */
    @Test
    fun aPlainRequestIsNotCalledAProxy() {
        val asked = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD, asked = "example.org", askedPort = 80), hetzner, 8080)
        assertEquals(ProxyFacts.Kind.REQUEST to true, asked.kind to asked.declared)
        assertEquals("example.org:80" to false, asked.asked to asked.askedLeftOut)
        val off = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080)
        assertEquals(true to "203.0.113.5:8080", off.kept to off.at)
        assertEquals(true, off.askedLeftOut)
        // A CONNECT's reply confirmed it: an HTTP proxy, whose destination asked for is never "left out" this way.
        assertEquals(false, ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT), hetzner, 3128).askedLeftOut)
    }

    /** What the engine left out for the switch is read from its flag, never from an address of zeros (fix round). */
    @Test
    fun aProxyWhoseDestinationIsNotKeptShowsItsKindAlone() {
        val zeros = InetAddress.getByName("0.0.0.0")
        val facts = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS4, password = true, leftOut = true), zeros, 0)
        assertEquals(false to "", facts.kept to facts.at)
        assertEquals(ProxyFacts.Kind.SOCKS4 to true, facts.kind to facts.password)
        // Left out at a real address, and kept at one of zeros: the flag decides.
        assertEquals(false, ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, leftOut = true), hetzner, 443).kept)
        assertEquals(true, ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS4), zeros, 0).kept)
    }

    /**
     * The strings of apps' own proxies, and of the switch they follow with the rows that name it, keep ADR 0025's words
     * (decision 4: no word that judges or implies intent) and the brief's: never "operator", never "proxy-like", no
     * intent ("look like", "disguise", "pretend", "fake", "hide"; screens review M2 of W8 part 2a), and how the network
     * part knows is always said; and the rows quote the switch's label word for word.
     */
    @Test
    fun theProxyStringsUseNoWordThatJudges() {
        val strings = listOf("strings_untranslated.xml", "strings.xml").map { File("src/main/res/values/$it") }.filter { it.isFile }
            .joinToString("") { it.readText() }
        val names = "proxy_[a-z_]+|(?:now|history)_proxy_[a-z_]+|cannot_see_proxy|now_named_proxy|log_switch[a-z_]*|(?:now|history)_[a-z_]+_off"
        val proxy = Regex("""<string name="($names)">([^<]*)</string>""")
            .findAll(strings).associate { it.groupValues[1] to it.groupValues[2].lowercase() }
        assertTrue(proxy.keys.toString(), proxy.size >= 38)
        val judging = listOf(
            "suspicious", "unusual", "abnormal", "excessive", "leak", "spying", "secretly", "malicious", "threat", "risk",
            "normal", "expected", "safe", "operator", "proxy-like", "hidden", "dangerous", "illegal",
            "look like", "looks like", "disguise", "pretend", "fake", "hide",
        )
        for ((name, text) in proxy) {
            for (word in judging) assertTrue("$name: $word", !Regex("\\b${Regex.escape(word)}").containsMatchIn(text))
        }
        assertTrue(proxy.getValue("proxy_asked").contains("read from the connection"))
        assertTrue(proxy.getValue("proxy_declared").contains("read from the connection"))
        assertTrue(proxy.getValue("proxy_request_asked").contains("read from the connection"))
        assertEquals("read from the connection.", proxy.getValue("proxy_how_read"))
        assertTrue(proxy.getValue("proxy_inferred").contains("inferred from where and how it connects"))
        assertEquals("inferred from where and how it connects.", proxy.getValue("proxy_how_inferred"))
        assertTrue(proxy.getValue("proxy_network").contains("who runs it is not known"))
        assertEquals(
            "its connection sent the name %1\$s. no dns answer datapavan passed gave that name this address.",
            proxy.getValue("proxy_cover"),
        )
        // "Own" goes from the proxy rows: Android's setting is no app's own (screens review M3).
        for (name in proxy.keys.filter { "proxy_" in it && it.endsWith("_hidden") }) {
            assertTrue(name, !Regex("\\bown\\b").containsMatchIn(proxy.getValue(name)))
        }
        // Every row that names the switch names it as it reads.
        val label = proxy.getValue("log_switch")
        val naming = proxy.filterValues { "\\\"" in it }
        assertTrue(naming.keys.toString(), naming.size >= 13)
        for ((name, text) in naming) assertTrue(name, text.contains("\\\"$label\\\""))
    }

    /** A release's dump writes the proxies' six counters as "-", in their places; a debuggable build's, all (S-m5). */
    @Test
    fun aReleaseDumpLeavesTheProxiesCountersOut() {
        val counters = LongArray(67) { it.toLong() }
        val release = ProxyFacts.dumpedCounters(counters, debuggable = false)
        assertEquals(67, release.size)
        assertEquals(List(6) { "-" }, release.subList(61, 67))
        assertEquals("60", release[60])
        assertEquals(counters.map { it.toString() }, ProxyFacts.dumpedCounters(counters, debuggable = true))
    }
}
