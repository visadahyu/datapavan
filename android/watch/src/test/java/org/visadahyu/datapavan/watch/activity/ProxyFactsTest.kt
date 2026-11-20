package org.visadahyu.datapavan.watch.activity

import java.io.File
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.watch.log.LogRecord

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

    @Test
    fun aProxyWhoseDestinationIsNotKeptShowsItsKindAlone() {
        val facts = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS4, password = true), InetAddress.getByName("0.0.0.0"), 0)
        assertEquals(false to "", facts.kept to facts.at)
        assertEquals(ProxyFacts.Kind.SOCKS4 to true, facts.kind to facts.password)
    }

    /**
     * The strings of apps' own proxies keep ADR 0025's words (decision 4: no word that judges or implies intent) and
     * the brief's: never "operator", never "proxy-like", and how Watch knows is always said.
     */
    @Test
    fun theProxyStringsUseNoWordThatJudges() {
        val strings = File("src/main/res/values/strings_untranslated.xml").readText() + File("src/main/res/values/strings.xml").readText()
        val proxy = Regex("""<string name="(proxy_[a-z_]+|now_proxy_hidden|history_proxy_hidden|cannot_see_proxy|now_named_proxy)">([^<]*)</string>""")
            .findAll(strings).associate { it.groupValues[1] to it.groupValues[2].lowercase() }
        assertTrue(proxy.keys.toString(), proxy.size >= 18)
        val judging = listOf(
            "suspicious", "unusual", "abnormal", "excessive", "leak", "spying", "secretly", "malicious", "threat", "risk",
            "normal", "expected", "safe", "operator", "proxy-like", "hidden", "dangerous", "illegal",
        )
        for ((name, text) in proxy) {
            for (word in judging) assertTrue("$name: $word", !Regex("\\b${Regex.escape(word)}").containsMatchIn(text))
        }
        assertTrue(proxy.getValue("proxy_asked").contains("read from the connection"))
        assertTrue(proxy.getValue("proxy_inferred").contains("inferred from where and how it connects"))
        assertTrue(proxy.getValue("proxy_network").contains("who runs it is not known"))
    }
}
