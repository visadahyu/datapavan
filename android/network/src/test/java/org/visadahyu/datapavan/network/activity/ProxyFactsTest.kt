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
        // The snapshot's mark of a first hop "Now" shows only is carried as given, and never set otherwise.
        assertEquals(false to true, facts.shownOnly to ProxyFacts.of(proxy, hetzner, 1080, shownOnly = true).shownOnly)
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
     * The proxy record's unit B, B2: from log version 7 and in every snapshot the engine says whether the proxy is local,
     * from the network beneath's on-link prefixes, and its word wins over the address, a stripped record's of zeros
     * included (finding 4 of the brief's audit); only a record that never said is read from its address.
     */
    @Test
    fun theEnginesLocalBitWinsOverTheAddress() {
        val proxy = LogRecord.Proxy(LogRecord.PROXY_SOCKS5)
        val home = InetAddress.getByName("192.168.1.2")
        assertEquals(ProxyFacts.Where.LOCAL, ProxyFacts.of(proxy, home, 1080).where)
        // On mobile data a private address outside the link's own prefix is not local, whatever its range.
        assertEquals(ProxyFacts.Where.UNKNOWN, ProxyFacts.of(proxy.copy(local = false), home, 1080).where)
        val named = proxy.copy(local = false, organisation = "Example Net")
        assertEquals(ProxyFacts.Where.NETWORK, ProxyFacts.of(named, home, 1080).where)
        // A global IPv6 address on the link's own prefix is local, though no range says so.
        assertEquals(ProxyFacts.Where.LOCAL, ProxyFacts.of(proxy.copy(local = true), InetAddress.getByName("2001:db8:1::5"), 1080).where)
        // Left out, at an address of zeros: the bit alone says it.
        val zeros = InetAddress.getByName("0.0.0.0")
        assertEquals(ProxyFacts.Where.LOCAL, ProxyFacts.of(proxy.copy(leftOut = true, local = true), zeros, 0).where)
        assertEquals(ProxyFacts.Where.UNKNOWN, ProxyFacts.of(proxy.copy(leftOut = true), zeros, 0).where)
    }

    /**
     * The fallback for a record before version 7 is the engine's rule with no prefixes told (rule 5): link-local, the
     * private ranges and unique local addresses; never CGNAT, never the deprecated fec0::/10, never zeros; a mapped IPv4
     * address read as its IPv4 address.
     */
    @Test
    fun theFallbackIsTheEnginesRuleWithNoPrefixes() {
        val local = listOf(
            "10.0.0.5", "172.16.5.5", "172.31.255.255", "192.168.1.20", "169.254.10.1", "fe80::1", "febf::1", "fc00::1",
            "fd00::5", "::ffff:192.168.1.20",
        )
        val notLocal = listOf(
            "100.64.1.1", "172.15.0.1", "172.32.0.1", "192.169.0.1", "fec0::1", "feff::1", "0.0.0.0", "::", "8.8.8.8",
            "2001:db8::7", "203.0.113.5", "::ffff:100.64.1.1",
        )
        for (address in local) assertTrue(address, ProxyFacts.isLocal(InetAddress.getByName(address)))
        for (address in notLocal) assertTrue(address, !ProxyFacts.isLocal(InetAddress.getByName(address)))
        // An IPv4-mapped address kept as IPv6 reads as its IPv4 address too.
        val mapped = ByteArray(16).also {
            it[10] = -1
            it[11] = -1
            it[12] = 192.toByte()
            it[13] = 168.toByte()
            it[15] = 2
        }
        assertTrue(ProxyFacts.isLocal(java.net.Inet6Address.getByAddress(null, mapped, -1)))
    }

    /**
     * The same, against the engine's own vectors (core/net/testdata/local-addresses.tsv): its rows with no prefixes and
     * the transport not known, which are rule 5's, give the engine's answer here.
     */
    @Test
    fun theFallbackGivesTheEnginesAnswerOnItsVectors() {
        val vectors = File("../../core/net/testdata/local-addresses.tsv")
        assertTrue("the engine's vectors: $vectors", vectors.isFile)
        val rows = vectors.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.split('\t') }
            .filter { it.size >= 4 && it[1] == "-" && it[2] == "unknown" }
        assertTrue(rows.toString(), rows.size >= 5)
        for (row in rows) assertEquals(row[0], row[3] == "local", ProxyFacts.isLocal(InetAddress.getByName(row[0])))
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
        val names = "proxy_[a-z_]+|(?:now|history)_proxy_[a-z_]+|cannot_see_proxy|now_named_proxy|log_switch[a-z_]*|(?:now|history)_(?!network_off)[a-z_]+_off"
        val proxy = Regex("""<string name="($names)">([^<]*)</string>""")
            .findAll(strings).associate { it.groupValues[1] to it.groupValues[2].lowercase() }
        assertTrue(proxy.keys.toString(), proxy.size >= 40)
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
        // Unit B, B3 (audit-B 15): a record the engine could not tell about is named by the kind's own words, never as a
        // proxy the messenger runs.
        assertTrue(proxy.getValue("history_proxy_unsure").contains("could not tell whether this connection went through a %1\$s."))
        // "Own" goes from the proxy rows: Android's setting is no app's own (screens review M3).
        for (name in proxy.keys.filter { "proxy_" in it && it.endsWith("_hidden") }) {
            assertTrue(name, !Regex("\\bown\\b").containsMatchIn(proxy.getValue(name)))
        }
        // Every row that names the switch names it as it reads.
        val label = proxy.getValue("log_switch")
        val naming = proxy.filterValues { "\\\"" in it }
        assertTrue(naming.keys.toString(), naming.size >= 20)
        for ((name, text) in naming) assertTrue(name, text.contains("\\\"$label\\\""))
        // Unit C: the strings of the user's choice for one app are in scope, and those that name the switch quote it; the
        // confirmation's title is the app's switch word for word, as a question.
        assertTrue(proxy.keys.toString(), proxy.size >= 60)
        for (name in listOf(
            "proxy_app_log_never", "proxy_app_log_switch_on", "now_proxy_live_only", "now_proxy_live_only_shared", "now_proxy_past",
            "now_proxy_past_shared", "now_proxy_live_only_switch", "now_proxy_past_switch",
        )) {
            assertTrue(name, name in naming)
        }
        // Words that claim no more than the code does (review C-rest 3 and 4, review C-engine major 1): the chain's
        // tool ends a choice too, whatever its key; the switch's note names both places the choice is made and what it
        // leaves out; the confirmation says what the engine may miss.
        assertTrue(!proxy.getValue("proxy_app_ended_tool").contains("signing key"))
        assertTrue(proxy.getValue("log_switch_note_proxies").contains("on its row or its page"))
        assertTrue(proxy.getValue("log_switch_note_proxies").contains("that leaves out a proxy that datapavan sees is in android\\'s settings or on your local network."))
        assertTrue(!proxy.getValue("proxy_app_log_never").contains("never"))
        assertTrue(proxy.getValue("proxy_app_log_never").contains("a proxy that a pac file names"))
        assertEquals(proxy.getValue("proxy_app_log") + "?", proxy.getValue("proxy_app_log_title"))
        assertTrue(proxy.getValue("proxy_app_log_body").contains("if you set this app\\'s proxy yourself, leave this off."))
    }

    /**
     * A release's dump writes the proxies' eight counters as "-", in their places, unit U's two included; a debuggable
     * build's, all (S-m5, review U-engine M2).
     */
    @Test
    fun aReleaseDumpLeavesTheProxiesCountersOut() {
        val counters = LongArray(73) { it.toLong() }
        val release = ProxyFacts.dumpedCounters(counters, debuggable = false)
        assertEquals(73, release.size)
        assertEquals(List(6) { "-" }, release.subList(61, 67))
        assertEquals(listOf("67", "68", "69", "70"), release.subList(67, 71))
        assertEquals(listOf("-", "-"), release.subList(71, 73))
        assertEquals("60", release[60])
        assertEquals(counters.map { it.toString() }, ProxyFacts.dumpedCounters(counters, debuggable = true))
    }
}
