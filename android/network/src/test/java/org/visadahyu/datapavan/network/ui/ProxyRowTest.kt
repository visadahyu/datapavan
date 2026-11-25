package org.visadahyu.datapavan.network.ui

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.History
import org.visadahyu.datapavan.network.activity.ProxyFacts
import org.visadahyu.datapavan.network.log.LogRecord

/** What a row of "Now" and the history says of a proxy (fix round of W8 part 2a, screens review M3, m3 and M4). */
class ProxyRowTest {
    private val hetzner = InetAddress.getByName("203.0.113.5")
    private val zeros = InetAddress.getByName("0.0.0.0")

    private fun texts(row: ProxyRow) = listOfNotNull(row.header?.text) + row.lines.map { it.text }

    /**
     * With the switch off, an inferred proxy still says how the network part knows, and the facts that name nothing:
     * never stated as a fact, never "its own". The header stands for the destination, and the row links to the switch.
     */
    @Test
    fun aProxyLeftOutSaysHowItIsKnownAndLinksToTheSwitch() {
        val telegram = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true), zeros, 0)
        val now = proxyRow(telegram, past = false)
        assertEquals(ProxyLine(R.string.now_proxy_past, ProxyFacts.Kind.MTPROTO), now.header)
        assertEquals(
            listOf(ProxyLine(R.string.proxy_how_inferred), ProxyLine(R.string.proxy_not_maker, args = listOf(isolate("Telegram")))),
            now.lines,
        )
        assertTrue(now.toSwitch)
        assertEquals(R.string.history_proxy_hidden, proxyRow(telegram, past = true).header?.text)
        // A SOCKS5 proxy read from the connection says so; a password crossed unencrypted is said, never its value.
        val socks = proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, password = true, leftOut = true), zeros, 0), past = false)
        assertEquals(listOf(R.string.now_proxy_past, R.string.proxy_how_read, R.string.proxy_password), texts(socks))
    }

    /**
     * The proxy record's unit B (audit-B 4): a proxy left out for the switch still says "On your local network" where the
     * engine's bit says so, in "Now" past the window, read from the snapshot's destination at its address of zeros, and in
     * the history (HistoryTest); as in a kept row, a local address says nothing of a maker.
     */
    @Test
    fun aLocalProxyLeftOutStillSaysItIsLocal() {
        val place = { proxy: LogRecord.Proxy ->
            org.visadahyu.datapavan.network.activity.Snapshot.Destination(
                protocol = 6, namedBy = 0, ech = 0, dns = 0, cameIn = false, address = zeros, port = 0, asn = 0,
                network = 0, name = "", dnsName = "", resolver = "", organisation = "", bytes = List(6) { 1L }, proxy = proxy,
            )
        }
        val socks = LogRecord.Proxy(LogRecord.PROXY_SOCKS5, leftOut = true, local = true)
        val past = proxyRow(checkNotNull(placeProxyFacts(place(socks), null, null)), past = false)
        assertEquals(listOf(R.string.now_proxy_past, R.string.proxy_how_read, R.string.proxy_local), texts(past))
        assertTrue(past.toSwitch)
        assertEquals(
            listOf(R.string.history_proxy_hidden, R.string.proxy_how_read, R.string.proxy_local),
            texts(proxyRow(ProxyFacts.of(socks, zeros, 0), past = true)),
        )
        val telegram = LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true, local = true)
        assertEquals(
            listOf(R.string.now_proxy_past, R.string.proxy_how_inferred, R.string.proxy_local),
            texts(proxyRow(checkNotNull(placeProxyFacts(place(telegram), null, null)), past = false)),
        )
        // Not local, or a record that never said, at its address of zeros: no such line.
        for (proxy in listOf(socks.copy(local = false), socks.copy(local = null))) {
            assertEquals(listOf(R.string.now_proxy_past, R.string.proxy_how_read), texts(proxyRow(ProxyFacts.of(proxy, zeros, 0), past = false)))
        }
    }

    /** Android's proxy setting, left out, has its own words, which never call it the app's: no second line contradicts them. */
    @Test
    fun androidsSettingLeftOutHasItsOwnWords() {
        val setting = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT, setting = true, leftOut = true), zeros, 0)
        assertEquals(listOf(R.string.now_proxy_setting_past, R.string.proxy_how_read), texts(proxyRow(setting, past = false)))
        assertEquals(R.string.history_proxy_setting_hidden, proxyRow(setting, past = true).header?.text)
        // Kept, the setting's line follows where the proxy is.
        val kept = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT, setting = true, asked = "example.org", askedPort = 443), hetzner, 3128)
        assertEquals(listOf(R.string.proxy_asked, R.string.proxy_network_unknown, R.string.proxy_setting), texts(proxyRow(kept, past = false)))
    }

    /**
     * The proxy record's unit A: a first hop "Now" shows only, while the switch is off, says after its facts that where the
     * app asked a declared proxy to go is not shown or logged, then that its address is shown only so long, and links to
     * the switch; an inferred one has no line of what was asked. A kept row has neither, and the history never does.
     */
    @Test
    fun aFirstHopShownOnlySaysWhyAndLinksToTheSwitch() {
        val socks = LogRecord.Proxy(
            LogRecord.PROXY_SOCKS5, password = true, proxyName = "proxy.example.net", organisation = "Hetzner Online GmbH",
        )
        val shown = proxyRow(ProxyFacts.of(socks, hetzner, 1080, shownOnly = true), past = false)
        assertEquals(
            listOf(
                ProxyLine(R.string.proxy_declared, ProxyFacts.Kind.SOCKS5, listOf(isolateLtr("proxy.example.net:1080"))),
                ProxyLine(R.string.proxy_network, args = listOf(isolate("Hetzner Online GmbH"))),
                ProxyLine(R.string.proxy_password),
                ProxyLine(R.string.now_proxy_asked_off),
                ProxyLine(R.string.now_proxy_live_only),
            ),
            shown.lines,
        )
        assertEquals(null to true, shown.header to shown.toSwitch)
        val mtproto = LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, organisation = "Example Net", cover = "www.google.com")
        val inferred = proxyRow(ProxyFacts.of(mtproto, hetzner, 443, shownOnly = true), past = false)
        assertEquals(
            listOf(R.string.proxy_inferred, R.string.proxy_network_not_maker, R.string.proxy_cover, R.string.now_proxy_live_only),
            texts(inferred),
        )
        assertTrue(inferred.toSwitch)
        val notes = setOf(R.string.now_proxy_asked_off, R.string.now_proxy_live_only)
        for (row in listOf(
            proxyRow(ProxyFacts.of(socks, hetzner, 1080), past = false),
            proxyRow(ProxyFacts.of(socks, hetzner, 1080, shownOnly = true), past = true),
            proxyRow(ProxyFacts.of(mtproto, hetzner, 443, shownOnly = true), past = true),
        )) {
            assertEquals(false, row.toSwitch)
            assertTrue(texts(row).toString(), texts(row).none { it in notes })
        }
    }

    /**
     * Review A, rest, minor 3: the snapshot's mark reaches the row "Now" draws, from the destination as the snapshot
     * reads it: shown only, the row ends with why and links to the switch; not, it does not.
     */
    @Test
    fun theSnapshotsMarkReachesTheRow() {
        val proxy = LogRecord.Proxy(LogRecord.PROXY_SOCKS5, proxyName = "proxy.example.net", organisation = "Hetzner Online GmbH")
        val place = { shownOnly: Boolean ->
            org.visadahyu.datapavan.network.activity.Snapshot.Destination(
                protocol = 6, namedBy = 0, ech = 0, dns = 0, cameIn = false, address = hetzner, port = 1080, asn = 0,
                network = 0, name = "proxy.example.net", dnsName = "", resolver = "", organisation = "",
                bytes = List(6) { 1L }, proxy = proxy, shownOnly = shownOnly,
            )
        }
        val shown = checkNotNull(placeProxyFacts(place(true), null, null))
        assertEquals(true, shown.shownOnly)
        val row = proxyRow(shown, past = false)
        assertEquals(R.string.now_proxy_live_only, row.lines.last().text)
        assertTrue(row.toSwitch)
        val kept = checkNotNull(placeProxyFacts(place(false), null, null))
        assertEquals(false to false, kept.shownOnly to proxyRow(kept, past = false).toSwitch)
        assertEquals(true, proxyFacts(proxy, hetzner, 1080, 0, null, null, shownOnly = true).shownOnly)
        assertEquals(null, placeProxyFacts(place(false).copy(proxy = null), null, null))
    }

    /** With the switch on, a declared proxy and an inferred one say how the network part knows in their first line. */
    @Test
    fun aProxyKeptSaysWhereAndHowItIsKnown() {
        val socks = ProxyFacts.of(
            LogRecord.Proxy(LogRecord.PROXY_SOCKS5, asked = "example.org", askedPort = 443, organisation = "Hetzner Online GmbH"), hetzner, 1080,
        )
        val row = proxyRow(socks, past = false)
        assertEquals(null to false, row.header to row.toSwitch)
        assertEquals(
            listOf(
                ProxyLine(R.string.proxy_asked, ProxyFacts.Kind.SOCKS5, listOf(isolateLtr("203.0.113.5:1080"), isolateLtr("example.org:443"))),
                ProxyLine(R.string.proxy_network, args = listOf(isolate("Hetzner Online GmbH"))),
            ),
            row.lines,
        )
        // A declared proxy with no destination asked for read is never called inferred.
        val bare = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS4), hetzner, 1080)
        assertEquals(listOf(R.string.proxy_declared, R.string.proxy_network_unknown), texts(proxyRow(bare, past = false)))
        val mtproto = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, cover = "www.google.com", organisation = "Example Net"), hetzner, 443)
        assertEquals(
            listOf(R.string.proxy_inferred, R.string.proxy_network, R.string.proxy_cover),
            texts(proxyRow(mtproto, past = false)),
        )
    }

    /**
     * Screens review m3: where the network part cannot name the network, the maker's network the address is not in is
     * still said (ADR 0052, decision 6: "always"), and where it can, the one line says both.
     */
    @Test
    fun theMakersNetworkIsSaidWhenTheNetworkIsUnknown() {
        val unknown = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_WHATSAPP, outsideMaker = true), hetzner, 5222)
        assertEquals(ProxyFacts.Where.UNKNOWN, unknown.where)
        assertEquals(
            listOf(
                ProxyLine(R.string.proxy_inferred, ProxyFacts.Kind.WHATSAPP, listOf(isolateLtr("203.0.113.5:5222"))),
                ProxyLine(R.string.proxy_network_unknown),
                ProxyLine(R.string.proxy_not_maker, args = listOf(isolate("WhatsApp"))),
            ),
            proxyRow(unknown, past = false).lines,
        )
        val named = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_WHATSAPP, outsideMaker = true, organisation = "Example Net"), hetzner, 5222)
        assertEquals(listOf(R.string.proxy_inferred, R.string.proxy_network_not_maker), texts(proxyRow(named, past = false)))
        // On the local network, no company's: nothing of a maker.
        val local = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true), InetAddress.getByName("192.168.1.2"), 443)
        assertEquals(listOf(R.string.proxy_inferred, R.string.proxy_local), texts(proxyRow(local, past = false)))
    }

    /**
     * A plain request in a proxy's form is never called a proxy: its line says what it asked for and how the network
     * part knows, and with the switch off that what it asked for is not shown, linking to the switch.
     */
    @Test
    fun aPlainRequestSaysWhatItAskedForNeverThatItsServerIsAProxy() {
        val on = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD, password = true, asked = "example.org", askedPort = 80), hetzner, 8080)
        val row = proxyRow(on, past = false)
        assertEquals(
            listOf(ProxyLine(R.string.proxy_request_asked, args = listOf(isolateLtr("example.org:80"))), ProxyLine(R.string.proxy_request_password)),
            row.lines,
        )
        assertEquals(null to false, row.header to row.toSwitch)
        val off = proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080), past = false)
        assertEquals(listOf(R.string.now_proxy_request_hidden, R.string.proxy_how_read), texts(off))
        assertTrue(off.toSwitch)
        assertEquals(R.string.history_proxy_request_hidden, proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080), past = true).lines[0].text)
        // No line of either sets a proxy's kind in or says where a proxy is.
        val proxyWords = setOf(R.string.proxy_asked, R.string.proxy_declared, R.string.proxy_inferred, R.string.proxy_network, R.string.proxy_password)
        assertTrue((row.lines + off.lines).none { it.kind != null || it.text in proxyWords })
    }

    /**
     * Fix brief point 2: the history never says a flow went through the user's tool unless its recorded route says so;
     * a direct one, the tool's own and one of a record with no route have words of their own.
     */
    @Test
    fun onlyARouteThroughTheToolSaysSo() {
        assertEquals(R.string.history_through_tool_off, leftOutWords(History.LeftOut.THROUGH_TOOL))
        assertEquals(R.string.history_direct_off, leftOutWords(History.LeftOut.DIRECT))
        assertEquals(R.string.history_through_tunnel_off, leftOutWords(History.LeftOut.TUNNEL))
        for (why in History.LeftOut.entries - History.LeftOut.THROUGH_TOOL) {
            assertTrue(why.name, leftOutWords(why) != R.string.history_through_tool_off)
        }
    }
}
