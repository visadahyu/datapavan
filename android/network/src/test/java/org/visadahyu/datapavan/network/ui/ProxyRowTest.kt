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

    /** A row the user's choice for its app could cover (unit C), the app not chosen and the switch off. */
    private val offered = RowChoice(offered = true)

    /**
     * With the switch off, an inferred proxy still says how the network part knows, and the facts that name nothing:
     * never stated as a fact, never "its own". The header stands for the destination, and the row links to the switch.
     */
    @Test
    fun aProxyLeftOutSaysHowItIsKnownAndLinksToTheSwitch() {
        val telegram = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true), zeros, 0)
        val now = proxyRow(telegram, past = false, choice = offered)
        assertEquals(ProxyLine(R.string.now_proxy_past, ProxyFacts.Kind.MTPROTO), now.header)
        assertEquals(
            listOf(ProxyLine(R.string.proxy_how_inferred), ProxyLine(R.string.proxy_not_maker, args = listOf(isolate("Telegram")))),
            now.lines,
        )
        assertTrue(now.toSwitch)
        assertEquals(R.string.history_proxy_hidden, proxyRow(telegram, past = true).header?.text)
        // A SOCKS5 proxy read from the connection says so; a password crossed unencrypted is said, never its value.
        val socks = proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, password = true, leftOut = true), zeros, 0), past = false, choice = offered)
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
        assertEquals(listOf(R.string.now_proxy_past_shared, R.string.proxy_how_read, R.string.proxy_local), texts(past))
        assertTrue(past.toSwitch)
        assertEquals(
            listOf(R.string.history_proxy_hidden, R.string.proxy_how_read, R.string.proxy_local),
            texts(proxyRow(ProxyFacts.of(socks, zeros, 0), past = true)),
        )
        val telegram = LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true, local = true)
        assertEquals(
            listOf(R.string.now_proxy_past_shared, R.string.proxy_how_inferred, R.string.proxy_local),
            texts(proxyRow(checkNotNull(placeProxyFacts(place(telegram), null, null)), past = false)),
        )
        // Not local, or a record that never said, at its address of zeros: no such line.
        for (proxy in listOf(socks.copy(local = false), socks.copy(local = null))) {
            assertEquals(
                listOf(R.string.now_proxy_past, R.string.proxy_how_read),
                texts(proxyRow(ProxyFacts.of(proxy, zeros, 0), past = false, choice = offered)),
            )
        }
    }

    /**
     * The proxy record's unit B, B3: a record the engine could not tell was a messenger's proxy says so in place of its
     * proxy line, in the kind's own words, and nothing of how it was inferred; the facts that name nothing stay. "Now"
     * never has such a record: the snapshot refuses the mark, and the live words stand.
     */
    @Test
    fun anUnsureRecordSaysSoInPlaceOfItsProxyLine() {
        val unsure = LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true, unsure = true)
        val row = proxyRow(ProxyFacts.of(unsure, zeros, 0), past = true)
        assertEquals(ProxyLine(R.string.history_proxy_unsure, ProxyFacts.Kind.MTPROTO), row.header)
        assertEquals(listOf(ProxyLine(R.string.proxy_not_maker, args = listOf(isolate("Telegram")))), row.lines)
        assertTrue(row.toSwitch)
        val local = proxyRow(ProxyFacts.of(unsure.copy(kind = LogRecord.PROXY_WHATSAPP, local = true), zeros, 0), past = true)
        assertEquals(listOf(R.string.history_proxy_unsure, R.string.proxy_local), texts(local))
        assertEquals(ProxyFacts.Kind.WHATSAPP, local.header?.kind)
        // Without the mark, the record went through one, and says how that is known.
        assertEquals(
            listOf(R.string.history_proxy_hidden, R.string.proxy_how_inferred, R.string.proxy_not_maker),
            texts(proxyRow(ProxyFacts.of(unsure.copy(unsure = false), zeros, 0), past = true)),
        )
        assertEquals(R.string.now_proxy_past, proxyRow(ProxyFacts.of(unsure, zeros, 0), past = false, choice = offered).header?.text)
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
        val shown = proxyRow(ProxyFacts.of(socks, hetzner, 1080, shownOnly = true), past = false, choice = offered)
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
        val inferred = proxyRow(ProxyFacts.of(mtproto, hetzner, 443, shownOnly = true), past = false, choice = offered)
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
        val row = proxyRow(shown, past = false, choice = offered)
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
        assertEquals(listOf(R.string.proxy_declared, R.string.proxy_network_unknown), texts(proxyRow(bare, past = true)))
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
     * The proxy record's unit B, R7 (audit-B 3 and 26): a plain request to Android's setting, the switch off, is that
     * proxy's first hop. From the snapshot's destination, "Now" shows it within its window with the setting's line and
     * the window's, and links to the switch; left out, past the window and in the history, it has the setting's headers
     * with the request's kind, which the screens name "HTTP proxy". A plain request to any other server, were it marked,
     * is still never called a proxy.
     */
    @Test
    fun aPlainRequestToAndroidsSettingIsItsFirstHop() {
        val lab = InetAddress.getByName("10.0.2.2")
        val place = { proxy: LogRecord.Proxy, address: InetAddress, shownOnly: Boolean ->
            org.visadahyu.datapavan.network.activity.Snapshot.Destination(
                protocol = 6, namedBy = 0, ech = 0, dns = 0, cameIn = false, address = address, port = 3128, asn = 0,
                network = 0, name = "", dnsName = "", resolver = "", organisation = "", bytes = List(6) { 1L }, proxy = proxy,
                shownOnly = shownOnly,
            )
        }
        val request = LogRecord.Proxy(LogRecord.PROXY_FORWARD, setting = true)
        val live = proxyRow(checkNotNull(placeProxyFacts(place(request, lab, true), null, null)), past = false)
        assertEquals(
            listOf(R.string.now_proxy_request_hidden, R.string.proxy_how_read, R.string.proxy_setting, R.string.now_proxy_live_only_shared),
            texts(live),
        )
        assertEquals(null to true, live.header to live.toSwitch)
        val zeros6 = InetAddress.getByName("::")
        val past = proxyRow(checkNotNull(placeProxyFacts(place(request.copy(leftOut = true), zeros6, false), null, null)), past = false)
        assertEquals(ProxyLine(R.string.now_proxy_setting_past, ProxyFacts.Kind.REQUEST), past.header)
        assertEquals(R.string.proxy_kind_http, proxyKind(ProxyFacts.Kind.REQUEST))
        assertEquals(listOf(R.string.proxy_how_read), past.lines.map { it.text })
        assertTrue(past.toSwitch)
        val history = proxyRow(ProxyFacts.of(request.copy(leftOut = true), zeros, 0), past = true)
        assertEquals(ProxyLine(R.string.history_proxy_setting_hidden, ProxyFacts.Kind.REQUEST), history.header)
        // A record is never shown only, nor is a row the engine did not mark: neither says the window's words.
        assertEquals(
            listOf(R.string.history_proxy_request_hidden, R.string.proxy_how_read, R.string.proxy_setting),
            texts(proxyRow(checkNotNull(placeProxyFacts(place(request, lab, true), null, null)), past = true)),
        )
        assertEquals(
            listOf(R.string.now_proxy_request_hidden, R.string.proxy_how_read, R.string.proxy_setting),
            texts(proxyRow(checkNotNull(placeProxyFacts(place(request, lab, false), null, null)), past = false)),
        )
        val other = proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080, shownOnly = true), past = false)
        assertEquals(listOf(R.string.now_proxy_request_hidden, R.string.proxy_how_read), texts(other))
        assertTrue(other.lines.none { it.kind != null })
    }

    /**
     * The proxy record's unit B, B6: a circumvention tool's own flow says so on its proxy row, after the facts and before
     * a first hop's window words, kept or left out, in "Now" and the history. Never on a plain request to a server that
     * is not Android's setting, which nothing says is a proxy, nor on a record the engine could not tell about.
     */
    @Test
    fun aToolsOwnFlowSaysSoOnItsProxyRow() {
        val socks = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, organisation = "Hetzner Online GmbH"), hetzner, 1080)
        val kept = proxyRow(socks, past = true, tool = "Orbot")
        assertEquals(listOf(R.string.proxy_declared, R.string.proxy_network, R.string.proxy_tool), texts(kept))
        assertEquals(ProxyLine(R.string.proxy_tool, args = listOf(isolate("Orbot"))), kept.lines.last())
        assertEquals(
            listOf(R.string.proxy_declared, R.string.proxy_network, R.string.proxy_tool, R.string.now_proxy_asked_off, R.string.now_proxy_live_only_shared),
            texts(proxyRow(socks.copy(shownOnly = true), past = false, tool = "Orbot")),
        )
        val leftOut = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT, leftOut = true), zeros, 0)
        assertEquals(
            listOf(R.string.history_proxy_hidden, R.string.proxy_how_read, R.string.proxy_tool),
            texts(proxyRow(leftOut, past = true, tool = "Orbot")),
        )
        val setting = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD, setting = true), hetzner, 3128)
        assertEquals(R.string.proxy_tool, texts(proxyRow(setting, past = false, tool = "Orbot")).last())
        val request = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080)
        val unsure = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, leftOut = true, unsure = true), zeros, 0)
        for (row in listOf(proxyRow(request, past = false, tool = "Orbot"), proxyRow(unsure, past = true, tool = "Orbot"), proxyRow(socks, past = false))) {
            assertTrue(texts(row).toString(), R.string.proxy_tool !in texts(row))
        }
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

    /**
     * The proxy record's unit C (C8): a first hop "Now" shows only, on a row the user's choice for its app could cover,
     * says so in its window's line and links to the choice after the switch; a row no choice covers says its proxy can
     * carry other apps' connections, and has no such link; a chosen app's, or one with the switch on, has none either.
     */
    @Test
    fun aFirstHopShownOnlyOffersTheChoiceWhereItCouldCoverIt() {
        val socks = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, organisation = "Hetzner Online GmbH"), hetzner, 1080, shownOnly = true)
        val row = proxyRow(socks, past = false, choice = offered)
        assertEquals(listOf(R.string.now_proxy_asked_off, R.string.now_proxy_live_only), texts(row).takeLast(2))
        assertEquals(true to Choice.LOG, row.toSwitch to row.toChoice)
        val shared = proxyRow(socks, past = false)
        assertEquals(R.string.now_proxy_live_only_shared, texts(shared).last())
        assertEquals(true to null, shared.toSwitch to shared.toChoice)
        for (choice in listOf(offered.copy(chosen = true), offered.copy(switchOn = true))) {
            assertEquals(null, proxyRow(socks, past = false, choice = choice).toChoice)
        }
    }

    /**
     * Unit C: what the screens offer is the engine's rule (ProxyChoice): never on Android's setting, a local proxy, a
     * circumvention tool's row or the PAC proxy's, nor on another user's row; an SDK Runtime UID's row through its app.
     * Each of those rows says its proxy can carry other apps' connections, past the window too, and links only to the
     * switch.
     */
    @Test
    fun noRowTheChoiceNeverCoversOffersIt() {
        val choices = ProxyChoices(tools = setOf(10_124), pacHandler = 10_125, chosen = setOf(10_126))
        assertEquals(true, choices.row(10_123, setting = false, local = false).offered)
        assertEquals(true, choices.row(20_123, setting = false, local = null).offered)
        val never = listOf(
            choices.row(10_123, setting = true, local = false),
            choices.row(10_123, setting = false, local = true),
            choices.row(10_124, setting = false, local = false),
            choices.row(20_124, setting = false, local = false),
            choices.row(10_125, setting = false, local = false),
            choices.row(1_010_123, setting = false, local = false),
            choices.row(null, setting = false, local = false),
        )
        val leftOut = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, leftOut = true), zeros, 0)
        for (choice in never) {
            assertEquals(false, choice.offered)
            val past = proxyRow(leftOut, past = false, choice = choice)
            assertEquals(R.string.now_proxy_past_shared to null, past.header?.text to past.toChoice)
            assertEquals(null, proxyRow(leftOut, past = true, choice = choice).toChoice)
        }
        // Chosen: the app's sandbox too; the row knows it.
        assertEquals(true to true, choices.row(20_126, setting = false, local = false).let { it.offered to it.chosen })
    }

    /**
     * Unit C: a row left out, in "Now" past the window and in the history, links to the choice while neither the switch
     * nor the choice keeps its app; a chosen app's place left out before the choice says so (audit-C 1); Android's setting
     * keeps its own header, which no choice covers.
     */
    @Test
    fun aRowLeftOutOffersTheChoiceInNowAndTheHistory() {
        val leftOut = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true), zeros, 0)
        for (past in listOf(false, true)) {
            val row = proxyRow(leftOut, past = past, choice = offered)
            assertEquals(true to Choice.LOG, row.toSwitch to row.toChoice)
            assertEquals(null, proxyRow(leftOut, past = past, choice = offered.copy(switchOn = true)).toChoice)
            assertEquals(null, proxyRow(leftOut, past = past, choice = offered.copy(chosen = true)).toChoice)
        }
        assertEquals(R.string.history_proxy_hidden, proxyRow(leftOut, past = true, choice = offered).header?.text)
        assertEquals(R.string.now_proxy_past_chosen, proxyRow(leftOut, past = false, choice = offered.copy(chosen = true)).header?.text)
        // With the switch on, the rule it states is true as it is.
        assertEquals(R.string.now_proxy_past, proxyRow(leftOut, past = false, choice = offered.copy(chosen = true, switchOn = true)).header?.text)
        val setting = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT, setting = true, leftOut = true), zeros, 0)
        assertEquals(R.string.now_proxy_setting_past, proxyRow(setting, past = false).header?.text)
    }

    /**
     * Unit C: a row the choice alone keeps, in "Now" with the switch off, says why it is shown in full and logged, and
     * links to stop; with the switch on, or in the history, neither. A row read from the connection, kept with no
     * destination asked for, says it asked before its proxy was logged (review A-rest, note 11): never an inferred one's,
     * a SOCKS5 relay's datagrams', a first hop shown only, or the history's.
     */
    @Test
    fun aRowTheChoiceKeepsSaysWhyAndOffersToStop() {
        val asked = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, asked = "example.org", askedPort = 443), hetzner, 1080)
        val chosen = offered.copy(chosen = true)
        val row = proxyRow(asked, past = false, choice = chosen)
        assertEquals(listOf(R.string.proxy_asked, R.string.proxy_network_unknown, R.string.now_proxy_app_logged), texts(row))
        assertEquals(false to Choice.STOP, row.toSwitch to row.toChoice)
        for (other in listOf(
            proxyRow(asked, past = false, choice = chosen.copy(switchOn = true)),
            proxyRow(asked, past = true, choice = chosen),
            proxyRow(asked, past = false, choice = offered),
            proxyRow(asked, past = false, choice = RowChoice(chosen = true)),
        )) {
            assertEquals(null, other.toChoice)
            assertTrue(R.string.now_proxy_app_logged !in texts(other))
        }
        val earlier = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5), hetzner, 1080)
        assertEquals(
            listOf(R.string.proxy_declared, R.string.proxy_network_unknown, R.string.now_proxy_asked_earlier, R.string.now_proxy_app_logged),
            texts(proxyRow(earlier, past = false, choice = chosen)),
        )
        assertEquals(R.string.now_proxy_asked_earlier, texts(proxyRow(earlier, past = false, choice = offered.copy(switchOn = true))).last())
        val mtproto = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO), hetzner, 443)
        for (other in listOf(
            proxyRow(earlier, past = false, choice = offered.copy(switchOn = true, tcp = false)),
            proxyRow(earlier, past = true, choice = offered),
            proxyRow(earlier.copy(shownOnly = true), past = false, choice = offered),
            proxyRow(mtproto, past = false, choice = offered),
            proxyRow(asked, past = false, choice = offered),
        )) {
            assertTrue(texts(other).toString(), R.string.now_proxy_asked_earlier !in texts(other))
        }
    }

    /**
     * Unit C: a plain request whose destination asked for was left out links to the choice where it could cover it; one
     * kept is never said to be logged for the choice, which would call its server a proxy.
     */
    @Test
    fun aPlainRequestOffersTheChoiceButIsNeverCalledAProxy() {
        val leftOut = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080)
        assertEquals(Choice.LOG, proxyRow(leftOut, past = false, choice = offered).toChoice)
        assertEquals(Choice.LOG, proxyRow(leftOut, past = true, choice = offered).toChoice)
        assertEquals(null, proxyRow(leftOut, past = false).toChoice)
        assertEquals(null, proxyRow(leftOut, past = false, choice = offered.copy(switchOn = true)).toChoice)
        val kept = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD, asked = "example.org", askedPort = 80), hetzner, 8080)
        val row = proxyRow(kept, past = false, choice = offered.copy(chosen = true))
        assertEquals(listOf(R.string.proxy_request_asked), texts(row))
        assertEquals(null, row.toChoice)
    }

    /**
     * Unit C: an app's row in "Now" and its page say the user ended its choice here, and what stays (audit-C 8), or why it
     * ended without the user (audit-C 13), its SDK Runtime's row by its app; nothing while it is chosen.
     */
    @Test
    fun anAppSaysWhyItsChoiceEnded() {
        val packages = listOf("com.example.messenger")
        val ended = mapOf("com.example.messenger" to org.visadahyu.datapavan.network.proxy.LoggedApps.Ended.SHARED)
        assertEquals(emptyList<Int>(), appChoiceLines(10_123, packages, ProxyChoices()))
        assertEquals(listOf(R.string.proxy_app_stopped), appChoiceLines(20_123, packages, ProxyChoices(stopped = setOf(10_123))))
        assertEquals(listOf(R.string.proxy_app_ended_shared), appChoiceLines(10_123, packages, ProxyChoices(ended = ended)))
        for ((why, line) in listOf(
            org.visadahyu.datapavan.network.proxy.LoggedApps.Ended.INSTALLED_AGAIN to R.string.proxy_app_ended_installed,
            org.visadahyu.datapavan.network.proxy.LoggedApps.Ended.TOOL to R.string.proxy_app_ended_tool,
        )) {
            assertEquals(listOf(line), appChoiceLines(10_123, packages, ProxyChoices(ended = mapOf("com.example.messenger" to why))))
        }
        assertEquals(emptyList<Int>(), appChoiceLines(10_123, packages, ProxyChoices(ended = ended, stopped = setOf(10_123), chosen = setOf(10_123))))
        assertEquals(emptyList<Int>(), appChoiceLines(null, packages, ProxyChoices(ended = ended)))
    }
}
