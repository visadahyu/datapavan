package org.visadahyu.datapavan.network.activity

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.log.AppState
import org.visadahyu.datapavan.network.log.LogRecord

class HistoryTest {
    /**
     * The proxy record's unit A: a record of the log is never a first hop shown only, so its row says nothing of a window
     * and gives no link for it, as the history screen builds it.
     */
    @Test
    fun aRecordsRowIsNeverShownOnly() {
        val proxy = LogRecord.Proxy(LogRecord.PROXY_SOCKS5, password = true, proxyName = "proxy.example.net")
        val facts = org.visadahyu.datapavan.network.ui.proxyFacts(proxy, InetAddress.getByName("203.0.113.5"), 1080, 0, null, null)
        assertEquals(false, facts.shownOnly)
        val notes = setOf(org.visadahyu.datapavan.network.R.string.now_proxy_live_only, org.visadahyu.datapavan.network.R.string.now_proxy_asked_off)
        for (shown in listOf(false, true)) {
            val row = org.visadahyu.datapavan.network.ui.proxyRow(facts.copy(shownOnly = shown), past = true)
            assertEquals(false, row.toSwitch)
            assertTrue(row.lines.none { it.text in notes })
        }
    }

    private val t = 1_794_953_400_000L
    private val app = 10_123

    private fun segment(uid: Int?, start: Long, end: Long, name: String = "a.example", dns: String = "", state: Int = AppState.BACKGROUND) =
        LogRecord.Segment(
            flow = 1, uid = uid, start = start, end = end, up = 10, down = 20, wireUp = 0, wireDown = 0, protocol = 6,
            outcome = 0, namedBy = 1, ech = 0, dns = 0, continues = true, cameIn = false,
            address = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1)), port = 443, asn = 0, network = 0,
            name = name, resolver = "", dnsName = dns, state = state,
        )

    /**
     * A day of an app's history: its own segments only, newest first, each with both names and its state; its
     * lookups counted; and records older than the app now holding its UID counted apart, as an app's since removed.
     */
    @Test
    fun aDayHoldsTheAppsOwnSegmentsNewestFirst() {
        val records = listOf(
            segment(app, t + 1_000, t + 2_000, dns = "b.example", state = AppState.IN_USE),
            segment(app, t + 5_000, t + 6_000),
            segment(app, t + 5_000, t + 9_000, dns = "a.example"),
            segment(10_124, t + 7_000, t + 8_000),
            segment(app, t - 50_000, t - 40_000),
            LogRecord.Lookups(app, t + 3_000, t + 4_000, 3, 0, 0),
            LogRecord.Lookups(app, t - 60_000, t - 59_000, 9, 0, 0),
            LogRecord.Lookups(null, t + 3_000, t + 4_000, 7, 0, 0),
        )
        val day = History.day(20_775, records, app, installedAt = t)
        assertEquals(listOf(t + 5_000 to t + 9_000, t + 5_000 to t + 6_000, t + 1_000 to t + 2_000), day.entries.map { it.start to it.end })
        assertEquals(listOf("", "", "b.example"), day.entries.map { it.dnsName })
        assertEquals(AppState.IN_USE, day.entries.last().state)
        assertEquals(listOf(10L to 20L), day.entries.map { it.sent to it.received }.distinct())
        assertEquals("192.0.2.1" to 443, day.entries[0].address to day.entries[0].port)
        assertEquals(3L, day.lookups)
        assertEquals(2, day.beforeInstall)
        // No app holds the UID now: every record is shown; and the flows Android named no app for are one "app".
        assertEquals(4, History.day(20_775, records, app, installedAt = null).entries.size)
        assertEquals(7L, History.day(20_775, records, null, installedAt = null).lookups)
        // A record that starts exactly when the app was installed is the app's.
        assertEquals(0, History.day(20_775, listOf(segment(app, t, t + 1)), app, installedAt = t).beforeInstall)
    }

    /**
     * A segment the log keeps no destination of, a chained app's or the tool's own while "Log where these apps
     * connect" is off, is told as such, never as a destination of zeros (review c1 of W5's third part, screens,
     * M3); a named destination at such an address is not.
     */
    @Test
    fun aSegmentWithNoDestinationIsToldAsSuch() {
        fun at(address: ByteArray, name: String = "") = segment(app, t + 1_000, t + 2_000).copy(address = InetAddress.getByAddress(address), name = name)
        val records = listOf(at(ByteArray(4)), at(ByteArray(16)), at(ByteArray(4), "named.example"), segment(app, t + 3_000, t + 4_000))
        val day = History.day(20_775, records, app, installedAt = t)
        assertEquals(listOf(false, true, true, false), day.entries.map { it.unlogged })
    }

    /**
     * W7, part 2: a segment that went through a WireGuard tunnel keeps its route and the tunnel's number, so that the
     * history names the configuration, or says it was removed; one of a version before routes says none.
     */
    @Test
    fun aSegmentThroughATunnelKeepsItsTunnel() {
        val records = listOf(
            segment(app, t + 1_000, t + 2_000).copy(via = LogRecord.VIA_TUNNEL, tunnel = 3),
            segment(app, t + 3_000, t + 4_000).copy(via = LogRecord.VIA_TOOL),
            segment(app, t + 5_000, t + 6_000).copy(via = LogRecord.VIA_UNKNOWN),
        )
        val day = History.day(20_775, records, app, installedAt = t)
        assertEquals(
            listOf(LogRecord.VIA_UNKNOWN to 0L, LogRecord.VIA_TOOL to 0L, LogRecord.VIA_TUNNEL to 3L),
            day.entries.map { it.via to it.tunnel },
        )
    }

    /**
     * Fix round of W8 part 2a: a segment with no destination says why from its recorded route and proxy. A flow left
     * out for an app's own proxy is told apart from one sent through the tool; only a route through the tool says it
     * went through the tool, never a direct one or one of a record that kept no route; the proxy's own flag decides,
     * never an address of zeros; and the address is read once, here.
     */
    @Test
    fun aSegmentWithNoDestinationSaysWhyByItsRoute() {
        val zeros = segment(app, t + 1_000, t + 2_000, name = "").copy(address = InetAddress.getByAddress(ByteArray(4)))
        fun why(segment: LogRecord.Segment, tool: Boolean = false) =
            History.leftOut(History.day(20_775, listOf(segment), app, installedAt = t).entries.single(), tool)
        val proxied = zeros.copy(proxy = LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true))
        assertEquals(History.LeftOut.PROXY, why(proxied))
        assertEquals(History.LeftOut.THROUGH_TOOL, why(zeros.copy(via = LogRecord.VIA_TOOL)))
        assertEquals(History.LeftOut.DIRECT, why(zeros.copy(via = LogRecord.VIA_DIRECT)))
        assertEquals(History.LeftOut.TUNNEL, why(zeros.copy(via = LogRecord.VIA_TUNNEL, tunnel = 2)))
        assertEquals(History.LeftOut.NO_ROUTE, why(zeros.copy(via = LogRecord.VIA_UNKNOWN)))
        assertEquals(History.LeftOut.TOOL_SERVERS, why(zeros.copy(via = LogRecord.VIA_DIRECT), tool = true))
        // A proxy's flow kept, the switch on, shows its own destination; at an address of zeros all the same, its flag
        // says it was not left out for an app's own proxy.
        assertEquals(null, why(segment(app, t + 1_000, t + 2_000).copy(proxy = LogRecord.Proxy(LogRecord.PROXY_SOCKS5))))
        assertEquals(History.LeftOut.DIRECT, why(zeros.copy(proxy = LogRecord.Proxy(LogRecord.PROXY_SOCKS5))))
        assertEquals(null, why(segment(app, t + 1_000, t + 2_000)))
        val entry = History.day(20_775, listOf(segment(app, t + 1_000, t + 2_000)), app, installedAt = t).entries.single()
        assertEquals(InetAddress.getByName("192.0.2.1") to "192.0.2.1", entry.ip to entry.address)
    }

    /**
     * The proxy record's unit B (audit-B 4): a record left out for the switch whose proxy the engine found on the local
     * network says so in the history, as its row is built from the day's entry; a record before version 7, at its
     * address of zeros, never does.
     */
    @Test
    fun aLocalProxyLeftOutSaysSoInTheHistory() {
        val zeros = segment(app, t + 1_000, t + 2_000, name = "").copy(address = InetAddress.getByAddress(ByteArray(4)), port = 0)
        fun row(proxy: LogRecord.Proxy): List<Int> {
            val entry = History.day(20_775, listOf(zeros.copy(proxy = proxy)), app, installedAt = t).entries.single()
            assertEquals(History.LeftOut.PROXY, History.leftOut(entry, tool = false))
            val facts = org.visadahyu.datapavan.network.ui.proxyFacts(checkNotNull(entry.proxy), entry.ip, entry.port, entry.asn, null, null)
            val row = org.visadahyu.datapavan.network.ui.proxyRow(facts, past = true)
            return listOfNotNull(row.header?.text) + row.lines.map { it.text }
        }
        val connect = LogRecord.Proxy(LogRecord.PROXY_CONNECT, leftOut = true, local = true)
        assertEquals(listOf(R.string.history_proxy_hidden, R.string.proxy_how_read, R.string.proxy_local), row(connect))
        assertEquals(listOf(R.string.history_proxy_hidden, R.string.proxy_how_read), row(connect.copy(local = null)))
        assertEquals(listOf(R.string.history_proxy_hidden, R.string.proxy_how_read), row(connect.copy(local = false)))
    }

    /** The days the log keeps, today first; none with retention "none". */
    @Test
    fun theDaysAreThoseTheLogKeeps() {
        assertEquals(listOf(100L, 99L, 98L, 97L, 96L, 95L, 94L), History.days(100, 7))
        assertEquals(listOf(100L), History.days(100, 1))
        assertEquals(emptyList<Long>(), History.days(100, 0))
    }
}
