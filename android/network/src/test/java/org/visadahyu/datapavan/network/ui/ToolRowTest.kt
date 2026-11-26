package org.visadahyu.datapavan.network.ui

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.History
import org.visadahyu.datapavan.network.activity.Snapshot
import org.visadahyu.datapavan.network.log.AppState
import org.visadahyu.datapavan.network.log.LogRecord

/**
 * A circumvention tool's own row in "Now" and its history (the proxy record's unit D, R10, option (c) of 2026-11-25): the
 * card's lines for the chain's tool and another, and for connections no longer shown; a place the engine shows here only;
 * the links to the switch and to the choice for one tool (D7); and the history's reading of a tool's records.
 */
class ToolRowTest {
    private val chained = 10_200
    private val orbot = 10_201
    private val other = 10_300

    private fun app(uid: Int?, isTool: Boolean = false, serversHidden: Boolean = false, throughTool: Boolean = false) =
        Snapshot.App(uid, AppState.IN_USE, isTool, throughTool, LongArray(80), emptyList(), serversHidden)

    private fun place(address: String, proxy: LogRecord.Proxy? = null, shownOnly: Boolean = true) = Snapshot.Destination(
        protocol = 6, namedBy = 0, ech = 0, dns = 0, cameIn = false, address = InetAddress.getByName(address), port = 443, asn = 0,
        network = 0, name = "", dnsName = "", resolver = "", organisation = "", bytes = List(6) { 1L }, proxy = proxy,
        shownOnly = shownOnly,
    )

    /** The tools whose own connections follow R10, the chain's among them, the switch off and no tool chosen. */
    private val choices = ProxyChoices(tools = setOf(chained, orbot))

    /**
     * The chain's tool keeps "your circumvention tool"; another tool is a circumvention tool Datapavan sends no app
     * through, whose proxy other apps may use unseen; an app that is neither says nothing of it, even with a tool's UID
     * on the engine's side.
     */
    @Test
    fun theChainsToolAndAnotherAreToldApart() {
        assertEquals(listOf(R.string.now_is_tool), toolCardLines(app(chained, isTool = true), choices))
        assertEquals(listOf(R.string.now_is_tool_unchained), toolCardLines(app(orbot), choices))
        assertEquals(emptyList<Int>(), toolCardLines(app(other), choices))
        assertEquals(emptyList<Int>(), toolCardLines(app(null), choices))
        // A chained app's row is not the tool's.
        assertEquals(emptyList<Int>(), toolCardLines(app(other, throughTool = true), choices))
    }

    /**
     * Some of a tool's bytes with no place in the window: said with the rule, on the chain's tool and another alike, in
     * the words of option (c), which hide nothing live; the old line of the rule of 2026-11-19 is gone.
     */
    @Test
    fun connectionsNoLongerShownAreSaidOnAnyTool() {
        assertEquals(listOf(R.string.now_is_tool, R.string.now_tool_left_out), toolCardLines(app(chained, isTool = true, serversHidden = true), choices))
        assertEquals(listOf(R.string.now_is_tool_unchained, R.string.now_tool_left_out), toolCardLines(app(orbot, serversHidden = true), choices))
        // The engine's bit is its word: a tool not in the screen's set yet still says it.
        assertEquals(listOf(R.string.now_tool_left_out), toolCardLines(app(other, serversHidden = true), choices))
        val strings = java.io.File("src/main/res/values/strings.xml").readText()
        assertFalse(strings.contains("now_tool_servers_off"))
    }

    /**
     * A place with no proxy that the engine shows here only is a tool's own connection: its line names the tool and who
     * can see it, links to the switch, and to the choice while the tool can be chosen. A first hop of an app's own proxy,
     * a place not marked, and a tool's place with the switch on or the tool chosen say nothing of it.
     */
    @Test
    fun aToolsPlaceShownHereOnlySaysSoAndLinks() {
        val row = checkNotNull(toolPlaceRow(place("203.0.113.9"), orbot, "Orbot", choices))
        assertEquals(listOf(ProxyLine(R.string.now_tool_live_only, args = listOf("Orbot"))), row.lines)
        assertTrue(row.toSwitch)
        assertEquals(Choice.LOG, row.toChoice)
        assertNull(row.header)
        assertNull(toolPlaceRow(place("203.0.113.9", shownOnly = false), orbot, "Orbot", choices))
        assertNull(toolPlaceRow(place("203.0.113.9", LogRecord.Proxy(LogRecord.PROXY_SOCKS5)), orbot, "Orbot", choices))
        // Chosen already, or the switch on: no link to choose (the engine then marks no place so anyway).
        assertNull(toolPlaceRow(place("203.0.113.9"), orbot, "Orbot", choices.copy(toolsChosen = setOf(orbot)))?.toChoice)
        assertNull(toolPlaceRow(place("203.0.113.9"), orbot, "Orbot", choices.copy(switchOn = true))?.toChoice)
        // Not offered: another user's tool, one not in the set, one of Android's own UIDs.
        assertNull(toolPlaceRow(place("203.0.113.9"), 1_010_201, "Orbot", choices.copy(tools = setOf(1_010_201)))?.toChoice)
        assertNull(toolPlaceRow(place("203.0.113.9"), other, "App", choices)?.toChoice)
        assertNull(toolPlaceRow(place("203.0.113.9"), 1_000, "Android", choices.copy(tools = setOf(1_000)))?.toChoice)
    }

    /**
     * The choice for one tool (D7): offered for a tool of this user's, never for an ordinary app, a chained app or the PAC
     * handler; its card links to stop it once chosen while the switch is off; turned off here, its card says what stays.
     */
    @Test
    fun theChoiceForOneToolIsOfferedOnItsRowsAlone() {
        assertTrue(choices.toolOffered(orbot))
        assertTrue(choices.toolOffered(chained))
        assertFalse(choices.toolOffered(other))
        assertFalse(choices.toolOffered(null))
        // Never the app's own proxy choice on a tool's row (unit C), nor the tool's on an app's.
        assertFalse(choices.offered(orbot))
        assertNull(toolCardChoice(app(orbot), choices))
        val chosen = choices.copy(toolsChosen = setOf(orbot))
        assertEquals(Choice.STOP, toolCardChoice(app(orbot), chosen))
        assertNull(toolCardChoice(app(orbot), chosen.copy(switchOn = true)))
        assertNull(toolCardChoice(app(other), chosen.copy(toolsChosen = setOf(other))))
        val stopped = choices.copy(toolsStopped = setOf(orbot))
        assertEquals(listOf(R.string.now_is_tool_unchained, R.string.proxy_app_stopped), toolCardLines(app(orbot), stopped))
        // Chosen again, the note goes.
        assertEquals(listOf(R.string.now_is_tool_unchained), toolCardLines(app(orbot), stopped.copy(toolsChosen = setOf(orbot))))
    }

    /**
     * A tool's history opens as a tool's, the chain's or another of R10's, so that a record the log keeps with no address
     * says why (D8); an ordinary app's, a vpn-only tool's among them, does not.
     */
    @Test
    fun aToolsHistoryReadsItsRecordsLeftOutAsTheTools() {
        assertTrue(opensAsTool(app(chained, isTool = true), ProxyChoices()))
        assertTrue(opensAsTool(app(orbot), choices))
        assertFalse(opensAsTool(app(other), choices))
        val stripped = History.Entry(
            start = 0, end = 1, protocol = 6, name = "", dnsName = "", address = "0.0.0.0", port = 0, namedBy = 0, sent = 1,
            received = 2, state = AppState.IN_USE, continues = false, unlogged = true, via = LogRecord.VIA_DIRECT,
        )
        assertEquals(History.LeftOut.TOOL_SERVERS, History.leftOut(stripped, opensAsTool(app(orbot), choices)))
        assertEquals(History.LeftOut.DIRECT, History.leftOut(stripped, opensAsTool(app(other), choices)))
        assertEquals(R.string.history_left_out_off, leftOutWords(History.LeftOut.TOOL_SERVERS))
    }
}
