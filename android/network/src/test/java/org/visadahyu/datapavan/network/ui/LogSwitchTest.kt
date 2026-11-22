package org.visadahyu.datapavan.network.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.activity.Snapshot
import org.visadahyu.datapavan.network.log.AppState

/** Where Watch's screen draws "Log where apps connect ..." (fix round of W8 part 2a, screens review M4). */
class LogSwitchTest {
    private fun counters(declared: Long = 0, inferred: Long = 0) =
        LongArray(67).also {
            it[LogSwitch.DECLARED] = declared
            it[LogSwitch.INFERRED] = inferred
        }

    /**
     * A phone with no circumvention tool and no WireGuard configuration, whose Telegram goes through an MTProto proxy:
     * the switch its rows name is drawn on its own, where the user can find it.
     */
    @Test
    fun aTelegramProxySeenDrawsTheSwitchWithNoToolAndNoTunnel() {
        val seen = LogSwitch.proxiesSeen(counters(inferred = 1))
        assertTrue(seen)
        val places = LogSwitch.places(toolAnswers = false, tunnels = false, proxiesSeen = seen, asked = false, on = false)
        assertEquals(setOf(LogSwitch.Place.ALONE), places)
        assertEquals(LogSwitch.Place.ALONE, LogSwitch.target(places))
        // A declared proxy (a SOCKS5 proxy set in an app) alike.
        assertTrue(LogSwitch.proxiesSeen(counters(declared = 2)))
    }

    /** Nothing left out for it: no switch. No engine (no counters): none seen. */
    @Test
    fun nothingLeftOutDrawsNoSwitch() {
        assertFalse(LogSwitch.proxiesSeen(counters()))
        assertFalse(LogSwitch.proxiesSeen(LongArray(0)))
        val places = LogSwitch.places(toolAnswers = false, tunnels = false, proxiesSeen = false, asked = false, on = false)
        assertEquals(emptySet<LogSwitch.Place>(), places)
        assertEquals(null, LogSwitch.target(places))
    }

    /**
     * The tool's section and the WireGuard section draw it where they did, and then it is not drawn again on its own; a
     * row's link brings the user to the first.
     */
    @Test
    fun theToolsAndTheTunnelsSectionsDrawItWhereTheyDid() {
        assertEquals(setOf(LogSwitch.Place.CHAIN), LogSwitch.places(true, false, proxiesSeen = true, asked = true, on = true))
        assertEquals(setOf(LogSwitch.Place.TUNNELS), LogSwitch.places(false, true, proxiesSeen = true, asked = false, on = false))
        val both = LogSwitch.places(true, true, proxiesSeen = false, asked = false, on = false)
        assertEquals(setOf(LogSwitch.Place.CHAIN, LogSwitch.Place.TUNNELS), both)
        assertEquals(LogSwitch.Place.CHAIN, LogSwitch.target(both))
    }

    /**
     * A row's link draws it, for a day of the history whose engine has since stopped; and a switch the user turned on
     * stays drawn, so that it can be turned off.
     */
    @Test
    fun aLinkOrTheSwitchOnDrawsIt() {
        assertEquals(setOf(LogSwitch.Place.ALONE), LogSwitch.places(false, false, proxiesSeen = false, asked = true, on = false))
        assertEquals(setOf(LogSwitch.Place.ALONE), LogSwitch.places(false, false, proxiesSeen = false, asked = false, on = true))
    }

    /** Once seen, a proxy stays seen while Watch runs, between two engines too; Watch stopped, none is. */
    @Test
    fun aProxySeenStaysSeenWhileWatchRuns() {
        assertTrue(LogSwitch.seen(before = false, running = true) { counters(inferred = 1) })
        assertTrue(LogSwitch.seen(before = true, running = true) { LongArray(0) })
        assertFalse(LogSwitch.seen(before = true, running = false) { counters(inferred = 1) })
        assertFalse(LogSwitch.seen(before = false, running = true) { counters() })
    }

    /**
     * A row's link opens Watch's screen above "Now" and leaves "Now" as it was beneath it, so that Back comes back to the
     * same app's row or its history (W8 part 3a, the brief's point 11): no flag that closes what is above Watch's screen
     * (`CLEAR_TOP`, which the link used and which closed "Now"), and none that takes the user to another task on Back.
     */
    @Test
    fun aRowsLinkKeepsNowBeneathTheSwitch() {
        val closing = android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK or
            android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or
            android.content.Intent.FLAG_ACTIVITY_NO_HISTORY
        assertEquals(0, LogSwitch.LINK_FLAGS and closing)
        assertEquals(android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP, LogSwitch.LINK_FLAGS)
        // MainActivity's link takes its flags from LINK_FLAGS alone.
        val main = java.io.File("src/main/java/org/visadahyu/datapavan/network/MainActivity.kt").readText()
        val link = main.substringAfter("fun logSwitchIntent(").substringBefore("\n\n")
        assertTrue(link, link.contains("addFlags(LogSwitch.LINK_FLAGS)") && !link.contains("FLAG_ACTIVITY"))
    }

    /** An app's row in "Now" links to it where the switch leaves out where it went: through the tool, its servers, or a tunnel. */
    @Test
    fun anAppsRowLinksToItWhereItLeavesSomethingOut() {
        fun app(isTool: Boolean = false, throughTool: Boolean = false, serversHidden: Boolean = false, throughTunnel: Long = 0) =
            Snapshot.App(10_123, AppState.IN_USE, isTool, throughTool, LongArray(80), emptyList(), serversHidden, throughTunnel)
        assertFalse(LogSwitch.hides(app()))
        assertTrue(LogSwitch.hides(app(throughTool = true)))
        assertTrue(LogSwitch.hides(app(isTool = true, serversHidden = true)))
        assertTrue(LogSwitch.hides(app(throughTunnel = 3)))
        assertFalse(LogSwitch.hides(app(isTool = true)))
    }
}
