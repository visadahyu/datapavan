package org.visadahyu.datapavan.network.blocking

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.audit.Owners
import org.visadahyu.datapavan.network.blocking.Coverage.App

/** Which apps tracker blocking covers, and which apps are browsers (W8, part 3a; the brief's point 5; ADR 0053). */
class CoverageTest {
    private fun covered(apps: List<App>, tool: Int? = null, browsers: Set<String> = emptySet(), include: Boolean = false) =
        Coverage.covered(apps, self = SELF, playServices = PLAY, tool = tool, browsers = browsers, includeBrowsers = include)

    /** The apps the user installed are covered; Android's own UIDs, apps that came with the phone and Watch are not. */
    @Test
    fun theAppsTheUserInstalledAreCovered() {
        val apps = listOf(
            App(10_123, "com.example.game", system = false),
            App(1_000, "android", system = true),
            App(1_000, "com.android.settings", system = true),
            // Under 10000 with no system flag all the same: Android's own.
            App(9_999, "com.example.low", system = false),
            // Came with the phone, or updated since it did.
            App(10_050, "com.vendor.weather", system = true),
            App(SELF, "org.visadahyu.datapavan.advanced", system = false),
            App(PLAY, Coverage.PLAY_SERVICES, system = true),
        )
        assertEquals(setOf(10_123), covered(apps))
        // Play services by its name too, wherever its UID was not found.
        assertEquals(emptySet<Int>(), Coverage.covered(listOf(App(10_300, Coverage.PLAY_SERVICES, false)), SELF, null, null, emptySet(), false))
    }

    /** The user's tool is never covered: its connections show cover names that can be any popular host. */
    @Test
    fun theUsersToolIsNeverCovered() {
        val apps = listOf(App(10_123, "com.example.game", false), App(10_400, "com.example.tool", false))
        assertEquals(setOf(10_123), covered(apps, tool = 10_400))
        assertEquals(setOf(10_123, 10_400), covered(apps))
    }

    /** Browsers are not covered unless the user includes them; a UID shared with a system package is not covered. */
    @Test
    fun browsersOnlyWhenIncludedAndSharedUidsWhole() {
        val apps = listOf(App(10_123, "com.example.game", false), App(10_500, "org.example.browser", false))
        assertEquals(setOf(10_123), covered(apps, browsers = setOf("org.example.browser")))
        assertEquals(setOf(10_123, 10_500), covered(apps, browsers = setOf("org.example.browser"), include = true))
        val shared = listOf(App(10_600, "com.example.one", false), App(10_600, "com.example.two", true))
        assertEquals(emptySet<Int>(), covered(shared))
    }

    /**
     * A browser answers a host no app claims through a filter that names no host. An app whose App Links claim its own
     * site's hosts names them, and is not one; an answer Android gave no filter for is not counted.
     */
    @Test
    fun aBrowserIsAnAppWhoseFilterNamesNoHost() {
        val answers = listOf(
            "org.mozilla.firefox" to 0,
            "com.android.chrome" to 0,
            "com.example.shop" to 2,
            "com.example.links" to 1,
            "com.example.unknown" to null,
            // One app answering by two activities, one of them a browser's.
            "com.example.reader" to 3,
            "com.example.reader" to 0,
        )
        assertEquals(setOf("org.mozilla.firefox", "com.android.chrome", "com.example.reader"), Coverage.browsers(answers))
        assertTrue(Coverage.BROWSER_PROBE.startsWith("https://") && Coverage.BROWSER_PROBE.contains(".invalid/"))
    }

    /**
     * The test the brief names (ADR 0053, decision 2): an app that the owners table gives to Google, reaching an AdMob
     * host, is blocked. Who publishes the app plays no part in what is covered or kept: it is covered as any app, no
     * exception keeps the AdMob row for it, and its code cannot keep a row graded block.
     */
    @Test
    fun anAppThatTheOwnersTableGivesToGoogleReachingAnAdMobHostIsBlocked() {
        val owners = Owners.parse(File("../../data/owners/entities.tsv").readText(), "", File("../../data/owners/publishers.tsv").readText())
        val (name, certificate) = File("../../data/owners/publishers.tsv").readLines()
            .map { it.split('\t') }.first { it.size >= 3 && it[2] == "google" && it[0].startsWith("com.google.android.apps.") }
            .let { it[0] to it[1] }
        val signing = AppSigning(listOf(certificate), emptyList(), debug = false)
        assertEquals("google", owners.publisher(name, signing))
        val uid = 10_777
        val covered = covered(listOf(App(uid, name, system = false)))
        assertEquals(setOf(uid), covered)
        val table = checkNotNull(BlockingTable.parse(File("../../data/blocking/hosts.tsv").readText()))
        val trackers = TrackerCode.parse(File("../../data/exodus/trackers.tsv").readText())
        val admob = checkNotNull(table.find("googleads.g.doubleclick.net"))
        assertEquals(BlockingTable.Grade.BLOCK, admob.grade)
        val exceptions = Exceptions.parse(File("../../data/blocking/exceptions.tsv").readText())
        val excepted = Grades.excepted(exceptions, listOf(name to signing))
        assertFalse(admob.host in excepted)
        // Its code holds AdMob, as a Google app's may: the row is still blocked.
        val adMob = trackers.single { it.name == "Google AdMob" }.id
        val decided = Grades.forApp(table, trackers, setOf(adMob), excepted)
        val facts = BlockingFacts(table, intArrayOf(), trackers, covered, emptyList(), mapOf(uid to decided), mapOf(name to uid))
        assertTrue(facts.blocks(uid, admob))
        assertTrue(Handover.text(true, false, 0, covered, facts.decided, emptyMap(), emptyList()).lines().contains("covered $uid"))
        assertFalse(Handover.text(true, false, 0, covered, facts.decided, emptyMap(), emptyList()).contains(admob.host))
    }

    private companion object {
        const val SELF = 10_200
        const val PLAY = 10_100
    }
}
