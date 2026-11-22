package org.visadahyu.datapavan.network.ui

import java.io.File
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.History
import org.visadahyu.datapavan.network.blocking.BlockingFacts
import org.visadahyu.datapavan.network.blocking.BlockingTable
import org.visadahyu.datapavan.network.blocking.Grades.Decided
import org.visadahyu.datapavan.network.blocking.Tallies.Tally
import org.visadahyu.datapavan.network.blocking.TrackerCode

/**
 * What "Now", the history and Watch's screen say of tracker blocking (W8, part 3a; the brief's points 6 to 8): each
 * branch as the pure rules choose it, and the words, held to ADR 0025's list.
 */
class BlockingLinesTest {
    private val table = checkNotNull(BlockingTable.parse(File("../../data/blocking/hosts.tsv").readText()))
    private val trackers = TrackerCode.parse(File("../../data/exodus/trackers.tsv").readText())
    private val companies = mapOf("https://admob.google.com" to "Google LLC", "https://firebase.google.com/" to "Google LLC")
    private val game = 10_123
    private val packages = listOf("com.example.game")

    private fun name(row: BlockingTable.Row, hideHost: Boolean = false) =
        rowName(row, trackers, { companies[it.website] }, hideHost)

    private fun row(host: String) = checkNotNull(table.row(host)) { host }

    private fun facts(decided: Map<String, Decided> = emptyMap(), covered: Set<Int> = setOf(game)) =
        BlockingFacts(table, intArrayOf(), trackers, covered, emptyList(), mapOf(game to decided), mapOf("com.example.game" to game))

    private fun view(
        facts: BlockingFacts = facts(),
        tallies: List<Tally> = emptyList(),
        on: Boolean = true,
        apps: Map<String, Long> = emptyMap(),
        entries: Set<Pair<String, String>> = emptySet(),
    ) = BlockingView(on, facts, tallies, apps, entries)

    private fun entry(
        name: String = "",
        dnsName: String = "",
        blocked: Boolean = false,
        sdk: String = "",
        unlogged: Boolean = false,
    ) = History.Entry(
        0, 0, 6, name, dnsName, if (unlogged) "0.0.0.0" else "192.0.2.7", 443, 0, 0, 0, 0, false,
        unlogged = unlogged, ip = InetAddress.getByName("192.0.2.7"), blocked = blocked, blockedSdk = sdk,
    )

    /**
     * A row is named by εxodus's tracker, with its company only where the owners' table gives one, a form with no company
     * for the many with none; by its host where no tracker joins; and never by its host where the switch hides it.
     */
    @Test
    fun aRowIsNamedByItsTrackerOrItsHost() {
        assertEquals(Named.Tracker("Google AdMob", "Google LLC"), name(row("googleads.g.doubleclick.net")))
        assertEquals(Named.Tracker("Adjust", null), name(row("app.adjust.com")))
        assertEquals(Named.Host("firebaselogging.googleapis.com"), name(row("firebaselogging.googleapis.com")))
        assertEquals(Named.Sdk("com.google.android.datatransport:transport-backend-cct"), name(row("firebaselogging.googleapis.com"), hideHost = true))
        // Where a tracker joins, hiding the host changes nothing: the tracker names no host.
        assertEquals(Named.Tracker("Adjust", null), name(row("app.adjust.com"), hideHost = true))
        // Two trackers of one company by the company; of no known company, by both names.
        val center = row("in.appcenter.ms")
        assertEquals(Named.Company("Microsoft"), rowName(center, trackers, { "Microsoft" }, false))
        assertTrue((rowName(center, trackers, { null }, false) as Named.Tracker).name.contains(", "))
    }

    /**
     * One allow for each row the app reached, but one for a company where one broad εxodus signature names several of its
     * trackers (as TrackerMarks groups them); counts summed, lookups apart from connections, since the first.
     */
    @Test
    fun oneAllowPerRowOrOnePerCompany() {
        val tallies = listOf(
            Tally(game, "app.adjust.com", 3, 1, 2_000),
            Tally(game, "app.adjust.io", 0, 2, 1_000),
            Tally(game, "graph.facebook.com", 1, 4, 3_000),
        )
        val rows = tallies.map { row(it.host) } + row("graph-video.facebook.com")
        val meta = { r: BlockingTable.Row -> "Meta Platforms, Inc.".takeIf { r.host.endsWith("facebook.com") } }
        val units = units(rows, tallies, { name(it) }, meta, allowed = setOf("app.adjust.io"), hideHost = false)
        assertEquals(3, units.size)
        val facebook = units.first { it.named == Named.Company("Meta Platforms, Inc.") }
        assertEquals(listOf("graph.facebook.com", "graph-video.facebook.com"), facebook.hosts)
        assertEquals(Triple(1L, 4L, 3_000L), Triple(facebook.lookups, facebook.connections, facebook.since))
        // Each row of one tracker has its own allow, each with its own function.
        val adjust = units.filter { it.named == Named.Tracker("Adjust", null) }
        assertEquals(listOf(listOf("app.adjust.com"), listOf("app.adjust.io")), adjust.map { it.hosts }.sortedBy { it.first() })
        assertEquals(listOf(false, true), adjust.sortedBy { it.hosts.first() }.map { it.allowed })
        // With the hosts hidden, rows told apart by their hosts alone share their name's allow.
        val hidden = units(rows.take(2), tallies, { name(it, true) }, { null }, emptySet(), hideHost = true)
        assertEquals(listOf(listOf("app.adjust.com", "app.adjust.io")), hidden.map { it.hosts })
        assertEquals(3L to 3L, hidden.single().lookups to hidden.single().connections)
    }

    /** An app's row says nothing with blocking off, for an app not covered and not counted, or with no package. */
    @Test
    fun anAppsRowOffersTheUndoOnlyWhereBlockingCoversIt() {
        val company = { _: BlockingTable.Row -> null as String? }
        assertNull(appBlocking(view(on = false), game, packages, { name(it) }, company, false))
        assertNull(appBlocking(view(facts(covered = emptySet())), game, packages, { name(it) }, company, false))
        assertNull(appBlocking(view(), game, emptyList(), { name(it) }, company, false))
        assertNull(appBlocking(view(), null, packages, { name(it) }, company, false))
        assertNull(appBlocking(view(BlockingFacts.NONE), game, packages, { name(it) }, company, false))
        // Covered, nothing counted yet: the undo is offered, not allowed.
        assertEquals(AppBlocking(null, emptyList()), appBlocking(view(), game, packages, { name(it) }, company, false))
        // Counted although no longer covered (a browser the user took out): still said, with its undo.
        val counted = appBlocking(view(facts(covered = emptySet()), listOf(Tally(game, "app.adjust.com", 0, 1, 5))), game, packages, { name(it) }, company, false)
        assertEquals(1, counted?.units?.size)
        // Allowed: until when, the latest of its packages'.
        val allowed = appBlocking(view(apps = mapOf("com.example.game" to 7_000L)), game, packages, { name(it) }, company, false)
        assertEquals(7_000L, allowed?.allowedUntil)
    }

    /** Why a host the app reached is not blocked in it: the table's, its code's, an unread code's, or an exception's. */
    @Test
    fun theFactOfAHostKept() {
        assertEquals(R.string.blocking_kept, keptFact(row("m.facebook.com"), null))
        assertEquals(R.string.blocking_kept_code, keptFact(row("graph.facebook.com"), Decided.KEEP))
        assertEquals(R.string.blocking_kept_unread, keptFact(row("graph.facebook.com"), Decided.NOT_READ))
        assertEquals(R.string.blocking_kept_unread, keptFact(row("graph.facebook.com"), null))
        assertEquals(R.string.blocking_kept_own, keptFact(row("graph.facebook.com"), Decided.EXCEPTED))
        assertNull(keptFact(row("graph.facebook.com"), Decided.BLOCK))
        assertNull(keptFact(row("app-measurement.com"), null))
        // In the history, under the segment that reached it, with blocking on and the app covered.
        val named = { r: BlockingTable.Row, hide: Boolean -> name(r, hide) }
        assertEquals(EntryBlocking.Kept(R.string.blocking_kept), entryBlocking(entry("x.onesignal.com"), view(), game, named, false))
        assertNull(entryBlocking(entry("x.onesignal.com"), view(on = false), game, named, false))
        assertNull(entryBlocking(entry("x.onesignal.com"), view(facts(covered = emptySet())), game, named, false))
        assertNull(entryBlocking(entry("www.example.com"), view(), game, named, false))
    }

    /**
     * A blocked flow shows as blocked, with its row's name and function; a chained app's flow logged with the switch off
     * keeps its row's SDK alone, and is named by its tracker, never by a host.
     */
    @Test
    fun aBlockedFlowInTheHistory() {
        val named = { r: BlockingTable.Row, hide: Boolean -> name(r, hide) }
        val admob = entryBlocking(entry("googleads.g.doubleclick.net", blocked = true, sdk = "com.google.android.gms:play-services-ads"), view(), game, named, false)
        assertEquals(EntryBlocking.Blocked(Named.Tracker("Google AdMob", "Google LLC"), row("googleads.g.doubleclick.net").function), admob)
        // Even with blocking off since: the log's record says what happened then.
        assertTrue(entryBlocking(entry("googleads.g.doubleclick.net", blocked = true), view(on = false), game, named, false) is EntryBlocking.Blocked)
        // Left out by the switch: the SDK names the tracker, and no host and no function is said.
        val hidden = entryBlocking(entry(blocked = true, sdk = "com.google.android.datatransport:transport-backend-cct", unlogged = true), view(), game, named, false)
        assertEquals(EntryBlocking.Blocked(Named.Sdk("com.google.android.datatransport:transport-backend-cct"), null), hidden)
        val adjust = entryBlocking(entry(blocked = true, sdk = "com.adjust.sdk:adjust-android", unlogged = true), view(), game, named, false)
        assertEquals(EntryBlocking.Blocked(Named.Tracker("Adjust", null), null), adjust)
        // An app whose destinations the switch hides: logged or not, the host is never its name.
        val tool = entryBlocking(entry("firebaselogging.googleapis.com", blocked = true), view(), game, named, hideHost = true)
        assertEquals(Named.Sdk("com.google.android.datatransport:transport-backend-cct"), (tool as EntryBlocking.Blocked).named)
        // An SDK the table no longer holds: by its coordinate.
        assertEquals(
            EntryBlocking.Blocked(Named.Sdk("com.example:gone"), null),
            entryBlocking(entry(blocked = true, sdk = "com.example:gone", unlogged = true), view(), game, named, false),
        )
    }

    /** The top of the history: the allows of the rows reached from the counts, the segments and the blocked flows, and the hosts kept. */
    @Test
    fun theTopOfTheHistory() {
        val named = { r: BlockingTable.Row, hide: Boolean -> name(r, hide) }
        val entries = listOf(
            entry("app-measurement.com"),
            entry("m.facebook.com"),
            entry(blocked = true, sdk = "io.sentry:sentry-android-core", unlogged = true),
        )
        val read = historyBlocking(view(tallies = listOf(Tally(game, "app.adjust.com", 1, 0, 9))), game, packages, entries, named, { null }, false)
        val names = read.units.map { it.named }
        assertTrue(names.toString(), Named.Tracker("Adjust", null) in names)
        assertTrue(names.toString(), Named.Tracker("Google Firebase Analytics", "Google LLC") in names)
        // Sentry's rows, reached by a flow logged without its names: one allow, named by its tracker.
        assertEquals(1, read.units.count { it.named == Named.Tracker("Sentry", null) })
        assertEquals(listOf(Named.Tracker("Facebook Login", null) to R.string.blocking_kept), read.kept)
        // Off, or an app not covered: nothing of it.
        assertEquals(HistoryBlocking(null, emptyList(), emptyList()), historyBlocking(view(on = false), game, packages, entries, named, { null }, false))
    }

    /**
     * Watch's screen: the switch, its notes and what is not covered always; the tool's option only while it is chained;
     * the pause only while blocking is on, and while paused its end and "Block again now".
     */
    @Test
    fun watchsScreenSection() {
        val off = blockingParts(BlockingSettingsView())
        assertEquals(
            listOf(BlockingPart.SWITCH, BlockingPart.NOTE, BlockingPart.NOT_COVERED, BlockingPart.BROWSERS, BlockingPart.BROWSERS_NOTE),
            off,
        )
        val on = blockingParts(BlockingSettingsView(on = true))
        assertEquals(off + listOf(BlockingPart.PAUSE, BlockingPart.NOTES), on)
        val paused = blockingParts(BlockingSettingsView(on = true, pausedUntil = 5))
        assertEquals(off + listOf(BlockingPart.PAUSED, BlockingPart.RESUME), paused)
        val chained = blockingParts(BlockingSettingsView(toolChained = true))
        assertEquals(off + listOf(BlockingPart.TOOL_DNS, BlockingPart.TOOL_DNS_NOTE), chained)
    }

    /** The strings the emulator check taps by their text, word for word. */
    @Test
    fun theLabelsTheEmulatorCheckTaps() {
        val strings = strings()
        assertEquals("Block trackers", strings.getValue("blocking_switch"))
        assertEquals("Allow trackers in this app", strings.getValue("blocking_allow_app"))
        assertEquals("Block trackers again", strings.getValue("blocking_block_app"))
        assertEquals("Pause blocking for 10 minutes", strings.getValue("blocking_pause"))
        assertEquals("Block again now", strings.getValue("blocking_resume"))
        assertEquals("Also block in browsers", strings.getValue("blocking_browsers"))
        assertEquals("Paused until %1\$s", strings.getValue("blocking_paused"))
    }

    /**
     * Tracker blocking's words keep ADR 0025's (decision 4): no word that judges or implies intent, never "grade", and
     * what the brief asks said is said: browsers, the apps not covered, late sends, and that the undo takes seconds.
     */
    @Test
    fun theBlockingStringsUseNoWordThatJudges() {
        val blocking = strings().filterKeys { it.startsWith("blocking_") }.mapValues { it.value.lowercase() }
        assertTrue(blocking.keys.toString(), blocking.size >= 32)
        val judging = listOf(
            "suspicious", "unusual", "abnormal", "excessive", "leak", "spying", "secretly", "malicious", "threat", "risk",
            "normal", "expected", "safe", "grade", "score", "rank", "dangerous", "bad", "harmful",
        )
        for ((name, text) in blocking) {
            for (word in judging) assertTrue("$name: $word", !Regex("\\b${Regex.escape(word)}").containsMatchIn(text))
        }
        assertEquals("browsers are not blocked unless you include them: they open any website.", blocking["blocking_browsers_note"])
        assertEquals("apps that came with the phone, android itself and google play services are not covered.", blocking["blocking_not_covered"])
        assertEquals("apps may send what they held back while blocked, once allowed.", blocking["blocking_late_sends"])
        assertTrue(blocking.getValue("blocking_seconds").startsWith("it works within a few seconds"))
        assertTrue(blocking.getValue("blocking_connections").contains("connections"))
        assertTrue(blocking.getValue("blocking_lookups").contains("lookups"))
    }

    /** Watch's English strings and plurals (their "other" form), by name. */
    private fun strings(): Map<String, String> {
        val text = listOf("strings.xml", "strings_untranslated.xml").map { File("src/main/res/values/$it") }.filter { it.isFile }
            .joinToString("") { it.readText() }
        val strings = Regex("""<string name="([a-z_0-9]+)">([^<]*)</string>""").findAll(text).associate { it.groupValues[1] to it.groupValues[2] }
        val plurals = Regex("""<plurals name="([a-z_0-9]+)">.*?<item quantity="other">([^<]*)</item>""", RegexOption.DOT_MATCHES_ALL)
            .findAll(text).associate { it.groupValues[1] to it.groupValues[2] }
        return strings + plurals
    }
}
