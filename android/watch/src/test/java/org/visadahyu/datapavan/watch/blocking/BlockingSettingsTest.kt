package org.visadahyu.datapavan.watch.blocking

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The user's blocking and its undo (W8, part 3a; the brief's point 6): an app allowed for an hour, rows until blocked
 * again, the pause for ten minutes, each worked out at each decision with no alarm, and never stretched by a clock set
 * back; and the setting handed to the engine whole.
 */
class BlockingSettingsTest {
    /** The store in memory, as SharedPreferences keeps it on the phone. */
    private class Memory : BlockingSettings.Store {
        val values = HashMap<String, Any>()
        override fun boolean(key: String) = values[key] as? Boolean ?: false
        override fun putBoolean(key: String, value: Boolean) {
            values[key] = value
        }
        override fun long(key: String) = values[key] as? Long ?: 0L
        override fun putLong(key: String, value: Long) {
            values[key] = value
        }
        @Suppress("UNCHECKED_CAST")
        override fun strings(key: String) = values[key] as? Set<String> ?: emptySet()
        override fun putStrings(key: String, value: Set<String>) {
            values[key] = value
        }
        override fun clear() = values.clear()
    }

    private val store = Memory()
    private val settings = BlockingSettings(store, self = "org.visadahyu.datapavan.advanced")
    private val hour = BlockingSettings.APP_MS
    private val now = 1_800_000_000_000L

    /** Off until the user turns it on; browsers and the tool's lookups too. */
    @Test
    fun everythingIsOffUntilTurnedOn() {
        assertEquals(listOf(false, false, false), listOf(settings.on, settings.browsers, settings.toolDns))
        settings.on = true
        settings.browsers = true
        assertEquals(listOf(true, true, false), listOf(settings.on, settings.browsers, settings.toolDns))
    }

    /** One tap allows an app for an hour, which ends by itself at its time, or at once by "Block trackers again". */
    @Test
    fun anAppIsAllowedForAnHourOrUntilBlockedAgain() {
        settings.allowApp("com.example.game", now)
        assertEquals(mapOf("com.example.game" to now + hour), settings.appsAllowed(now))
        assertEquals(1L, Allowances.left(now + hour, now + hour - 1, hour))
        // Its hour over, it is forgotten: the next decision blocks again.
        assertEquals(emptyMap<String, Long>(), settings.appsAllowed(now + hour))
        assertEquals(emptySet<String>(), store.strings("apps_allowed"))
        settings.allowApp("com.example.game", now)
        settings.allowApp("com.example.other", now + 1_000)
        settings.blockAppAgain("com.example.game")
        assertEquals(mapOf("com.example.other" to now + 1_000 + hour), settings.appsAllowed(now + 2_000))
        // A second tap starts its hour again.
        settings.allowApp("com.example.other", now + 30 * 60_000)
        assertEquals(mapOf("com.example.other" to now + 90 * 60_000), settings.appsAllowed(now + 30 * 60_000))
        // Watch itself is never allowed: it is never covered.
        settings.allowApp("org.visadahyu.datapavan.advanced", now)
        assertFalse("org.visadahyu.datapavan.advanced" in settings.appsAllowed(now))
    }

    /**
     * A clock set back cannot stretch an allowance: what is left is at most an hour (the pause, ten minutes), and the end
     * kept is brought back to it, so that it holds once the clock runs on.
     */
    @Test
    fun aClockSetBackStretchesNoAllowance() {
        settings.allowApp("com.example.game", now)
        val back = now - 5 * hour
        assertEquals(mapOf("com.example.game" to back + hour), settings.appsAllowed(back))
        assertEquals(hour, Allowances.left(now + hour, back, hour))
        // Kept so: with the clock still set back, an hour after that the app is blocked again.
        assertEquals(emptyMap<String, Long>(), settings.appsAllowed(back + hour))
        settings.pause(now)
        assertEquals(back + BlockingSettings.PAUSE_MS, settings.pausedUntil(back))
        assertNull(settings.pausedUntil(back + BlockingSettings.PAUSE_MS))
        assertEquals(0L, Allowances.left(now, now + 1, hour))
        assertNull(Allowances.clamp(0, now, hour))
    }

    /** The pause names no app, lasts ten minutes, and "Block again now" ends it. */
    @Test
    fun thePauseLastsTenMinutesOrUntilBlockedAgain() {
        assertNull(settings.pausedUntil(now))
        settings.pause(now)
        assertEquals(now + 10 * 60_000, settings.pausedUntil(now + 1))
        assertNull(settings.pausedUntil(now + 10 * 60_000))
        settings.pause(now)
        settings.resume()
        assertNull(settings.pausedUntil(now))
    }

    /** A row, or one company's rows, is allowed in one app until blocked again; another app keeps it blocked. */
    @Test
    fun rowsAreAllowedInOneAppUntilBlockedAgain() {
        settings.allowEntries("com.example.game", listOf("graph.facebook.com", "m.facebook.com"))
        settings.allowEntries("com.example.other", listOf("app-measurement.com"))
        assertEquals(
            setOf("com.example.game" to "graph.facebook.com", "com.example.game" to "m.facebook.com", "com.example.other" to "app-measurement.com"),
            settings.entriesAllowed(),
        )
        // No time ends them, however late.
        settings.appsAllowed(now + 100 * hour)
        assertEquals(3, settings.entriesAllowed().size)
        settings.blockEntriesAgain("com.example.game", listOf("graph.facebook.com", "m.facebook.com"))
        assertEquals(setOf("com.example.other" to "app-measurement.com"), settings.entriesAllowed())
        // An app's own "Block trackers again" leaves its rows' allowances as they are: each has its own undo.
        settings.allowApp("com.example.other", now)
        settings.blockAppAgain("com.example.other")
        assertEquals(setOf("com.example.other" to "app-measurement.com"), settings.entriesAllowed())
    }

    /** ADR 0047's wipe leaves nothing: blocking off, nothing allowed, no pause. */
    @Test
    fun theWipeLeavesNothing() {
        settings.on = true
        settings.allowApp("com.example.game", now)
        settings.allowEntries("com.example.game", listOf("app-measurement.com"))
        settings.pause(now)
        settings.wipe()
        assertTrue(store.values.isEmpty())
        assertFalse(settings.on)
        assertEquals(emptyMap<String, Long>(), settings.appsAllowed(now))
        assertNull(settings.pausedUntil(now))
    }

    /** The setting is handed whole, a line each, as the engine's `blocking_setting` reads it. */
    @Test
    fun theSettingIsHandedWhole() {
        val text = Handover.text(
            on = true,
            toolDns = false,
            pausedMs = 0,
            covered = listOf(10_456, 10_123),
            decided = mapOf(10_123 to mapOf("graph.facebook.com" to Grades.Decided.BLOCK), 10_456 to mapOf("graph.facebook.com" to Grades.Decided.EXCEPTED)),
            apps = mapOf(10_123 to 3_599_000L, 10_456 to 0L, 10_789 to null),
            entries = listOf(10_123 to "app-measurement.com", 10_123 to "app-measurement.com"),
        )
        assertEquals(
            listOf(
                "on 1", "tool-dns 0", "paused 0", "covered 10123 10456",
                "graded 10123 graph.facebook.com block", "graded 10456 graph.facebook.com keep",
                "allowed 10123 3599000", "allowed 10789 -", "entry 10123 app-measurement.com",
            ),
            text.lines(),
        )
        assertEquals(listOf("on 0", "tool-dns 1", "paused 600000", "covered"), Handover.text(false, true, 600_000, emptyList(), emptyMap(), emptyMap(), emptyList()).lines())
        // A code row kept, or never read, is kept for the engine too.
        val kept = Handover.text(true, false, 0, listOf(1), mapOf(1 to mapOf("a.example" to Grades.Decided.KEEP, "b.example" to Grades.Decided.NOT_READ)), emptyMap(), emptyList())
        assertTrue(kept.lines().containsAll(listOf("graded 1 a.example keep", "graded 1 b.example keep")))
    }

    /** What the engine counted reads back, lookups apart from connections; a line that is not one is skipped. */
    @Test
    fun theEnginesCountsReadBack() {
        val read = Tallies.parse("10123\tapp-measurement.com\t4\t2\t1800000000000\nbad\n10123\t\t1\t1\t1\n10456\tgraph.facebook.com\tx\t1\t1")
        assertEquals(listOf(Tallies.Tally(10_123, "app-measurement.com", 4, 2, 1_800_000_000_000)), read)
        assertEquals(emptyList<Tallies.Tally>(), Tallies.parse(""))
    }
}
