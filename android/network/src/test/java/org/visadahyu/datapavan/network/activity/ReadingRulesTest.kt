package org.visadahyu.datapavan.network.activity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The tracker's reading rates and its rule for a clock set back (ADR 0046, decision 1), at their edges. */
class ReadingRulesTest {
    /** One reading every 5 seconds with the screen on and one a minute with it off; an ask too soon waits for its turn. */
    @Test
    fun readingsKeepTheirRates() {
        assertEquals(5_000L, ReadingRules.SCREEN_ON_EVERY_MS)
        assertEquals(60_000L, ReadingRules.SCREEN_OFF_EVERY_MS)
        val last = 1_000_000L
        assertEquals(0L, ReadingRules.wait(last + 5_000, last, screenOn = true))
        assertEquals(1L, ReadingRules.wait(last + 4_999, last, screenOn = true))
        assertEquals(5_000L, ReadingRules.wait(last, last, screenOn = true))
        assertEquals(0L, ReadingRules.wait(last + 60_000, last, screenOn = false))
        assertEquals(1L, ReadingRules.wait(last + 59_999, last, screenOn = false))
        assertEquals(55_000L, ReadingRules.wait(last + 5_000, last, screenOn = false))
        assertEquals(0L, ReadingRules.wait(last + 3_600_000, last, screenOn = false))
    }

    /** The screen turning off reads once past the margin, no sooner than the rate with the screen on allows. */
    @Test
    fun theScreenTurningOffReadsOncePastTheMargin() {
        val last = 1_000_000L
        assertEquals(UsageStates.MARGIN_MS + 500, ReadingRules.screenOffWait(last + 60_000, last))
        assertEquals(UsageStates.MARGIN_MS + 500, ReadingRules.screenOffWait(last + 2_500, last))
        assertEquals(4_000L, ReadingRules.screenOffWait(last + 1_000, last))
    }

    /** A wall clock a second or more behind the time since the last reading was set back; less, or ahead, was not. */
    @Test
    fun aClockSetBackIsASecondOrMoreBehind() {
        val wall = 1_794_953_400_000L
        assertFalse(ReadingRules.setBack(null, 0, wall, 10_000))
        assertFalse(ReadingRules.setBack(wall, 0, wall + 10_000, 10_000))
        assertFalse(ReadingRules.setBack(wall, 0, wall + 9_001, 10_000))
        assertTrue(ReadingRules.setBack(wall, 0, wall + 9_000, 10_000))
        assertTrue(ReadingRules.setBack(wall, 0, wall - 3_600_000, 10_000))
        assertFalse(ReadingRules.setBack(wall, 0, wall + 3_600_000, 10_000))
    }

    /** Each reading reads the UIDs again: a package installed again with a new UID is seen at the next. */
    @Test
    fun eachReadingReadsTheUidsAgain() {
        var installed = 10_200
        val uids = Uids { if (it == "a") installed else null }
        val first = uids.forReading()
        assertEquals(10_200, first("a"))
        installed = 10_250
        assertEquals("kept within a reading", 10_200, first("a"))
        val next = uids.forReading()
        assertEquals(10_250, next("a"))
        assertEquals(null, next("gone"))
    }

    /** Each reading reads the notification grants again: one the user gave or took back is seen at the next. */
    @Test
    fun eachReadingReadsTheGrantsAgain() {
        var allowed = false
        val grants = Grants { it == "a" && allowed }
        val first = grants.forReading()
        assertFalse(first("a"))
        allowed = true
        assertFalse("kept within a reading", first("a"))
        assertTrue(grants.forReading()("a"))
    }

    /**
     * What a reading knows: nothing without access or before the first unlock, without asking Android for
     * events; the events otherwise; and nothing when the query found none and access was taken away
     * meanwhile (review b2 of W5's second part, N6).
     */
    @Test
    fun aReadingKnowsTheStatesOnlyWithAccessAndOnceUnlocked() {
        var queried = 0
        fun query(events: List<Int>?): () -> List<Int>? = { queried++; events }
        assertEquals(States.NO_ACCESS to emptyList<Int>(), ReadingRules.know({ false }, { true }, query(listOf(1))))
        assertEquals(States.LOCKED to emptyList<Int>(), ReadingRules.know({ true }, { false }, query(listOf(1))))
        assertEquals(0, queried)
        assertEquals(States.KNOWN to listOf(1), ReadingRules.know({ true }, { true }, query(listOf(1))))
        assertEquals(States.NO_ACCESS to emptyList<Int>(), ReadingRules.know({ true }, { true }, query(null)))
        assertEquals(States.KNOWN to emptyList<Int>(), ReadingRules.know({ true }, { true }, query(emptyList())))
        var asked = 0
        val taken = { asked++ == 0 }
        assertEquals(States.NO_ACCESS to emptyList<Int>(), ReadingRules.know(taken, { true }, query(emptyList())))
        assertEquals("access asked again after an empty query", 2, asked)
    }

    /**
     * A reading asked for too soon waits for its turn; the soonest of those asked for is kept; one made serves
     * them all (review b2 of W5's second part, N6).
     */
    @Test
    fun readingsWaitForTheirTurnAndTheSoonestIsKept() {
        val turns = Turns()
        assertEquals(0L, turns.ask(1_000, 0))
        assertEquals(null, turns.due)
        assertEquals(55_000L, turns.ask(1_000, 55_000))
        assertEquals(56_000L, turns.due)
        assertEquals("a later one waits for the one already waiting", null, turns.ask(2_000, 60_000))
        assertEquals("a sooner one, as at screen off, takes its place", 3_000L, turns.ask(10_000, 3_000))
        assertEquals(13_000L, turns.due)
        turns.read()
        assertEquals(null, turns.due)
        assertEquals(5_000L, turns.ask(14_000, 5_000))
    }
}
