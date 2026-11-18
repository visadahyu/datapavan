package org.visadahyu.datapavan.watch.activity

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
        assertEquals(10_200, uids["a"])
        installed = 10_250
        assertEquals(10_200, uids["a"])
        uids.newReading()
        assertEquals(10_250, uids["a"])
        assertEquals(null, uids["gone"])
    }
}
