package org.visadahyu.datapavan.watch.log

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.LocalTime
import java.time.ZoneId
import java.time.ZoneOffset

/**
 * The connection log files each record under the local day of its start (ADR 0037). The engine cuts every
 * record at the quarter hours of UTC (finding 4 of the independent review of 2026-11-09), so no record
 * crosses a local midnight in any zone that is a whole number of quarter hours from UTC: every zone this
 * runtime's tzdata knows, which these tests check, Kathmandu (+5:45), the Chatham Islands (+12:45 and
 * +13:45) and Eucla (+8:45) included, also when the zone changes while Watch runs.
 */
class LogDaysTest {
    private val zones = ZoneId.getAvailableZoneIds().sorted().map(ZoneId::of)

    /** The fixture's records, as (start, end). */
    private val spans = EngineRecords.records.map { (record, _) -> record.start to record.end }

    /** A clock whose zone the test changes, as the user or a journey does. */
    private class Travel(var zone: ZoneId) : LogClock {
        override fun now(): Long = 0

        override fun zone(): ZoneId = zone
    }

    /** Whether a record from [start] to [end] (its end not in it) lies within the local day of its start. */
    private fun LogClock.withinItsDay(start: Long, end: Long, zone: ZoneId = zone()) =
        dayOf(start, zone) == dayOf(maxOf(start, end - 1), zone)

    /** Every offset each zone has used since 1980, and will by its rules, is a whole number of quarter hours. */
    @Test
    fun everyZoneIsAWholeNumberOfQuarterHoursFromUtc() {
        val since = Instant.parse("1980-01-01T00:00:00Z")
        val odd = mutableListOf<String>()
        for (zone in zones) {
            val rules = zone.rules
            val offsets = mutableListOf<ZoneOffset>(rules.getOffset(Instant.now()), rules.getOffset(since))
            for (transition in rules.transitions.filter { !it.instant.isBefore(since) }) {
                offsets += transition.offsetBefore
                offsets += transition.offsetAfter
            }
            for (rule in rules.transitionRules) {
                offsets += rule.offsetBefore
                offsets += rule.offsetAfter
                offsets += rule.standardOffset
            }
            if (offsets.any { it.totalSeconds % (15 * 60) != 0 }) odd += zone.id
        }
        assertEquals(emptyList<String>(), odd)
        assertTrue("this runtime knows only ${zones.size} zones", zones.size > 400)
    }

    /** The engine's own cuts, around Kathmandu's, the Chatham Islands' and Eucla's midnights, each lie within one local day of every zone. */
    @Test
    fun noRecordOfTheEngineCrossesALocalMidnightOfAnyZone() {
        val clock = Travel(ZoneId.of("UTC"))
        for (zone in zones) {
            for ((start, end) in spans) assertTrue("$start..$end in ${zone.id}", clock.withinItsDay(start, end, zone))
        }
        // Each zone's midnight ends one segment of the fixture and begins the next.
        for ((zone, at) in listOf("Asia/Kathmandu" to 4, "Pacific/Chatham" to 6, "Australia/Eucla" to 8)) {
            val (before, after) = spans[at] to spans[at + 1]
            assertEquals(before.second, after.first)
            assertEquals(LocalTime.MIDNIGHT, Instant.ofEpochMilli(after.first).atZone(ZoneId.of(zone)).toLocalTime())
            assertEquals(clock.dayOf(before.first, ZoneId.of(zone)) + 1, clock.dayOf(after.first, ZoneId.of(zone)))
        }
    }

    /**
     * The zone changes while Watch runs, between one record and the next, as on a journey or when the user
     * sets it: each record is filed by the zone the clock reads when it is written, and lies within that
     * zone's day.
     */
    @Test
    fun aZoneChangedWhileWatchRunsFilesEachRecordWithinOneDayOfItsZone() {
        val journey = listOf(
            "Asia/Kathmandu", "Pacific/Chatham", "Australia/Eucla", "America/St_Johns", "Australia/Lord_Howe",
            "Asia/Tehran", "Pacific/Kiritimati", "Africa/Monrovia", "Europe/Istanbul",
        ).map(ZoneId::of)
        val clock = Travel(journey[0])
        for ((i, span) in spans.withIndex()) {
            clock.zone = journey[i % journey.size]
            val (start, end) = span
            assertTrue("$start..$end filed in ${clock.zone}", clock.withinItsDay(start, end))
            assertEquals(Instant.ofEpochMilli(start).atZone(clock.zone).toLocalDate().toEpochDay(), clock.dayOf(start))
        }
    }
}
