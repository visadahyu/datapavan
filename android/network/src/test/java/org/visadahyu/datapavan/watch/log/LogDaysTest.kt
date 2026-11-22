package org.visadahyu.datapavan.watch.log

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.time.LocalTime
import java.time.ZoneId

/**
 * The connection log files each record under the local day of its start (ADR 0037). The engine cuts every
 * record within one quarter hour of UTC (finding 4 of the independent review of 2026-11-09), so no record
 * crosses a change of the local date in any zone where every such change falls on a quarter hour of UTC:
 * the zone's offsets, which put its midnights there, and the instants at which it changes them alike
 * (review 1 of W5's first part, names, finding 5). These tests check that of every zone this runtime's
 * tzdata knows, since 2012 and by every zone's rules ahead, Kathmandu (+5:45), the Chatham Islands (+12:45
 * and +13:45) and Eucla (+8:45) included, and that the log files a batch in one zone when the zone changes
 * while it is written.
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

    /**
     * In every zone, every instant at which the local date changes falls on a quarter hour of UTC, from 2012
     * to 2100: every offset the zone uses then is a whole number of quarter hours, which puts its midnights
     * on one, and every change of offset that changes the local date falls on one. tzdata's own rules give
     * the changes ahead. Until 2010, Newfoundland's, Goose Bay's and Moncton's did not: they changed the
     * date at 02:31, 03:01 and 03:01 UTC.
     */
    @Test
    fun everyChangeOfTheLocalDateFallsOnAQuarterHourOfUtc() {
        val from = Instant.parse("2012-01-01T00:00:00Z")
        val until = Instant.parse("2100-01-01T00:00:00Z")
        val quarter = 15 * 60
        val off = mutableListOf<String>()
        var changes = 0
        for (zone in zones) {
            val rules = zone.rules
            if (rules.getOffset(from).totalSeconds % quarter != 0) off += "${zone.id} at $from"
            var transition = rules.nextTransition(from)
            while (transition != null && transition.instant.isBefore(until)) {
                val at = transition.instant
                if (transition.offsetAfter.totalSeconds % quarter != 0) off += "${zone.id}: ${transition.offsetAfter} from $at"
                val before = at.minusNanos(1).atOffset(transition.offsetBefore).toLocalDate()
                val after = at.atOffset(transition.offsetAfter).toLocalDate()
                if (before != after) {
                    changes++
                    if (at.epochSecond % quarter != 0L) off += "${zone.id}: the date changes at $at"
                }
                transition = rules.nextTransition(at)
            }
        }
        assertEquals(emptyList<String>(), off)
        assertTrue("this runtime knows only ${zones.size} zones", zones.size > 400)
        assertTrue("no change of offset changed a date: $changes", changes > 0)
    }

    /** The engine's own cuts, around Kathmandu's, the Chatham Islands' and Eucla's midnights, each lie within one local day of every zone. */
    @Test
    fun noRecordOfTheEngineCrossesAChangeOfTheLocalDateInAnyZone() {
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
     * The zone changes between batches, as on a journey or when the user sets it: the log files each batch
     * ([ConnectionLog.file], as `writeNow` does) by the zone the clock reads when it is written, and each
     * record lies within that zone's day.
     */
    @Test
    fun aZoneChangedBetweenBatchesFilesEachRecordWithinOneDayOfItsZone() {
        val journey = listOf(
            "Asia/Kathmandu", "Pacific/Chatham", "Australia/Eucla", "America/St_Johns", "Australia/Lord_Howe",
            "Asia/Tehran", "Pacific/Kiritimati", "Africa/Monrovia", "Europe/Istanbul",
        ).map(ZoneId::of)
        val clock = Travel(journey[0])
        for ((i, written) in EngineRecords.records.withIndex()) {
            clock.zone = journey[i % journey.size]
            val (record, bytes) = written
            val batch = ByteBuffer.allocate(4 + 2 + bytes.size).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(1).putShort(bytes.size.toShort()).put(bytes).array()
            val filed = ConnectionLog.file(batch, clock, Long.MIN_VALUE, pastRetention = false) {}
            assertEquals(1, filed.size)
            val day = filed[0].day
            assertEquals(Instant.ofEpochMilli(record.start).atZone(clock.zone).toLocalDate().toEpochDay(), day)
            assertTrue("${record.start}..${record.end} filed in ${clock.zone}", clock.withinItsDay(record.start, record.end))
            assertEquals(day, clock.dayOf(maxOf(record.start, record.end - 1)))
        }
    }

    /**
     * The zone changes while a batch is written ([ConnectionLog.file], which `writeNow` files every batch
     * with): the batch is filed in the zone read once at its start, so that no record of it goes under a
     * day whose key the batch did not draw. Here the clock gives another zone at each reading.
     */
    @Test
    fun aBatchIsFiledInTheOneZoneReadAsItIsWritten() {
        val journey = listOf("Pacific/Chatham", "Pacific/Kiritimati", "Asia/Kathmandu", "America/St_Johns").map(ZoneId::of)
        val clock = object : LogClock {
            var read = 0

            override fun now(): Long = 0

            override fun zone(): ZoneId = journey[read++ % journey.size]
        }
        var skipped = 0
        val filed = ConnectionLog.file(EngineRecords.batch, clock, Long.MIN_VALUE, pastRetention = false) { skipped++ }
        assertEquals(1, clock.read)
        assertEquals(0, skipped)
        assertEquals(EngineRecords.records.size, filed.size)
        for ((record, _, day) in filed) {
            assertEquals(Instant.ofEpochMilli(record.start).atZone(journey[0]).toLocalDate().toEpochDay(), day)
        }
        // Days before the first kept are left out, unless kept by hand.
        val first = filed.maxOf { it.day }
        val kept = ConnectionLog.file(EngineRecords.batch, LogClock.Phone, first, pastRetention = false) {}
        assertTrue(kept.all { LogClock.Phone.dayOf(it.record.start) >= first })
        assertEquals(EngineRecords.records.size, ConnectionLog.file(EngineRecords.batch, LogClock.Phone, Long.MAX_VALUE, pastRetention = true) {}.size)
    }
}
