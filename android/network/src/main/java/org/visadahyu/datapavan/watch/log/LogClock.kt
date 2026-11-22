package org.visadahyu.datapavan.watch.log

import java.time.Instant
import java.time.ZoneId

/**
 * The time as the connection log reads it: the moment, and the phone's time zone, both read anew each
 * time, since the user or the network can change either while Watch runs. Android sets the zone anew in
 * every running process when it changes (`ACTION_TIMEZONE_CHANGED`, which resets Java's default zone), so
 * the next record is filed in the new one.
 */
interface LogClock {
    /** Milliseconds since 1970 (UTC). */
    fun now(): Long

    fun zone(): ZoneId

    /**
     * The local day of [millis] in [zone], as days since 1970. The engine cuts every record within one
     * quarter hour of UTC (core/net/src/engine/logbook.rs), and in every zone every change of the local
     * date falls on a quarter hour of UTC, the zone's offsets and the instants it changes them alike (since
     * 2011, by every zone's rules ahead: `LogDaysTest`), so a record filed by the day of its start lies
     * within that day, in any zone.
     */
    fun dayOf(millis: Long, zone: ZoneId = zone()): Long = Instant.ofEpochMilli(millis).atZone(zone).toLocalDate().toEpochDay()

    /** The phone's own clock and time zone. */
    object Phone : LogClock {
        override fun now(): Long = System.currentTimeMillis()

        override fun zone(): ZoneId = ZoneId.systemDefault()
    }
}
