package org.visadahyu.datapavan.watch.log

import java.time.ZoneId

/**
 * The time as the connection log reads it: the moment, and the phone's time zone, both read anew each
 * time, since the user or the network can change either while Watch runs.
 */
interface LogClock {
    /** Milliseconds since 1970 (UTC). */
    fun now(): Long

    fun zone(): ZoneId

    /** The phone's own clock and time zone. */
    object Phone : LogClock {
        override fun now(): Long = System.currentTimeMillis()

        override fun zone(): ZoneId = ZoneId.systemDefault()
    }
}
