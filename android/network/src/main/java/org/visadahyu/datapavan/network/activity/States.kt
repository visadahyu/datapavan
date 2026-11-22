package org.visadahyu.datapavan.network.activity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * A reading of the apps' states as Watch hands it to the engine ([org.visadahyu.datapavan.network.Engine.nativeStates];
 * core/net/src/states.rs, version 2, little-endian): version, the span's start and end in milliseconds
 * since 1970, what is known over it ([KNOWN], [NO_ACCESS], [LOCKED]), the screen at its end (0 off, 1 on,
 * 2 not known), when it last came on (0 not known, and always 0 for a screen not on, which the engine
 * refuses otherwise) and when it last went off (0 not known, and always 0 for a screen not known or, for
 * one on, after it came on, which the engine refuses too), then the count of intervals and each: UID, start,
 * end, state ([IN_USE], [NOTIFICATION]). An app with no interval in a known span was in the background
 * throughout. UIDs, times and states only: nothing names a destination.
 */
object States {
    const val VERSION: Byte = 2

    const val IN_USE = 1
    const val NOTIFICATION = 2

    const val KNOWN = 0
    const val NO_ACCESS = 1
    const val LOCKED = 2

    private const val HEAD = 1 + 8 + 8 + 1 + 1 + 8 + 8 + 4
    private const val INTERVAL = 4 + 8 + 8 + 1

    /** A reading in its stored form. */
    fun encode(from: Long, until: Long, known: Int, screen: UsageStates.Screen, intervals: List<UsageStates.Interval>): ByteArray {
        val out = ByteBuffer.allocate(HEAD + intervals.size * INTERVAL).order(ByteOrder.LITTLE_ENDIAN)
            .put(VERSION).putLong(from).putLong(until).put(known.toByte())
            .put(
                when (screen.on) {
                    false -> 0
                    true -> 1
                    null -> 2
                }.toByte(),
            )
            .putLong(if (screen.on == true) screen.since ?: 0 else 0)
            .putLong(offSince(screen) ?: 0)
            .putInt(intervals.size)
        for (interval in intervals) {
            out.putInt(interval.uid).putLong(interval.from).putLong(interval.until).put(interval.state.toByte())
        }
        return out.array()
    }

    /**
     * When the screen went off, as the engine takes it: for a screen off, and for one on since a moment told,
     * not after it (as events within one millisecond could have it); never for one on since a moment not
     * known, for which the engine would open a window running while the screen is on (review c1, engine, nit 6).
     */
    internal fun offSince(screen: UsageStates.Screen): Long? = screen.offSince?.takeIf {
        screen.on == false || (screen.on == true && screen.since != null && it <= screen.since)
    }

    /** A reading that knows the states: its intervals. */
    fun encode(reading: UsageStates.Reading): ByteArray =
        encode(reading.from, reading.until, KNOWN, reading.screen, reading.intervals)
}
