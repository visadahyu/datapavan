package org.visadahyu.datapavan.watch.activity

/**
 * When [StateTracker] reads the usage events (ADR 0046, decision 1), as pure functions of the phone's
 * elapsed time ([android.os.SystemClock.elapsedRealtime]) and the wall clock, so that the JVM tests hold
 * the rates that are its battery promise and the trigger of its rule for a clock set back (review b1 of
 * W5's second part, Kotlin, finding 5).
 */
internal object ReadingRules {
    /** At most one reading every 5 seconds with the screen on, and one a minute with it off. */
    const val SCREEN_ON_EVERY_MS = 5_000L
    const val SCREEN_OFF_EVERY_MS = 60_000L

    /** A wall clock this far behind the time since the last reading, or more, was set back. */
    const val SET_BACK_MS = 1_000L

    /**
     * How long after `now` a reading the engine asked for may be made, the last having begun at `lastRead`:
     * 0 when it may be made now. An ask that comes too soon waits for its turn rather than being dropped, so
     * that what the engine holds is placed within a reading's period even when no traffic asks again.
     */
    fun wait(now: Long, lastRead: Long, screenOn: Boolean): Long {
        val every = if (screenOn) SCREEN_ON_EVERY_MS else SCREEN_OFF_EVERY_MS
        return (lastRead + every - now).coerceAtLeast(0)
    }

    /**
     * How long after the screen turned off, at `now`, its last reading is made: once the moment it turned off
     * is past the margin the readings leave for events not reported yet, and no sooner than the rate with the
     * screen on allows, so that what was sent while it was on is placed then and not a minute later.
     */
    fun screenOffWait(now: Long, lastRead: Long): Long =
        maxOf(UsageStates.MARGIN_MS + SCREEN_OFF_SLACK_MS, lastRead + SCREEN_ON_EVERY_MS - now)

    /**
     * Whether the wall clock was set back between two readings: it reads `wall` at `elapsed`, where the last
     * read `lastWall` at `lastElapsed`, and is behind by [SET_BACK_MS] or more.
     */
    fun setBack(lastWall: Long?, lastElapsed: Long, wall: Long, elapsed: Long): Boolean =
        lastWall != null && wall + SET_BACK_MS <= lastWall + (elapsed - lastElapsed)

    /** A little past the margin, for the screen-off event to be in Android's record. */
    private const val SCREEN_OFF_SLACK_MS = 500L
}

/**
 * Each package's UID, read once per reading: a package removed and installed again gets a new UID in the
 * same boot, which a cache kept longer would miss (review b1 of W5's second part, Kotlin, finding 4).
 */
internal class Uids(private val lookup: (String) -> Int?) {
    private val known = HashMap<String, Int?>()

    /** A new reading: every UID is read again. */
    fun newReading() = known.clear()

    /** The package's UID, null for one not installed. */
    operator fun get(packageName: String): Int? = known.getOrPut(packageName) {
        if (known.size >= MAX_PACKAGES) known.clear()
        lookup(packageName)
    }

    private companion object {
        /** At most this many packages' UIDs are kept within one reading; past it the list starts anew. */
        const val MAX_PACKAGES = 1_024
    }
}
