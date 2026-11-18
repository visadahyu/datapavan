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

    /**
     * What one reading knows, and its events: without usage access, nothing ([States.NO_ACCESS]); before
     * the user's first unlock, nothing either ([States.LOCKED]); else the events `query` gives. Android
     * gives an app an empty record in both cases rather than none, so access is asked again after a query
     * that found nothing, as when it was taken away meanwhile (review b1 of W5's second part, Kotlin,
     * finding 3; review b2, N6: no test held it).
     */
    fun <E> know(access: () -> Boolean, unlocked: () -> Boolean, query: () -> List<E>?): Pair<Int, List<E>> {
        if (!access()) return States.NO_ACCESS to emptyList()
        if (!unlocked()) return States.LOCKED to emptyList()
        val events = query() ?: return States.NO_ACCESS to emptyList()
        if (events.isEmpty() && !access()) return States.NO_ACCESS to emptyList()
        return States.KNOWN to events
    }

    /** A little past the margin, for the screen-off event to be in Android's record. */
    private const val SCREEN_OFF_SLACK_MS = 500L
}

/**
 * When the tracker's next reading waiting for its turn is made, by elapsed time: an ask too soon waits, the
 * soonest of those asked for is kept, and a reading made serves them all (review b2 of W5's second part,
 * N6: the tracker's scheduling had no test).
 */
internal class Turns {
    /** When the reading waiting is due, null for none. */
    var due: Long? = null
        private set

    /**
     * An ask at `now`, for a reading `wait` from now: 0 to read at once; else how long to wait, when the
     * reading waiting comes later or none waits; null when the one waiting comes as soon.
     */
    fun ask(now: Long, wait: Long): Long? {
        if (wait <= 0) return 0
        val at = now + wait
        val waiting = due
        if (waiting != null && waiting <= at) return null
        due = at
        return wait
    }

    /** A reading is made: none waits any more. */
    fun read() {
        due = null
    }
}

/**
 * Each package's UID, read once per reading: a package removed and installed again gets a new UID in the
 * same boot, which a cache kept longer would miss (review b1 of W5's second part, Kotlin, finding 4).
 */
internal class Uids(private val lookup: (String) -> Int?) {
    private val known = HashMap<String, Int?>()

    /** A new reading's lookup: every UID is read again for it. */
    fun forReading(): (String) -> Int? {
        known.clear()
        return ::get
    }

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
