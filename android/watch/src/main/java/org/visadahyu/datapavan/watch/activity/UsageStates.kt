package org.visadahyu.datapavan.watch.activity

/**
 * The apps' states from Android's usage events (ADR 0046, decision 1), as a pure function of the events
 * read, so that the JVM tests drive it with synthetic sequences ([StateTracker] reads the events on the
 * phone). Each app, by UID, is:
 *
 * - **in use** while an activity of it, or of any package sharing its UID, is resumed or visible, or the
 *   user interacted with it, and for [grace] after: an activity is visible from its `ACTIVITY_RESUMED` to
 *   its `ACTIVITY_STOPPED` (paused but not stopped, as beside another in split screen, it is still
 *   visible), while the screen is interactive, and while the lock screen is not shown unless the activity
 *   was resumed over it; several apps can be in use at once. The default keyboard counts as in use while
 *   the screen is interactive, since it may be shown (decision 5);
 * - an activity is known by its package and class only, since Android keeps the instance to itself: a
 *   `STOPPED` that comes after a `RESUMED` of the same class that itself followed a `PAUSED`, with no
 *   `PAUSED` since, is the stop of another instance, as when a second instance of one screen opens over the
 *   first or Back returns to it, and ends nothing (review b1 of W5's second part, Kotlin, finding 1);
 * - **with its notification** from a `FOREGROUND_SERVICE_START` of it to its `FOREGROUND_SERVICE_STOP`;
 * - **in the background** otherwise.
 *
 * `DEVICE_SHUTDOWN` and `DEVICE_STARTUP` end every open interval. Each reading covers the events from
 * [queryFrom], [LATE_MS] before the end of the last: an event that arrives late, or out of order, within
 * that overlap places its moment again, and the reading tells the engine from there, which places again
 * what it still holds; one later than that is not read. A wall clock set back starts the readings anew
 * from the moment it was found ([clockSetBack]), carrying what is open.
 */
class UsageStates(
    /** How long after the user leaves an app it still counts as in use: an upload that finishes then is theirs. */
    private val grace: Long = GRACE_MS,
) {
    /** One usage event: its time (milliseconds since 1970), kind, package and, for activities and services, class. */
    data class Event(val time: Long, val kind: Kind, val packageName: String, val className: String? = null)

    /** The kinds of event read (UsageEvents.Event), all in API 29. */
    enum class Kind {
        RESUMED, PAUSED, STOPPED, SERVICE_START, SERVICE_STOP, INTERACTION,
        SCREEN_ON, SCREEN_OFF, KEYGUARD_SHOWN, KEYGUARD_HIDDEN, SHUTDOWN, STARTUP,
    }

    /** One interval of an app's state that is not the background: [States.IN_USE] or [States.NOTIFICATION]. */
    data class Interval(val uid: Int, val from: Long, val until: Long, val state: Int)

    /** The screen at the end of a reading: on, off or not known, and when it last came on, if known. */
    data class Screen(val on: Boolean?, val since: Long?)

    /** What a reading tells the engine: the states over a span of the wall clock. */
    data class Reading(val from: Long, val until: Long, val intervals: List<Interval>, val screen: Screen)

    /** What is carried from one reading to the next, as of [time]: every event before it applied. */
    private data class Base(
        val time: Long,
        /** Activities resumed and not stopped, and those paused a moment ago, by package and class. */
        val activities: Map<Pair<String, String?>, Activity>,
        /** Foreground services started and not stopped, with when each started. */
        val services: Map<Pair<String, String?>, Long>,
        val screenOn: Boolean?,
        val screenOnSince: Long?,
        /** Whether the lock screen is shown, and since when. */
        val keyguard: Boolean,
        val keyguardSince: Long,
        /** The last moment each app was in use, before [time], for the grace. */
        val lastInUse: Map<Int, Long>,
    )

    /**
     * One activity class of a package: when it was last resumed, null while it is not open; whether it was
     * paused since; whether that resume followed a pause, so that a stop with no pause since is another
     * instance's; and the time of its last event.
     */
    private data class Activity(val resumedAt: Long?, val paused: Boolean, val reopened: Boolean, val at: Long)

    private var base: Base? = null

    /**
     * The events at or after the base's time, in time order and, within one millisecond, in the order
     * Android gave them, for readings to place again (review b1, Kotlin, finding 1: a rotation whose new
     * instance resumes in the millisecond the old one stopped).
     */
    private val pending = mutableListOf<Event>()

    /** Where the next reading tells the engine from: the end of the last one told, after its overlap. */
    private var toldUntil: Long? = null

    /** Where a reading after a clock set back begins: events before it are of the old clock. */
    private var floor = Long.MIN_VALUE

    /** Where the next query of events begins, `now` being the wall clock. */
    fun queryFrom(now: Long): Long = maxOf(base?.time ?: (now - LOOKBACK_MS), floor)

    /**
     * Places the events of one reading, ending at `until` (the wall clock, less [MARGIN_MS] for events not
     * reported yet): `events` in any order, those seen before included; `uidOf` names a package's UID, null
     * for one no longer installed; `keyboard` is the default keyboard's UID. The states from the start of
     * the overlap, or from `startedAt` on a first reading, to `until`.
     */
    fun read(events: Collection<Event>, until: Long, uidOf: (String) -> Int?, keyboard: Int?, startedAt: Long): Reading {
        val start = base ?: Base(
            time = queryFrom(until),
            activities = emptyMap(), services = emptyMap(), screenOn = null, screenOnSince = null,
            keyguard = false, keyguardSince = Long.MIN_VALUE, lastInUse = emptyMap(),
        )
        add(events.filter { it.time >= maxOf(start.time, floor) && it.time < until })
        // From the overlap with the last reading, or the end of what was told before, or the start.
        val from = minOf(until, maxOf(floor, if (base != null) start.time else toldUntil ?: startedAt))
        val run = Run(start, uidOf, keyboard)
        // Everything up to `until`; the base moves to the start of the next overlap.
        val keep = until - LATE_MS
        var moved: Base? = null
        for (event in pending) {
            if (event.time >= until) break
            if (moved == null && event.time >= keep) moved = run.snapshot(maxOf(keep, start.time))
            run.apply(event)
        }
        val next = moved ?: run.snapshot(maxOf(keep, start.time))
        val intervals = run.finish(until, from)
        pending.removeAll { it.time < next.time }
        base = next
        toldUntil = until
        return Reading(from, until, intervals, Screen(run.screenOn, run.screenOnSince))
    }

    /**
     * Adds the events read to [pending], each once: an event read again, as in the overlap, is the one
     * already there, matched by its fields, as many times as it came; the new ones follow those of their
     * millisecond, in the order read.
     */
    private fun add(read: List<Event>) {
        val seen = HashMap<Event, Int>()
        for (event in pending) seen[event] = (seen[event] ?: 0) + 1
        val new = read.filter { event ->
            val left = seen[event] ?: 0
            if (left > 0) seen[event] = left - 1
            left == 0
        }
        if (new.isEmpty()) return
        val all = (pending + new).sortedBy { it.time }
        pending.clear()
        pending += all
    }

    /**
     * Nothing is known up to `until`, as without usage access or before the first unlock: the reading to
     * tell, from the end of the last; the next with events rebuilds what is open from [LOOKBACK_MS] back.
     */
    fun nothing(until: Long, startedAt: Long): Pair<Long, Long> {
        val from = maxOf(toldUntil ?: startedAt, floor).coerceAtMost(until)
        base = null
        pending.clear()
        toldUntil = until
        return from to until
    }

    /**
     * The engine did not take the last reading, as in the moment the tunnel is set up again: the next
     * reading reads back a day afresh and tells from `toldUntil`, the end of the last one it took.
     */
    fun untold(toldUntil: Long?) {
        base = null
        pending.clear()
        this.toldUntil = toldUntil
    }

    /**
     * The wall clock was set back, found at `at` on the new clock: what is open is carried, as of `at`,
     * every event read so far applied; readings begin at `at`, and events before it, of the old clock or
     * the moment between, are not read.
     */
    fun clockSetBack(at: Long, uidOf: (String) -> Int?, keyboard: Int?) {
        floor = at
        toldUntil = at
        val start = base ?: return
        val run = Run(start, uidOf, keyboard)
        for (event in pending) run.apply(event)
        val carried = run.snapshot(Long.MAX_VALUE)
        // Times of the old clock later than `at` become `at`, but an activity resumed before the lock screen
        // showed stays before it, so that it stays hidden under it.
        val keyguardSince = minOf(carried.keyguardSince, at)
        base = carried.copy(
            time = at,
            activities = carried.activities.mapValues { (_, a) ->
                val resumedAt = a.resumedAt?.let { r ->
                    if (carried.keyguard && r < carried.keyguardSince) minOf(r, keyguardSince - 1) else minOf(r, at)
                }
                a.copy(resumedAt = resumedAt, at = minOf(a.at, at))
            },
            services = carried.services.mapValues { minOf(it.value, at) },
            screenOnSince = carried.screenOnSince?.let { minOf(it, at) },
            keyguardSince = keyguardSince,
            lastInUse = carried.lastInUse.mapValues { minOf(it.value, at) },
        )
        pending.clear()
    }

    /** One pass over the events from a base: the state as each applies, and the intervals it makes. */
    private inner class Run(start: Base, private val uidOf: (String) -> Int?, private val keyboard: Int?) {
        private val activities = start.activities.toMutableMap()
        private val services = start.services.toMutableMap()
        var screenOn = start.screenOn
        var screenOnSince = start.screenOnSince
        private var keyguard = start.keyguard
        private var keyguardSince = start.keyguardSince
        private val lastInUse = start.lastInUse.toMutableMap()
        private var now = start.time

        /** The apps visible and with a service now, and since when; and the keyboard, shown or not. */
        private val visibleSince = mutableMapOf<Int, Long>()
        private val servingSince = mutableMapOf<Int, Long>()
        private var keyboardSince: Long? = null
        private val visible = mutableListOf<Interval>()
        private val interactions = mutableListOf<Interval>()
        private val serving = mutableListOf<Interval>()
        private val keyboardShown = mutableListOf<Interval>()

        init {
            update()
        }

        /** Whether the screen shows anything: interactive, or not known to be off. */
        private fun screen() = screenOn != false

        private fun visibleUids(): Set<Int> = buildSet {
            if (screen()) {
                for ((key, activity) in activities) {
                    val resumedAt = activity.resumedAt ?: continue
                    if (!keyguard || resumedAt >= keyguardSince) uidOf(key.first)?.let(::add)
                }
            }
        }

        private fun servingUids(): Set<Int> = services.keys.mapNotNull { uidOf(it.first) }.toSet()

        /** Notes which apps became visible or not, and served or not, at [now]. */
        private fun update() {
            val shown = visibleUids()
            for (uid in visibleSince.keys - shown) {
                visible += Interval(uid, visibleSince.getValue(uid), now, States.IN_USE)
                lastInUse[uid] = now
                visibleSince.remove(uid)
            }
            for (uid in shown - visibleSince.keys) visibleSince[uid] = now
            val served = servingUids()
            for (uid in servingSince.keys - served) {
                serving += Interval(uid, servingSince.getValue(uid), now, States.NOTIFICATION)
                servingSince.remove(uid)
            }
            for (uid in served - servingSince.keys) servingSince[uid] = now
            if (keyboard != null) {
                val since = keyboardSince
                if (screen() && since == null) keyboardSince = now
                if (!screen() && since != null) {
                    keyboardShown += Interval(keyboard, since, now, States.IN_USE)
                    keyboardSince = null
                }
            }
        }

        fun apply(event: Event) {
            now = maxOf(now, event.time)
            val key = event.packageName to event.className
            when (event.kind) {
                Kind.RESUMED -> activities[key] =
                    Activity(event.time, paused = false, reopened = activities[key]?.paused == true, at = event.time)
                Kind.PAUSED -> activities[key] =
                    activities[key]?.copy(paused = true, at = event.time) ?: Activity(null, paused = true, reopened = false, at = event.time)
                Kind.STOPPED -> {
                    val open = activities[key]
                    if (open?.resumedAt != null && !open.paused && open.reopened) {
                        // Another instance's stop: the one resumed after the pause stays.
                        activities[key] = open.copy(reopened = false, at = event.time)
                    } else {
                        activities.remove(key)
                    }
                }
                Kind.SERVICE_START -> services[key] = event.time
                Kind.SERVICE_STOP -> services.remove(key)
                Kind.INTERACTION -> uidOf(event.packageName)?.let { uid ->
                    interactions += Interval(uid, event.time, event.time, States.IN_USE)
                    lastInUse[uid] = maxOf(lastInUse[uid] ?: Long.MIN_VALUE, event.time)
                }
                Kind.SCREEN_ON -> {
                    screenOn = true
                    screenOnSince = event.time
                }
                Kind.SCREEN_OFF -> screenOn = false
                Kind.KEYGUARD_SHOWN -> {
                    keyguard = true
                    keyguardSince = event.time
                }
                Kind.KEYGUARD_HIDDEN -> keyguard = false
                Kind.SHUTDOWN, Kind.STARTUP -> {
                    activities.clear()
                    services.clear()
                    keyguard = false
                }
            }
            update()
        }

        /**
         * What is carried from here, as of `time`, what the grace no longer reaches from it dropped. The apps
         * visible now need no more: the next pass finds them visible from its start.
         */
        fun snapshot(time: Long): Base {
            val inUse = lastInUse.filterValues { it + grace > time }
            // A pause not followed by a resume yet is kept for as long as a reading reads again.
            val kept = activities.filterValues { it.resumedAt != null || it.at >= time - LATE_MS }
            return Base(time, kept, services.toMap(), screenOn, screenOnSince, keyguard, keyguardSince, inUse)
        }

        /**
         * The intervals from `from` to `until`: in use while visible or interacted with and for the grace
         * after, but the keyboard's, which is in use while the screen is on and no longer; with its
         * notification while a service runs.
         */
        fun finish(until: Long, from: Long): List<Interval> {
            now = maxOf(now, until)
            for ((uid, since) in visibleSince) visible += Interval(uid, since, until, States.IN_USE)
            for ((uid, since) in servingSince) serving += Interval(uid, since, until, States.NOTIFICATION)
            keyboardSince?.let { since -> keyboard?.let { keyboardShown += Interval(it, since, until, States.IN_USE) } }
            val inUse = keyboardShown.toMutableList()
            for (interval in visible + interactions) inUse += interval.copy(until = interval.until + grace)
            for ((uid, last) in lastInUse) inUse += Interval(uid, last, last + grace, States.IN_USE)
            return (merged(inUse) + merged(serving)).mapNotNull { interval ->
                val a = maxOf(interval.from, from)
                val b = minOf(interval.until, until)
                if (a < b) interval.copy(from = a, until = b) else null
            }
        }

    }

    companion object {
        /** The grace after the user leaves an app (decision 1: 30 seconds, until the lab run sets it). */
        const val GRACE_MS = 30_000L

        /** A reading tells the states up to this long before the wall clock, for events not reported yet. */
        const val MARGIN_MS = 2_000L

        /** Each reading reads again this much of the last, for events that come late or out of order. */
        const val LATE_MS = 10_000L

        /** A first reading, or one after a time with no events, reads this far back to find what is open. */
        const val LOOKBACK_MS = 24 * 60 * 60 * 1000L

        /** The intervals of one app and state, joined where they meet or overlap, in order. */
        fun merged(intervals: List<Interval>): List<Interval> =
            intervals.groupBy { it.uid to it.state }.values.flatMap { same ->
                val sorted = same.sortedBy { it.from }
                val out = mutableListOf<Interval>()
                for (interval in sorted) {
                    val last = out.lastOrNull()
                    if (last != null && interval.from <= last.until) {
                        out[out.size - 1] = last.copy(until = maxOf(last.until, interval.until))
                    } else {
                        out += interval
                    }
                }
                out
            }.sortedWith(compareBy({ it.uid }, { it.state }, { it.from }))
    }
}
