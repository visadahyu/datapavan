package org.visadahyu.datapavan.watch.activity

import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.watch.activity.UsageStates.Event
import org.visadahyu.datapavan.watch.activity.UsageStates.Interval
import org.visadahyu.datapavan.watch.activity.UsageStates.Kind

/** The state machine of ADR 0046's decision 1, one test for each of its rules, on synthetic events. */
class UsageStatesTest {
    private val t = 1_794_953_400_000L
    private val grace = UsageStates.GRACE_MS

    private val apps = mapOf("a" to A, "a.helper" to A, "b" to B, "c" to C, "kb" to KEYBOARD)
    private val uidOf: (String) -> Int? = { apps[it] }

    private fun at(seconds: Long) = t + seconds * 1_000
    private fun event(seconds: Long, kind: Kind, app: String, type: String? = null) = Event(at(seconds), kind, app, type)
    private fun inUse(uid: Int, from: Long, until: Long) = Interval(uid, from, until, States.IN_USE)
    private fun serving(uid: Int, from: Long, until: Long) = Interval(uid, from, until, States.NOTIFICATION)

    /** One reading of `events`, from the start [t], to `until` seconds in. */
    private fun read(events: List<Event>, until: Long = 600, keyboard: Int? = null, states: UsageStates = UsageStates()) =
        states.read(events, at(until), uidOf, keyboard, startedAt = t)

    @Test
    fun anActivityResumedIsInUseUntilItStopsAndTheGraceAfter() {
        val reading = read(listOf(event(10, Kind.RESUMED, "a", "Main"), event(70, Kind.STOPPED, "a", "Main")))
        assertEquals(listOf(inUse(A, at(10), at(70) + grace)), reading.intervals)
        assertEquals(t to at(600), reading.from to reading.until)
    }

    /** The grace ends at the stop plus 30 seconds, to the millisecond: in use before, not at it. */
    @Test
    fun theGraceEndsExactlyThirtySecondsAfter() {
        assertEquals(30_000L, grace)
        val reading = read(listOf(event(10, Kind.RESUMED, "a", "Main"), event(20, Kind.STOPPED, "a", "Main")), until = 50)
        assertEquals(listOf(inUse(A, at(10), at(50))), reading.intervals)
        val longer = read(listOf(event(10, Kind.RESUMED, "a", "Main"), event(20, Kind.STOPPED, "a", "Main")), until = 51)
        assertEquals(listOf(inUse(A, at(10), at(50))), longer.intervals)
    }

    /** A user interaction, as a tap on the app's notification, is in use for the grace. */
    @Test
    fun aUserInteractionIsInUseForTheGrace() {
        val reading = read(listOf(event(100, Kind.INTERACTION, "b")))
        assertEquals(listOf(inUse(B, at(100), at(100) + grace)), reading.intervals)
        // Two within the grace make one interval.
        val two = read(listOf(event(100, Kind.INTERACTION, "b"), event(120, Kind.INTERACTION, "b")))
        assertEquals(listOf(inUse(B, at(100), at(120) + grace)), two.intervals)
    }

    /** Paused but not stopped, as beside another app in split screen, an activity is visible: both apps are in use at once. */
    @Test
    fun severalAppsInUseAtOnceAreEachInUse() {
        val reading = read(
            listOf(
                event(10, Kind.RESUMED, "a", "Main"),
                event(20, Kind.PAUSED, "a", "Main"),
                event(20, Kind.RESUMED, "b", "Main"),
            ),
        )
        assertEquals(listOf(inUse(A, at(10), at(600)), inUse(B, at(20), at(600))), reading.intervals)
    }

    /** A foreground service is "with its notification" from its start to its stop; with an activity, both are told, and in use wins in the engine. */
    @Test
    fun aForegroundServiceIsWithItsNotificationFromStartToStop() {
        val reading = read(
            listOf(
                event(10, Kind.SERVICE_START, "c", "Player"),
                event(50, Kind.RESUMED, "c", "Main"),
                event(60, Kind.STOPPED, "c", "Main"),
                event(200, Kind.SERVICE_STOP, "c", "Player"),
            ),
        )
        assertEquals(listOf(inUse(C, at(50), at(60) + grace), serving(C, at(10), at(200))), reading.intervals)
        // Two services of one app: with its notification until the last stops.
        val two = read(
            listOf(
                event(10, Kind.SERVICE_START, "c", "Player"),
                event(20, Kind.SERVICE_START, "c", "Upload"),
                event(30, Kind.SERVICE_STOP, "c", "Player"),
                event(40, Kind.SERVICE_STOP, "c", "Upload"),
            ),
        )
        assertEquals(listOf(serving(C, at(10), at(40))), two.intervals)
    }

    /** Packages that share a UID count together: one in use is the UID in use. */
    @Test
    fun packagesSharingAUidCountTogether() {
        val reading = read(
            listOf(
                event(10, Kind.RESUMED, "a", "Main"),
                event(20, Kind.RESUMED, "a.helper", "Other"),
                event(30, Kind.STOPPED, "a", "Main"),
                event(90, Kind.STOPPED, "a.helper", "Other"),
            ),
        )
        assertEquals(listOf(inUse(A, at(10), at(90) + grace)), reading.intervals)
    }

    /**
     * The screen off ends what is visible, the grace after; on again behind the lock screen, an app is not
     * visible until the lock screen is dismissed, but one resumed over it, as the camera, is.
     */
    @Test
    fun theScreenAndTheLockScreenHideActivities() {
        val reading = read(
            listOf(
                event(0, Kind.SCREEN_ON, "android"),
                event(10, Kind.RESUMED, "a", "Main"),
                event(100, Kind.SCREEN_OFF, "android"),
                event(101, Kind.KEYGUARD_SHOWN, "android"),
                event(200, Kind.SCREEN_ON, "android"),
                event(210, Kind.RESUMED, "b", "Camera"),
                event(220, Kind.STOPPED, "b", "Camera"),
                event(300, Kind.KEYGUARD_HIDDEN, "android"),
            ),
        )
        assertEquals(
            listOf(inUse(A, at(10), at(100) + grace), inUse(A, at(300), at(600)), inUse(B, at(210), at(220) + grace)),
            reading.intervals,
        )
        assertEquals(UsageStates.Screen(true, at(200)), reading.screen)
    }

    /** The default keyboard is in use while the screen is on, since it may be shown, and in the background while it is off. */
    @Test
    fun theKeyboardIsInUseWhileTheScreenIsOn() {
        val reading = read(
            listOf(event(0, Kind.SCREEN_ON, "android"), event(100, Kind.SCREEN_OFF, "android"), event(200, Kind.SCREEN_ON, "android")),
            keyboard = KEYBOARD,
        )
        assertEquals(listOf(inUse(KEYBOARD, t, at(100)), inUse(KEYBOARD, at(200), at(600))), reading.intervals)
        assertEquals(UsageStates.Screen(true, at(200)), reading.screen)
    }

    /** `DEVICE_SHUTDOWN` and `DEVICE_STARTUP` end every open interval: none carries across a restart of the phone. */
    @Test
    fun aRestartOfThePhoneEndsEveryOpenInterval() {
        val reading = read(
            listOf(
                event(10, Kind.RESUMED, "a", "Main"),
                event(20, Kind.SERVICE_START, "c", "Player"),
                event(100, Kind.SHUTDOWN, "android"),
                event(150, Kind.SERVICE_START, "b", "Sync"),
                event(160, Kind.STARTUP, "android"),
            ),
        )
        assertEquals(listOf(inUse(A, at(10), at(100) + grace), serving(B, at(150), at(160)), serving(C, at(20), at(100))), reading.intervals)
    }

    /** Watch starting again reads back a day: a service started three hours before, still running, is with its notification from Watch's start. */
    @Test
    fun aRestartOfWatchFindsWhatIsOpenFromADayBack() {
        val states = UsageStates()
        assertEquals(at(600) - UsageStates.LOOKBACK_MS, states.queryFrom(at(600)))
        val reading = read(listOf(event(-3 * 3_600, Kind.SERVICE_START, "c", "Player"), event(-3_000, Kind.RESUMED, "a", "Main")), states = states)
        assertEquals(listOf(inUse(A, t, at(600)), serving(C, t, at(600))), reading.intervals)
        assertEquals(t to at(600), reading.from to reading.until)
    }

    /**
     * Each reading reads again the last ten seconds of the one before: an event that arrives late within them
     * places its moment again, and the reading tells from there; events out of order within a reading are put
     * in order.
     */
    @Test
    fun eventsLateAndOutOfOrderAcrossReadingsArePlacedAgain() {
        val states = UsageStates()
        val first = read(listOf(event(10, Kind.RESUMED, "a", "Main")), until = 60, states = states)
        assertEquals(listOf(inUse(A, at(10), at(60))), first.intervals)
        assertEquals(at(60) - UsageStates.LATE_MS, states.queryFrom(at(120)))
        // The stop at 55 s comes with the next reading, before an event of the first again and out of order.
        val second = states.read(
            listOf(event(90, Kind.INTERACTION, "b"), event(55, Kind.STOPPED, "a", "Main"), event(10, Kind.RESUMED, "a", "Main")),
            at(120), uidOf, null, startedAt = t,
        )
        assertEquals(at(50) to at(120), second.from to second.until)
        assertEquals(listOf(inUse(A, at(50), at(55) + grace), inUse(B, at(90), at(120))), second.intervals)
        // A later one still carries what is open, and nothing twice.
        val third = states.read(listOf(event(90, Kind.INTERACTION, "b")), at(200), uidOf, null, startedAt = t)
        assertEquals(listOf(inUse(B, at(110), at(120))), third.intervals)
    }

    /** A wall clock set back: what is open carries over from the moment it was found, and nothing before it is read. */
    @Test
    fun aWallClockSetBackCarriesWhatIsOpenAndReadsOnlyAfterIt() {
        val states = UsageStates()
        read(listOf(event(10, Kind.RESUMED, "a", "Main"), event(20, Kind.SERVICE_START, "c", "Player")), until = 60, states = states)
        val back = at(-3_600)
        states.clockSetBack(back, uidOf, null)
        assertEquals(back, states.queryFrom(back + 30_000))
        val after = states.read(
            listOf(event(-3_700, Kind.RESUMED, "b", "Old"), Event(back + 5_000, Kind.STOPPED, "a", "Main")),
            back + 60_000, uidOf, null, startedAt = t,
        )
        assertEquals(back to back + 60_000, after.from to after.until)
        assertEquals(listOf(inUse(A, back, back + 5_000 + grace), serving(C, back, back + 60_000)), after.intervals)
    }

    /** Without usage access or events, nothing is known; the next reading with them reads back a day from its end. */
    @Test
    fun nothingKnownIsToldAsSuchAndTheNextReadingStartsAfresh() {
        val states = UsageStates()
        read(listOf(event(10, Kind.RESUMED, "a", "Main")), until = 60, states = states)
        assertEquals(at(60) to at(120), states.nothing(at(120), startedAt = t))
        assertEquals(at(180) - UsageStates.LOOKBACK_MS, states.queryFrom(at(180)))
        val again = states.read(listOf(event(10, Kind.RESUMED, "a", "Main"), event(150, Kind.STOPPED, "a", "Main")), at(240), uidOf, null, startedAt = t)
        assertEquals(at(120) to at(240), again.from to again.until)
        assertEquals(listOf(inUse(A, at(120), at(180))), again.intervals)
    }

    /** A reading the engine did not take is told again: the next reads back a day and tells from the end of the last taken. */
    @Test
    fun aReadingNotTakenIsToldAgain() {
        val states = UsageStates()
        read(listOf(event(10, Kind.RESUMED, "a", "Main")), until = 60, states = states)
        read(listOf(event(100, Kind.STOPPED, "a", "Main")), until = 120, states = states)
        states.untold(at(60))
        assertEquals(at(180) - UsageStates.LOOKBACK_MS, states.queryFrom(at(180)))
        val again = states.read(
            listOf(event(10, Kind.RESUMED, "a", "Main"), event(100, Kind.STOPPED, "a", "Main")),
            at(180), uidOf, null, startedAt = t,
        )
        assertEquals(at(60) to at(180), again.from to again.until)
        assertEquals(listOf(inUse(A, at(60), at(130))), again.intervals)
    }

    /** Intervals of one app and state are joined where they meet or overlap. */
    @Test
    fun intervalsThatMeetAreJoined() {
        val joined = UsageStates.merged(
            listOf(inUse(A, 10, 20), inUse(A, 20, 30), inUse(A, 40, 50), inUse(A, 45, 46), serving(A, 0, 100), inUse(B, 0, 1)),
        )
        assertEquals(listOf(inUse(A, 10, 30), inUse(A, 40, 50), serving(A, 0, 100), inUse(B, 0, 1)), joined)
    }

    private companion object {
        const val A = 10_101
        const val B = 10_102
        const val C = 10_103
        const val KEYBOARD = 10_104
    }
}
