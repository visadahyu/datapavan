package org.visadahyu.datapavan.watch.activity

import android.Manifest
import android.annotation.SuppressLint
import android.app.usage.UsageEvents
import android.app.usage.UsageEventsQuery
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import androidx.core.content.ContextCompat
import java.util.concurrent.ExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import org.visadahyu.datapavan.audit.hasUsageAccess

/**
 * Reads the apps' states from Android's usage events for the engine (ADR 0046, decision 1), in Watch's
 * process beside the tunnel it serves; [UsageStates] places them. It lives in `:watch`, which cannot
 * depend on `:app`, and needs nothing of the audit but the rule of usage access, which `android/shared`
 * holds for both.
 *
 * It reads incrementally, from the end of its last reading less its overlap, and only when asked: when
 * the engine asks ([wanted]: a flow opened, bytes have waited five seconds for their state, or a reading
 * left some still waiting), at most every 5 seconds with the screen on and once a minute with it off, an
 * ask that comes sooner waiting for its turn ([ReadingRules]); once when the screen turns off, for what was
 * sent while it was on; at once when the screen comes on, as the live view may open, when the wall clock is
 * set, and when Watch starts and stops. No alarm wakes the phone: a reading waiting for its turn is made
 * when the phone is awake. The screen's state comes from the events and from `ACTION_SCREEN_ON` and
 * `ACTION_SCREEN_OFF`, received while the tunnel runs, which need no permission.
 *
 * Without usage access, and before the user's first unlock after a restart, it tells the engine that
 * nothing is known: those seconds have no state, and [known] says which. Android itself gives an app an
 * empty record in both cases, never none, so the tracker asks [UserManager.isUserUnlocked] first, and asks
 * for access again after a query that found nothing (review b1 of W5's second part, Kotlin, finding 3).
 */
internal class StateTracker(private val context: Context, private val tell: (ByteArray) -> Boolean) {
    private val usage = context.getSystemService(UsageStatsManager::class.java)
    /**
     * From Android 12, Android may wait up to 10 seconds before it shows a foreground service's notification
     * [doc: Android 12 behavior changes, "UX delay for foreground service notifications"]: a service counts
     * as "with its notification" only after that (review b3 of W5's second part, fresh, M1).
     */
    private val core = UsageStates(
        notificationDelay = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) NOTIFICATION_DELAY_MS else 0,
    )
    private val worker = ScheduledThreadPoolExecutor(1) { task -> Thread(task, "watch-states").apply { isDaemon = true } }.apply {
        // A reading waiting for its turn is dropped at the stop, which reads a last time itself.
        executeExistingDelayedTasksAfterShutdownPolicy = false
        removeOnCancelPolicy = true
    }
    private val queued = AtomicBoolean(false)

    /** The reading waiting for its turn, and when it is due by elapsed time; guarded by `this`. */
    private var later: ScheduledFuture<*>? = null
    private val turns = Turns()
    /** From when the first reading tells the states: a little before the engine it serves began. */
    private val startedAt = System.currentTimeMillis() - START_SLACK_MS

    /** When the last reading began, by [SystemClock.elapsedRealtime], and what the wall clock read then. */
    @Volatile
    private var lastRead = Long.MIN_VALUE / 2

    @Volatile
    private var lastWall: Long? = null

    /** The screen, by the broadcasts: on or off, and when it last came on. */
    @Volatile
    private var screenOn = context.getSystemService(PowerManager::class.java).isInteractive

    @Volatile
    private var screenOnSince: Long? = null

    /** Each package's UID, read again each reading, the worker's own: a package no longer installed has none. */
    /**
     * Whether each package may post notifications, read again each reading: from Android 13 an app's
     * notifications are off until the user allows them, and a foreground service's then shows only in the
     * task manager [doc: "Notification runtime permission"], so such an app's service is not "with its
     * notification". Below Android 13 notifications are on unless the user turned them off, which another
     * app cannot see.
     */
    private val notifying = Grants { packageName ->
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            context.packageManager.checkPermission(Manifest.permission.POST_NOTIFICATIONS, packageName) ==
            PackageManager.PERMISSION_GRANTED
    }

    private val uids = Uids { packageName ->
        try {
            context.packageManager.getPackageUid(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    /** What the last reading knew, for the dump: [States.KNOWN], [States.NO_ACCESS], [States.LOCKED], or -1 before the first. */
    @Volatile
    var known = -1
        private set

    /** How many readings were told, and when the last ended, in milliseconds since 1970. */
    @Volatile
    var readings = 0L
        private set

    @Volatile
    var toldUntil = 0L
        private set

    /** The events found late, as [UsageStates.late] counts them, for the debug dump. */
    @Volatile
    var late = 0 to 0L
        private set

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_SCREEN_ON -> {
                    screenOn = true
                    screenOnSince = System.currentTimeMillis()
                    post(force = true)
                }
                Intent.ACTION_SCREEN_OFF -> {
                    screenOn = false
                    readIn(ReadingRules.screenOffWait(SystemClock.elapsedRealtime(), lastRead))
                }
                Intent.ACTION_TIME_CHANGED -> post(force = true)
            }
        }
    }

    /** Starts following the screen and reads once. Main thread. */
    fun start() {
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_TIME_CHANGED)
        }
        // System broadcasts only: they reach a receiver that other apps cannot.
        ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        post(force = true)
    }

    /** Reads a last time, so that what the engine holds is placed before it stops, then stops. Main thread. */
    fun stop() {
        try {
            context.unregisterReceiver(receiver)
        } catch (e: IllegalArgumentException) {
            // Not registered: nothing to undo.
        }
        readNow(STOP_WAIT_MS)
        worker.shutdown()
    }

    /** The engine asks for a reading: one is made where the rules allow it. Any thread; returns at once. */
    fun wanted() = post(force = false)

    /** Reads now and waits for the engine to have it, at most `waitMs`: whether it did. */
    fun readNow(waitMs: Long): Boolean = try {
        worker.submit { read() }.get(waitMs, TimeUnit.MILLISECONDS)
        true
    } catch (e: TimeoutException) {
        false
    } catch (e: ExecutionException) {
        false
    } catch (e: java.util.concurrent.RejectedExecutionException) {
        false
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        false
    }

    /** A reading now when forced or due; one asked for too soon is made when its turn comes (decision 1). */
    private fun post(force: Boolean) {
        val wait = if (force) 0L else ReadingRules.wait(SystemClock.elapsedRealtime(), lastRead, screenOn)
        if (wait > 0) {
            readIn(wait)
            return
        }
        if (queued.compareAndSet(false, true)) {
            try {
                worker.execute {
                    queued.set(false)
                    read()
                }
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                queued.set(false)
            }
        }
    }

    /** A reading in `delayMs`, unless one is waiting that comes as soon ([Turns]). Any thread. */
    private fun readIn(delayMs: Long) {
        synchronized(this) {
            val wait = turns.ask(SystemClock.elapsedRealtime(), delayMs) ?: return
            later?.cancel(false)
            later = try {
                worker.schedule({ read() }, wait, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.RejectedExecutionException) {
                turns.read()
                null
            }
        }
    }

    /** One reading, on the worker: the events since the last, placed, and told to the engine. */
    private fun read() {
        // This reading serves whatever waited for its turn.
        synchronized(this) {
            later?.cancel(false)
            later = null
            turns.read()
        }
        val uidOf = uids.forReading()
        val elapsed = SystemClock.elapsedRealtime()
        val now = System.currentTimeMillis()
        // A clock set back by a second or more, against the time since the last reading.
        val wall = lastWall
        if (ReadingRules.setBack(wall, lastRead, now, elapsed) && wall != null) {
            core.clockSetBack(now, wall + (elapsed - lastRead) - now, uidOf, keyboard(uidOf))
        }
        lastRead = elapsed
        lastWall = now
        val until = now - UsageStates.MARGIN_MS
        // The phone's start by the wall clock: a first reading reads back to it (review b2, fresh, M1).
        val bootedAt = now - elapsed
        val (what, events) = ReadingRules.know(
            access = { hasUsageAccess(context) },
            unlocked = { context.getSystemService(UserManager::class.java).isUserUnlocked },
            query = { events(core.queryFrom(until, bootedAt), until) },
        )
        val message = if (what != States.KNOWN) {
            nothing(until, what)
        } else {
            val reading = core.read(
                events, until, uidOf, keyboard(uidOf), startedAt, bootedAt,
                notifies = notifying.forReading(), screenNow = screenOn,
            )
            known = States.KNOWN
            val screen = if (reading.screen.on == null) UsageStates.Screen(screenOn, screenOnSince) else reading.screen
            States.encode(reading.copy(screen = screen))
        }
        if (tell(message)) {
            readings++
            late = core.late
            toldUntil = until
        } else {
            // No engine took it: the next reading tells again from the end of the last one taken.
            core.untold(toldUntil.takeIf { readings > 0 })
        }
    }

    private fun nothing(until: Long, why: Int): ByteArray {
        known = why
        val (from, to) = core.nothing(until, startedAt)
        return States.encode(from, to, why, UsageStates.Screen(screenOn, screenOnSince), emptyList())
    }

    /**
     * The usage events from `from` to `until`, of the kinds the states need; null when Android refuses them.
     * From Android 15 the query asks for those kinds only, so that the day read back after a start copies no
     * other event across (review b1, Kotlin, nit 10). Called only once [hasUsageAccess] said yes: usage
     * access is the package's, declared by the audit's manifest (`:app`, ADR 0022), which Watch's process
     * shares, so Watch's library declares nothing new (ADR 0046: "No new permission").
     */
    @SuppressLint("MissingPermission")
    private fun events(from: Long, until: Long): List<UsageStates.Event>? {
        // Right after a clock set back the span can be empty, which Android 15's query refuses (review b2 of
        // W5's second part, fresh, nit): an empty span has no events.
        if (from >= until) return emptyList()
        val events = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                usage.queryEvents(UsageEventsQuery.Builder(from, until).setEventTypes(*EVENT_TYPES).build())
            } else {
                usage.queryEvents(from, until)
            }
        } catch (e: SecurityException) {
            null
        } catch (e: IllegalArgumentException) {
            // Refused as not valid: nothing is known of the span, told as such, never as no events (review b3,
            // R9). The guard above keeps it from happening on AOSP.
            null
        } ?: return null
        val read = mutableListOf<UsageStates.Event>()
        val event = UsageEvents.Event()
        while (events.getNextEvent(event)) {
            val kind = KINDS[event.eventType] ?: continue
            read += UsageStates.Event(event.timeStamp, kind, event.packageName, event.className)
        }
        return read
    }

    /** The default keyboard's UID (decision 5: in use while the screen is on), if Android says which it is. */
    private fun keyboard(uidOf: (String) -> Int?): Int? {
        val component = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
        } catch (e: SecurityException) {
            null
        } ?: return null
        return uidOf(component.substringBefore('/'))
    }

    companion object {
        /** How far before the tracker's start its first reading tells, to cover the engine started just before. */
        private const val START_SLACK_MS = 10_000L

        /** The longest Android 12 and later may wait before it shows a foreground service's notification. */
        private const val NOTIFICATION_DELAY_MS = 10_000L

        /** How long Watch's stop waits for its last reading. */
        private const val STOP_WAIT_MS = 2_000L

        private val KINDS = mapOf(
            UsageEvents.Event.ACTIVITY_RESUMED to UsageStates.Kind.RESUMED,
            UsageEvents.Event.ACTIVITY_PAUSED to UsageStates.Kind.PAUSED,
            UsageEvents.Event.ACTIVITY_STOPPED to UsageStates.Kind.STOPPED,
            UsageEvents.Event.FOREGROUND_SERVICE_START to UsageStates.Kind.SERVICE_START,
            UsageEvents.Event.FOREGROUND_SERVICE_STOP to UsageStates.Kind.SERVICE_STOP,
            UsageEvents.Event.USER_INTERACTION to UsageStates.Kind.INTERACTION,
            UsageEvents.Event.SCREEN_INTERACTIVE to UsageStates.Kind.SCREEN_ON,
            UsageEvents.Event.SCREEN_NON_INTERACTIVE to UsageStates.Kind.SCREEN_OFF,
            UsageEvents.Event.KEYGUARD_SHOWN to UsageStates.Kind.KEYGUARD_SHOWN,
            UsageEvents.Event.KEYGUARD_HIDDEN to UsageStates.Kind.KEYGUARD_HIDDEN,
            UsageEvents.Event.DEVICE_SHUTDOWN to UsageStates.Kind.SHUTDOWN,
            UsageEvents.Event.DEVICE_STARTUP to UsageStates.Kind.STARTUP,
        )

        private val EVENT_TYPES = KINDS.keys.toIntArray()
    }
}
