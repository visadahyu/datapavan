package org.visadahyu.datapavan.watch.activity

import android.annotation.SuppressLint
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import androidx.core.content.ContextCompat
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
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
 * the engine asks ([wanted]: a flow opened, or bytes have waited five seconds for their state), at most
 * every 5 seconds with the screen on and once a minute with it off; when the screen comes on, as the
 * live view may open; when the wall clock is set; and when Watch stops. No timer wakes the phone. The
 * screen's state comes from the events and from `ACTION_SCREEN_ON` and `ACTION_SCREEN_OFF`, received while
 * the tunnel runs, which need no permission.
 *
 * Without usage access, and when Android gives no events, as before the first unlock after a restart, it
 * tells the engine that nothing is known: those seconds have no state, and [known] says which.
 */
internal class StateTracker(private val context: Context, private val tell: (ByteArray) -> Boolean) {
    private val usage = context.getSystemService(UsageStatsManager::class.java)
    private val core = UsageStates()
    private val worker = Executors.newSingleThreadExecutor { task -> Thread(task, "watch-states").apply { isDaemon = true } }
    private val queued = AtomicBoolean(false)
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

    /** Each package's UID, the worker's own: a package no longer installed has none. */
    private val uids = HashMap<String, Int?>()

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

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_SCREEN_ON -> {
                    screenOn = true
                    screenOnSince = System.currentTimeMillis()
                    post(force = true)
                }
                Intent.ACTION_SCREEN_OFF -> screenOn = false
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

    /** At most every 5 seconds with the screen on, every minute with it off (decision 1). */
    private fun due() = SystemClock.elapsedRealtime() - lastRead >= if (screenOn) SCREEN_ON_EVERY_MS else SCREEN_OFF_EVERY_MS

    private fun post(force: Boolean) {
        if ((force || due()) && queued.compareAndSet(false, true)) {
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

    /** One reading, on the worker: the events since the last, placed, and told to the engine. */
    private fun read() {
        val elapsed = SystemClock.elapsedRealtime()
        val now = System.currentTimeMillis()
        // A clock set back by a second or more, against the time since the last reading.
        val expected = lastWall?.let { it + (elapsed - lastRead) }
        if (expected != null && now + 1_000 <= expected) core.clockSetBack(now, ::uidOf, keyboard())
        lastRead = elapsed
        lastWall = now
        val until = now - UsageStates.MARGIN_MS
        val message = if (!hasUsageAccess(context)) {
            nothing(until, States.NO_ACCESS)
        } else {
            val events = events(core.queryFrom(until), until)
            if (events == null) {
                nothing(until, States.LOCKED)
            } else {
                val reading = core.read(events, until, ::uidOf, keyboard(), startedAt)
                known = States.KNOWN
                val screen = if (reading.screen.on == null) UsageStates.Screen(screenOn, screenOnSince) else reading.screen
                States.encode(reading.copy(screen = screen))
            }
        }
        if (tell(message)) {
            readings++
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
     * The usage events from `from` to `until`, of the kinds the states need; null when Android gives none,
     * as before the first unlock. Called only once [hasUsageAccess] said yes: usage access is the package's,
     * declared by the audit's manifest (`:app`, ADR 0022), which Watch's process shares, so Watch's library
     * declares nothing new (ADR 0046: "No new permission").
     */
    @SuppressLint("MissingPermission")
    private fun events(from: Long, until: Long): List<UsageStates.Event>? {
        val events = try {
            usage.queryEvents(from, until)
        } catch (e: SecurityException) {
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

    /** A package's UID, kept once read; null for one not installed. */
    private fun uidOf(packageName: String): Int? = uids.getOrPut(packageName) {
        if (uids.size >= MAX_PACKAGES) uids.clear()
        try {
            context.packageManager.getPackageUid(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }

    /** The default keyboard's UID (decision 5: in use while the screen is on), if Android says which it is. */
    private fun keyboard(): Int? {
        val component = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
        } catch (e: SecurityException) {
            null
        } ?: return null
        return uidOf(component.substringBefore('/'))
    }

    companion object {
        const val SCREEN_ON_EVERY_MS = 5_000L
        const val SCREEN_OFF_EVERY_MS = 60_000L

        /** How far before the tracker's start its first reading tells, to cover the engine started just before. */
        private const val START_SLACK_MS = 10_000L

        /** How long Watch's stop waits for its last reading. */
        private const val STOP_WAIT_MS = 2_000L

        /** At most this many packages' UIDs are kept; past it the list starts anew. */
        private const val MAX_PACKAGES = 1_024

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
    }
}
