package org.visadahyu.datapavan.watch.log

import android.content.Context
import android.database.sqlite.SQLiteFullException
import androidx.core.content.edit
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.time.Instant
import java.time.ZoneId
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.random.Random

/**
 * Debug builds only (scripts/verify-log.sh): a model-based test of the connection log, run inside Watch
 * on the phone, with Android's own SQLite and the phone's own Keystore.
 *
 * From a seed it draws a sequence of what can happen to the log: writes, reads, the clock moving on,
 * back and past midnight, a change of time zone, the process starting again, the phone locked and
 * unlocked, a change of retention, the wipe, Android's expiry job, a database that is full, a batch that
 * fails once after its key rows, and a Keystore that fails. It applies each to a log of its own (its own file, preferences and Keystore key,
 * never the user's) and checks the log against a small model of what it must give back and what it must
 * not:
 *
 * - nothing past retention or wiped is ever read again, even after the clock is set back;
 * - after any moment Watch runs expiry, the file holds no day past retention, and with retention 0 there
 *   is no file and no key;
 * - an earlier day does not open on a locked phone;
 * - every record written while nothing failed is read back whole on an unlocked phone, so a failure
 *   cannot leave the log broken once it has passed; a record written while something failed is read back
 *   whole or not at all, and if not at all, the log counted a failure;
 * - nothing is counted as a failure while nothing fails, and nothing the log does ends the process.
 */
object LogModel {
    private val state = AtomicReference("log-model idle")
    private var running = false

    /** Starts a run in the background and says so; [result] says how it ended. */
    fun start(context: Context, seed: Long, steps: Int): String {
        synchronized(this) {
            if (running) return "log-model busy"
            running = true
        }
        state.set("log-model running seed $seed step 0/$steps")
        thread(name = "watch-log-model") {
            val outcome = try {
                Run(context.applicationContext, seed, steps, state).go()
            } catch (e: Exception) {
                "log-model failed seed $seed: the run itself failed: ${e.javaClass.name}: ${e.message}"
            }
            state.set(outcome)
            synchronized(this) { running = false }
        }
        return "log-model started seed $seed steps $steps"
    }

    fun result(): String = state.get()
}

private class Violation(message: String) : Exception(message)

/** A record the model expects: [sure] when written while nothing failed, else it may be missing. */
private data class Expected(val id: Long, val uid: Int?, val start: Long, val day: Long, val sure: Boolean, val failuresBefore: Int)

private class ModelClock(var now: Long, var zone: ZoneId) : LogClock {
    override fun now(): Long = now

    override fun zone(): ZoneId = zone
}

private enum class Fault { RUNTIME, CHECKED }

/**
 * The real Keystore wrap, with a phone that can be locked and a Keystore that can fail. A runtime
 * failure is what some makers' Keystores throw; a checked one is what [KeystoreWrap] already handles.
 */
private class FaultyWrap(private val inner: KeyWrap) : KeyWrap {
    var locked = false
    var fault: Fault? = null

    override fun wrap(dayKey: ByteArray): ByteArray {
        when (fault) {
            Fault.RUNTIME -> throw ProviderException("model: the Keystore failed")
            Fault.CHECKED -> throw GeneralSecurityException("model: the Keystore failed")
            null -> Unit
        }
        return inner.wrap(dayKey)
    }

    override fun unwrap(wrapped: ByteArray): ByteArray? = when (fault) {
        Fault.RUNTIME -> throw ProviderException("model: the Keystore failed")
        // KeystoreWrap answers a checked failure with null, as for a locked phone.
        Fault.CHECKED -> null
        null -> if (locked) null else inner.unwrap(wrapped)
    }

    override fun destroy() {
        when (fault) {
            Fault.RUNTIME -> throw ProviderException("model: the Keystore failed")
            // KeystoreWrap logs a checked failure and goes on; the key pair stays.
            Fault.CHECKED -> Unit
            null -> inner.destroy()
        }
    }

    override fun exists(): Boolean = inner.exists()
}

private class Run(private val context: Context, private val seed: Long, private val steps: Int, private val state: AtomicReference<String>) {
    private val random = Random(seed)
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val wrap = FaultyWrap(KeystoreWrap(prefs, ALIAS))
    private val clock = ModelClock(System.currentTimeMillis(), ZoneId.systemDefault())
    private lateinit var log: ConnectionLog

    private var retention = 30
    private var diskFull = false

    /** The next batch fails once, after its key rows and before its records: a disk that fills in the middle. */
    @Volatile
    private var failOnce = false

    /** Records that may still be in the log, by id; what is gone leaves this map for [gone]. */
    private val expected = LinkedHashMap<Long, Expected>()
    private val gone = HashSet<Long>()
    private var nextId = 1L

    /** Failures of the logs this run closed, and of the one open. */
    private var pastFailures = 0
    private val failures get() = pastFailures + log.failures

    private val trail = ArrayDeque<String>()
    private val events = sortedMapOf<String, Int>()
    private var written = 0
    private var lostUnderFaults = 0
    private var keptUnderFaults = 0

    fun go(): String {
        clean()
        log = newLog()
        try {
            for (step in 1..steps) {
                if (step % 10 == 0) state.set("log-model running seed $seed step $step/$steps")
                try {
                    step()
                } catch (e: Violation) {
                    return "log-model failed seed $seed step $step: ${e.message} | last: ${trail.joinToString("; ")}"
                }
            }
            // At the end nothing fails and the phone is unlocked: every record left must read back.
            try {
                wrap.locked = false
                wrap.fault = null
                failOnce = false
                setDiskFull(false)
                note("end")
                readAll()
                checkFile()
            } catch (e: Violation) {
                return "log-model failed seed $seed at the end: ${e.message} | last: ${trail.joinToString("; ")}"
            }
            return "log-model passed seed $seed steps $steps written $written lost-under-faults $lostUnderFaults " +
                "kept-under-faults $keptUnderFaults failures $failures events ${events.entries.joinToString(",") { "${it.key}:${it.value}" }}"
        } finally {
            wrap.locked = false
            wrap.fault = null
            log.wipe()
            log.close()
            clean()
        }
    }

    private fun clean() {
        context.deleteDatabase(NAME)
        KeystoreWrap(prefs, ALIAS).destroy()
        prefs.edit { clear() }
    }

    private fun newLog() = ConnectionLog(context, NAME, prefs, wrap, clock).also {
        it.beforeRecord = {
            if (failOnce) {
                failOnce = false
                throw SQLiteFullException("model: the disk filled")
            }
        }
    }

    private fun step() {
        val faultBefore = faulty()
        val failuresBefore = failures
        if (diskFull) limitPages()
        val roll = random.nextInt(100)
        val maintained = when {
            roll < 30 -> write()
            roll < 52 -> read()
            roll < 66 -> advance()
            roll < 70 -> back()
            roll < 74 -> zone()
            roll < 80 -> restart()
            roll < 85 -> lock()
            roll < 88 -> keystoreFault()
            roll < 91 -> diskFault()
            roll < 95 -> retention()
            roll < 97 -> wipe()
            else -> job()
        }
        if (maintained && !faulty()) checkFile()
        if (!faultBefore && !faulty() && failures != failuresBefore) {
            throw Violation("${failures - failuresBefore} failures counted while nothing failed")
        }
    }

    private fun faulty() = diskFull || failOnce || wrap.fault != null

    private fun note(event: String) {
        trail.addLast(event)
        if (trail.size > 25) trail.removeFirst()
        val kind = event.substringBefore(' ')
        events[kind] = (events[kind] ?: 0) + 1
    }

    private fun dayOf(millis: Long) = Instant.ofEpochMilli(millis).atZone(clock.zone).toLocalDate().toEpochDay()

    private fun today() = dayOf(clock.now)

    private fun firstKept() = today() - retention + 1

    /** What Watch's expiry does, as the model sees it: days past retention, or everything, are gone. */
    private fun expireModel() {
        val first = firstKept()
        val leaving = expected.values.filter { retention == 0 || it.day < first }
        for (record in leaving) {
            expected.remove(record.id)
            gone += record.id
        }
    }

    // Events. Each answers whether it is a moment at which Watch runs expiry.

    private fun write(): Boolean {
        val count = 1 + random.nextInt(5)
        val failuresBefore = failures
        val sure = !faulty()
        val batch = (0 until count).map {
            val back = if (random.nextInt(10) == 0) random.nextLong(DAY, 3 * DAY) else random.nextLong(0, 25 * MINUTE)
            val start = clock.now - back
            Expected(nextId++, APPS[random.nextInt(APPS.size)], start, dayOf(start), sure, failuresBefore)
        }
        note("write ${batch.joinToString(",") { "${it.id}@${it.day}" }}${if (sure) "" else " (faulty)"}")
        log.write(encode(batch))
        log.settle(SETTLE)
        expireModel()
        if (retention > 0) {
            val first = firstKept()
            for (record in batch.filter { it.day >= first }) {
                expected[record.id] = record
                written++
            }
        }
        return true
    }

    private fun read(): Boolean {
        val days = sortedSetOf(today(), firstKept() - 1 - random.nextInt(3))
        expected.values.map { it.day }.distinct().takeIf { it.isNotEmpty() }?.let { days += it[random.nextInt(it.size)] }
        if (random.nextInt(8) == 0) days += expected.values.map { it.day }
        note("read ${days.joinToString(",")}")
        expireModel()
        for (day in days) check(day, log.read(day))
        return true
    }

    private fun readAll() {
        expireModel()
        for (day in (expected.values.map { it.day } + today()).toSortedSet()) check(day, log.read(day))
    }

    private fun advance(): Boolean {
        val roll = random.nextInt(100)
        val by = when {
            roll < 40 -> random.nextLong(MINUTE, 30 * MINUTE)
            roll < 65 -> random.nextLong(HOUR, 6 * HOUR)
            roll < 85 -> {
                val midnight = Instant.ofEpochMilli(clock.now).atZone(clock.zone).toLocalDate().plusDays(1)
                    .atStartOfDay(clock.zone).toInstant().toEpochMilli()
                midnight - clock.now + random.nextLong(5_000, 90_000)
            }
            roll < 97 -> random.nextLong(DAY, 3 * DAY)
            else -> random.nextLong(20 * DAY, 40 * DAY)
        }
        clock.now += by
        note("advance ${by / MINUTE}m to day ${today()}")
        return false
    }

    private fun back(): Boolean {
        val by = if (random.nextInt(10) < 6) random.nextLong(10 * MINUTE, 12 * HOUR) else random.nextLong(DAY, 3 * DAY)
        clock.now -= by
        note("back ${by / MINUTE}m to day ${today()}")
        return false
    }

    private fun zone(): Boolean {
        clock.zone = ZoneId.of(ZONES[random.nextInt(ZONES.size)])
        note("zone ${clock.zone} day ${today()}")
        return false
    }

    private fun restart(): Boolean {
        note("restart")
        pastFailures += log.failures
        log.close()
        log = newLog()
        if (diskFull) limitPages()
        log.settle(SETTLE)
        expireModel()
        return true
    }

    private fun lock(): Boolean {
        wrap.locked = !wrap.locked
        note(if (wrap.locked) "lock" else "unlock")
        return false
    }

    private fun keystoreFault(): Boolean {
        wrap.fault = if (wrap.fault != null) null else Fault.entries[random.nextInt(Fault.entries.size)]
        note("keystore ${wrap.fault ?: "works"}")
        return false
    }

    private fun diskFault(): Boolean {
        if (!diskFull && random.nextBoolean()) {
            failOnce = true
            note("disk fails-once")
        } else {
            setDiskFull(!diskFull)
            note(if (diskFull) "disk full" else "disk free")
        }
        return false
    }

    /**
     * A full disk, as SQLite meets it: once VACUUM has left no free page in the file, the database may
     * not grow by a page.
     */
    private fun setDiskFull(full: Boolean) {
        diskFull = full
        if (!log.hasFile) return
        if (full) {
            log.onConnection("VACUUM")
            limitPages()
        } else {
            log.onConnection("PRAGMA max_page_count = $MAX_PAGES")
        }
    }

    /** The limit again, on whatever connection the log has now (a wipe or a restart opens a new one). */
    private fun limitPages() {
        if (!log.hasFile) return
        log.onConnection("PRAGMA max_page_count = ${log.onConnection("PRAGMA page_count")}")
    }

    private fun retention(): Boolean {
        val days = ConnectionLog.RETENTION_CHOICES.filter { it != retention }.let { it[random.nextInt(it.size)] }
        note("retention $days")
        log.retentionDays = days
        retention = days
        log.settle(SETTLE)
        expireModel()
        return true
    }

    private fun wipe(): Boolean {
        note("wipe")
        val failuresBefore = failures
        var done: Boolean? = null
        log.wipe { done = it }
        log.settle(SETTLE)
        for (id in expected.keys) gone += id
        expected.clear()
        when {
            done == null -> throw Violation("the wipe did not finish")
            !faulty() && done != true -> throw Violation("the wipe left something while nothing failed")
            done != true && failures == failuresBefore -> throw Violation("the wipe left something and counted no failure")
        }
        return true
    }

    private fun job(): Boolean {
        note("job")
        var done = false
        log.expire { done = true }
        log.settle(SETTLE)
        if (!done) throw Violation("the expiry job did not finish")
        expireModel()
        return true
    }

    // Checks.

    /** The file, as it is: no day past retention, and with retention 0 neither file nor key. */
    private fun checkFile() {
        if (retention == 0) {
            if (log.hasFile || log.hasKey) throw Violation("retention 0, yet file ${log.hasFile} key ${log.hasKey}")
            return
        }
        val (rows, keyRows) = log.stored()
        val first = firstKept()
        rows.keys.firstOrNull { it < first }?.let { throw Violation("day $it, past retention, still has ${rows[it]} rows") }
        keyRows.keys.firstOrNull { it < first }?.let { throw Violation("day $it, past retention, still has a key row") }
        for ((day, count) in rows) {
            val all = expected.values.count { it.day == day }
            val sure = expected.values.count { it.day == day && it.sure }
            if (count !in sure..all) throw Violation("day $day has $count rows, the model $sure to $all")
        }
    }

    /** What a read of [day] gave, against the model. */
    private fun check(day: Long, read: List<LogRecord>?) {
        val got = read?.map { it as? LogRecord.Lookups ?: throw Violation("day $day gave a record that was never written") }
        got?.firstOrNull { it.count in gone }?.let { throw Violation("record ${it.count} was read after it expired or was wiped") }
        val all = expected.values.filter { it.day == day }
        if (retention == 0 || day < firstKept()) {
            if (got == null || got.isNotEmpty()) throw Violation("day $day, past retention, gave ${got?.size ?: "null"}")
            return
        }
        if (got == null) {
            val excused = (wrap.locked || wrap.fault != null) && all.isNotEmpty()
            if (!excused) throw Violation("day $day did not open (locked ${wrap.locked}, keystore ${wrap.fault ?: "works"})")
            return
        }
        if (wrap.locked && day != today() && (got.isNotEmpty() || all.any { it.sure })) {
            throw Violation("earlier day $day gave ${got.size} records on a locked phone")
        }
        val ids = got.map { it.count }
        if (ids.size != ids.toSet().size) throw Violation("day $day gave a record twice")
        for (record in got) {
            val want = expected[record.count] ?: throw Violation("day $day gave record ${record.count}, which the model does not hold")
            if (want.day != day || want.uid != record.uid || want.start != record.start || record.wireUp != want.id * 3) {
                throw Violation("record ${record.count} came back changed")
            }
        }
        for (want in all) {
            when {
                want.id in ids -> if (!want.sure) {
                    expected[want.id] = want.copy(sure = true)
                    keptUnderFaults++
                }
                want.sure -> throw Violation("record ${want.id} of day $day, written while nothing failed, is missing")
                failures == want.failuresBefore -> throw Violation("record ${want.id} was lost and no failure was counted")
                else -> {
                    expected.remove(want.id)
                    lostUnderFaults++
                }
            }
        }
    }

    /** A batch as the engine hands it over: lookup records (core/net/src/log.rs), the id in place of the count. */
    private fun encode(records: List<Expected>): ByteArray {
        val encoded = records.map {
            ByteBuffer.allocate(42).order(ByteOrder.LITTLE_ENDIAN).put(1).put(2).putInt(it.uid ?: -1)
                .putLong(it.start).putLong(it.start).putInt(it.id.toInt()).putLong(it.id * 3).putLong(it.id * 5).array()
        }
        val batch = ByteBuffer.allocate(4 + encoded.sumOf { 2 + it.size }).order(ByteOrder.LITTLE_ENDIAN).putInt(encoded.size)
        for (record in encoded) batch.putShort(record.size.toShort()).put(record)
        return batch.array()
    }

    private companion object {
        const val NAME = "log-model.db"
        const val PREFS = "log-model"
        const val ALIAS = "watch-log-model"
        const val MAX_PAGES = 1_073_741_823L

        /** Long enough for the Keystore to make a key pair, which can take seconds on an emulator. */
        const val SETTLE = 120L
        val MINUTE = TimeUnit.MINUTES.toMillis(1)
        val HOUR = TimeUnit.HOURS.toMillis(1)
        val DAY = TimeUnit.DAYS.toMillis(1)
        val APPS = listOf(null, 2000, 10_101, 10_102, 10_103)

        /** Zones far apart, with and without summer time, and offsets of 30 and 45 minutes. */
        val ZONES = listOf(
            "UTC", "Asia/Tehran", "Pacific/Kiritimati", "Etc/GMT+12", "Asia/Kathmandu", "America/New_York",
            "Australia/Lord_Howe", "Europe/Berlin",
        )
    }
}
