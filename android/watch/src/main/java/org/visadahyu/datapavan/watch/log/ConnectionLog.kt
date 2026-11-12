package org.visadahyu.datapavan.watch.log

import android.annotation.SuppressLint
import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log
import androidx.core.content.edit
import androidx.core.database.sqlite.transaction
import java.time.Instant
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Watch's connection log (W4, ADR 0037): the engine's records, each sealed under a key for its day,
 * in app-private SQLite. A day key lives in memory only while its day is today, and on disk only
 * wrapped by the Keystore key pair, whose private key works only on an unlocked phone. Expiry deletes
 * the days past retention, rows and keys together; the wipe deletes the database and the key pair.
 * Retention 0 writes nothing and keeps nothing.
 *
 * Expiry does not wait for traffic: it runs when the process makes the log, when the tunnel starts,
 * when the screen opens, before every read, count and write, and from a job about every six hours
 * ([LogExpiryJob]). What lies past retention is never read back, even before expiry has run.
 *
 * Everything runs on one thread of its own, never on the engine's or the screen's, and nothing that
 * fails there reaches the tunnel: each failure is counted ([failures]) and logged without any
 * destination.
 */
class ConnectionLog internal constructor(
    private val context: Context,
    private val name: String,
    private val prefs: SharedPreferences,
    private val wrap: KeyWrap,
    private val clock: LogClock,
    /** Asked to keep the expiry job scheduled (true) or to cancel it (false). */
    private val expiryJob: (Boolean) -> Unit = {},
) {
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "watch-log") }
    private var database: Database? = null

    /** Today's day key in memory, by day: the key's row and the key. Other days' are cleared. */
    private val keys = HashMap<Long, Pair<Long, ByteArray>>()
    private val sealers = HashMap<Long, Sealer>()

    /** The first day kept when expiry last ran ([NOTHING_KEPT] for retention 0), or null: expiry runs again once that moves. */
    private var expiredBefore: Long? = null
    private var jobAsked = false
    private val failed = AtomicInteger()

    private val lockFlow = MutableStateFlow(Lock.NO_KEY_YET)

    /** The log's [Lock], kept current as its key pair is made and destroyed, for the screen. */
    val lock: StateFlow<Lock> = lockFlow.asStateFlow()

    init {
        submit(
            guarded {
                tidy()
                lockFlow.value = lockNow()
                if (hasFile && retentionDays > 0) {
                    expiryJob(true)
                    jobAsked = true
                }
            },
        )
    }

    /** Days the log keeps: 0 (none), 1, 7 or 30. */
    var retentionDays: Int
        get() = prefs.getInt(RETENTION, DEFAULT_RETENTION)
        set(days) {
            require(days in RETENTION_CHOICES)
            prefs.edit { putInt(RETENTION, days) }
            worker.execute(guarded { tidy(force = true) })
        }

    /** What failed on the log's thread since the process made the log: none means every record offered was kept. */
    val failures: Int get() = failed.get()

    /** Writes a batch of records from the engine (core/net/src/log.rs). */
    fun write(batch: ByteArray) = write(batch, pastRetention = false)

    /** Debug builds: runs inside a batch's transaction before each record's row, so that a test can fail the database there. */
    @Volatile
    internal var beforeRecord: () -> Unit = {}

    /** Debug builds: [pastRetention] keeps records that retention has already passed, as if put back by hand. */
    internal fun write(batch: ByteArray, pastRetention: Boolean) {
        submit(guarded { writeNow(batch, pastRetention) })
    }

    /** Deletes what retention no longer keeps; [done] runs on the log's thread afterwards. */
    fun expire(done: () -> Unit = {}) {
        submit(
            guarded {
                try {
                    tidy()
                } finally {
                    done()
                }
            },
        )
    }

    /** Deletes the database and the key pair; [done] runs on the log's thread with whether nothing is left. */
    fun wipe(done: (Boolean) -> Unit = {}) {
        submit(
            guarded {
                var gone = false
                try {
                    gone = wipeNow()
                } finally {
                    done(gone)
                }
            },
        )
    }

    /** Waits until everything given to the log so far is done, at most [seconds]. */
    fun settle(seconds: Long = 10) {
        onWorker(Unit, seconds) {}
    }

    /** What the log holds, without any destination. */
    data class Counts(val days: Int, val records: Int, val keys: Int)

    /** What the log holds once expiry has run. */
    fun counts(): Counts = onWorker(Counts(0, 0, 0)) {
        tidyOrCount()
        val (records, keys) = storedNow()
        Counts(records.size, records.values.sum(), keys.values.sum())
    }

    /** Debug builds: rows and key rows by day, as the file holds them now, without running expiry first. */
    internal fun stored(): Pair<Map<Long, Int>, Map<Long, Int>> = onWorker(emptyMap<Long, Int>() to emptyMap()) { storedNow() }

    /** Whether the log's key pair exists: not before the first record, nor after a wipe. */
    val hasKey: Boolean get() = wrap.exists()

    /** How the log keeps earlier days shut, as far as its key pair goes (ADR 0037). */
    enum class Lock {
        /** No key pair yet: nothing has been written since the log began or was wiped. */
        NO_KEY_YET,

        /** The key pair works only while the phone is unlocked (on a phone with no screen lock, always). */
        UNLOCKED_ONLY,

        /** The phone refused a key pair tied to its lock, so the log's works at any time. */
        ANY_TIME,
    }

    /** The log's [Lock] now, asked of the Keystore from the calling thread. */
    fun lockNow(): Lock = when {
        !wrap.exists() -> Lock.NO_KEY_YET
        (wrap as? KeystoreWrap)?.unlockedOnly != false -> Lock.UNLOCKED_ONLY
        else -> Lock.ANY_TIME
    }

    /** Whether the database file exists. */
    internal val hasFile: Boolean get() = context.getDatabasePath(name).exists()

    /**
     * The records of [day] (days since 1970, local), or null when the day cannot be opened now: a locked
     * phone, or a failure. A day past retention has no records, whatever the file still holds.
     */
    fun read(day: Long): List<LogRecord>? = onWorker(null, 30) { readNow(day) }

    /** Today, as days since 1970, in the phone's time zone now. */
    fun today(): Long = dayOf(clock.now())

    /** The local day of a moment, as days since 1970. */
    fun dayOf(millis: Long): Long = Instant.ofEpochMilli(millis).atZone(clock.zone()).toLocalDate().toEpochDay()

    /**
     * Debug builds: runs [sql] on the log's own connection, which pragmas such as max_page_count need,
     * and gives the first column of its first row (-1 for none). It makes the file if there is none.
     */
    internal fun onConnection(sql: String): Long = onWorker(-1L) {
        open().writableDatabase.rawQuery(sql, null).use { if (it.moveToFirst() && it.columnCount > 0) it.getLong(0) else -1L }
    }

    /** Debug builds: finishes what is queued, then closes the database and clears the keys from memory. */
    internal fun close() {
        submit(guarded { forgetKeys { true } })
        worker.shutdown()
        worker.awaitTermination(30, TimeUnit.SECONDS)
        database?.close()
        database = null
    }

    private fun readNow(day: Long): List<LogRecord>? {
        tidyOrCount()
        if (retentionDays == 0 || day < firstKept()) return emptyList()
        val db = existing() ?: return emptyList()
        val records = mutableListOf<LogRecord>()
        val rows = db.readableDatabase.rawQuery(
            "SELECT k.id, k.wrapped, r.app, r.sealed FROM records r JOIN day_keys k ON r.key = k.id WHERE r.day = ? ORDER BY r.id",
            arrayOf(day.toString()),
        )
        rows.use {
            val opened = HashMap<Long, Sealer?>()
            while (it.moveToNext()) {
                val keyId = it.getLong(0)
                val sealer = opened.getOrPut(keyId) {
                    sealers[day]?.takeIf { keys[day]?.first == keyId } ?: wrap.unwrap(it.getBlob(1))?.let { key ->
                        Sealer(key, day, keyId).also { key.fill(0) }
                    }
                } ?: return null
                val record = sealer.open(it.getBlob(3), it.getBlob(2))?.let(LogRecord::parse)
                if (record == null) failure("A record did not open") else records += record
            }
        }
        return records
    }

    private fun writeNow(batch: ByteArray, pastRetention: Boolean) {
        tidyOrCount()
        if (retentionDays == 0) return
        val first = firstKept()
        val records = LogRecord.batch(batch).filter { (record, _) -> pastRetention || dayOf(record.start) >= first }
        if (records.isEmpty()) return
        val db = open().writableDatabase
        // Each new day key's row is committed on its own before the batch: a batch that fails then
        // leaves no key in memory whose row the database does not have. A key row with no records is
        // harmless and goes with its day.
        val byDay = records.map { (record, _) -> dayOf(record.start) }.distinct().associateWith { sealerFor(db, it) }
        db.transaction {
            for ((record, bytes) in records) {
                val day = dayOf(record.start)
                val sealer = byDay.getValue(day)
                val token = sealer.token(record.uid)
                beforeRecord()
                insertOrThrow(
                    "records", null,
                    ContentValues().apply {
                        put("day", day)
                        put("key", sealer.keyId)
                        put("app", token)
                        put("sealed", sealer.seal(bytes, token))
                    },
                )
            }
        }
        // A late record of an earlier day drew a key of its own; it does not stay in memory.
        forgetKeys { it != today() }
        if (!jobAsked) {
            expiryJob(true)
            jobAsked = true
        }
    }

    /** The key for [day]: the one in memory, else a fresh one, stored only wrapped, its row committed. */
    private fun sealerFor(db: SQLiteDatabase, day: Long): Sealer {
        sealers[day]?.let { return it }
        val key = Sealer.newDayKey()
        try {
            val id = db.insertOrThrow("day_keys", null, ContentValues().apply { put("day", day); put("wrapped", wrap.wrap(key)) })
            // The first day key also made the key pair.
            if (lockFlow.value == Lock.NO_KEY_YET) lockFlow.value = lockNow()
            keys[day] = id to key
            return Sealer(key, day, id).also { sealers[day] = it }
        } catch (e: Exception) {
            key.fill(0)
            throw e
        }
    }

    /**
     * Clears every day key but today's from memory (best effort: the JVM may keep copies), and deletes
     * the days past retention, rows and keys together, once the first day kept has moved (or [force]).
     * With retention 0 nothing is kept: whatever is left goes, as by the wipe.
     */
    private fun tidy(force: Boolean = false) {
        val today = today()
        forgetKeys { it != today }
        if (retentionDays == 0) {
            if (!force && expiredBefore == NOTHING_KEPT) return
            if ((hasFile || wrap.exists()) && !wipeNow()) return
            expiredBefore = NOTHING_KEPT
            return
        }
        val first = firstKept()
        if (!force && expiredBefore == first) return
        existing()?.writableDatabase?.transaction {
            delete("records", "day < ?", arrayOf(first.toString()))
            delete("day_keys", "day < ?", arrayOf(first.toString()))
        }
        expiredBefore = first
    }

    /**
     * [tidy] before a read, a count or a write, which go on if it fails: what lies past retention is
     * still never read back nor written, and expiry runs again at the next moment.
     */
    private fun tidyOrCount() {
        try {
            tidy()
        } catch (e: Exception) {
            failure("Expiry failed", e)
        }
    }

    private fun firstKept(): Long = today() - retentionDays + 1

    private fun forgetKeys(which: (Long) -> Boolean) {
        for (day in keys.keys.filter(which)) {
            keys.remove(day)?.second?.fill(0)
            sealers.remove(day)
        }
    }

    /** Whether nothing is left: no file and no key pair. */
    private fun wipeNow(): Boolean {
        forgetKeys { true }
        database?.close()
        database = null
        context.deleteDatabase(name)
        expiredBefore = null
        wrap.destroy()
        lockFlow.value = lockNow()
        val gone = !hasFile && !wrap.exists()
        if (!gone) failure("The wipe left something")
        if (retentionDays == 0) {
            expiryJob(false)
            jobAsked = false
        }
        return gone
    }

    private fun storedNow(): Pair<Map<Long, Int>, Map<Long, Int>> {
        val db = existing() ?: return emptyMap<Long, Int>() to emptyMap()
        fun byDay(table: String) = db.readableDatabase.rawQuery("SELECT day, COUNT(*) FROM $table GROUP BY day", null).use {
            buildMap { while (it.moveToNext()) put(it.getLong(0), it.getInt(1)) }
        }
        return byDay("records") to byDay("day_keys")
    }

    private fun open(): Database = database ?: Database(context, name).also { database = it }

    private fun existing(): Database? = database ?: if (hasFile) open() else null

    /** A task that counts its failure instead of ending the process, and the tunnel with it. */
    private fun guarded(task: () -> Unit) = Runnable {
        try {
            task()
        } catch (e: Exception) {
            failure("A task failed", e)
        }
    }

    private fun submit(task: Runnable) {
        try {
            worker.execute(task)
        } catch (e: RejectedExecutionException) {
            failure("The log is closed", e)
        }
    }

    /** Runs [task] on the log's thread and waits for its answer, or gives [fallback] if it fails. */
    private fun <T> onWorker(fallback: T, seconds: Long = 10, task: () -> T): T = try {
        worker.submit<T> {
            try {
                task()
            } catch (e: Exception) {
                failure("A task failed", e)
                fallback
            }
        }.get(seconds, TimeUnit.SECONDS)
    } catch (e: TimeoutException) {
        failure("A task did not finish in time", e)
        fallback
    } catch (e: ExecutionException) {
        failure("A task failed", e)
        fallback
    } catch (e: RejectedExecutionException) {
        failure("The log is closed", e)
        fallback
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        fallback
    }

    private fun failure(what: String, e: Exception? = null) {
        failed.incrementAndGet()
        // Only what failed and the kind of error: an error's message could quote what was being written.
        Log.w(TAG, if (e == null) what else "$what: ${e.javaClass.name}")
    }

    private class Database(context: Context, name: String) : SQLiteOpenHelper(context, name, null, 1) {
        override fun onConfigure(db: SQLiteDatabase) {
            // Deleted rows' pages are overwritten in the file; what flash memory keeps is sealed anyway.
            // A pragma that answers with a row: Android's execSQL refuses it.
            db.rawQuery("PRAGMA secure_delete = ON", null).use { it.moveToFirst() }
            db.setForeignKeyConstraintsEnabled(true)
        }

        override fun onCreate(db: SQLiteDatabase) {
            db.execSQL("CREATE TABLE day_keys (id INTEGER PRIMARY KEY, day INTEGER NOT NULL, wrapped BLOB NOT NULL)")
            db.execSQL(
                "CREATE TABLE records (id INTEGER PRIMARY KEY, day INTEGER NOT NULL, " +
                    "key INTEGER NOT NULL REFERENCES day_keys(id), app BLOB NOT NULL, sealed BLOB NOT NULL)",
            )
            db.execSQL("CREATE INDEX records_by_day_and_app ON records (day, app)")
        }

        override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
    }

    companion object {
        private const val TAG = "WatchLog"
        private const val NAME = "log.db"
        private const val PREFS = "log"
        private const val ALIAS = "watch-log"
        private const val RETENTION = "retention_days"
        // No log becomes evidence by default (ADR 0040): it keeps nothing until the user chooses, at
        // onboarding once W9 brings it, and in the log's settings until then.
        private const val DEFAULT_RETENTION = 0
        private const val NOTHING_KEPT = Long.MIN_VALUE
        val RETENTION_CHOICES = listOf(0, 1, 7, 30)

        // Holds only the application's context, which lives as long as the process.
        @SuppressLint("StaticFieldLeak")
        @Volatile
        private var instance: ConnectionLog? = null

        /** The process's one log. */
        fun of(context: Context): ConnectionLog = instance ?: synchronized(this) {
            instance ?: run {
                val app = context.applicationContext
                val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                ConnectionLog(app, NAME, prefs, KeystoreWrap(prefs, ALIAS), LogClock.Phone) { keep -> LogExpiryJob.keep(app, keep) }
                    .also { instance = it }
            }
        }
    }
}
