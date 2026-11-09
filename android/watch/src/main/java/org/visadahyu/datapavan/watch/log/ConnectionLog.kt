package org.visadahyu.datapavan.watch.log

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Log
import java.security.GeneralSecurityException
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Watch's connection log (W4, ADR 0037): the engine's records, each sealed under a key for its day,
 * in app-private SQLite. A day key lives in memory while its day is written, and on disk only wrapped
 * by the Keystore key pair, whose private key works only on an unlocked phone. Expiry deletes a day's
 * rows with its keys; the wipe deletes the database and the key pair. Retention 0 writes nothing.
 *
 * Everything runs on one thread of its own, never on the engine's or the screen's.
 */
class ConnectionLog private constructor(private val context: Context) {
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val wrap: KeyWrap = KeystoreWrap(prefs)
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "watch-log") }
    private var database: Database? = null

    /** Day keys in memory, by day: the key's row and the key. Only the newest two days are kept. */
    private val keys = HashMap<Long, Pair<Long, ByteArray>>()
    private val sealers = HashMap<Long, Sealer>()
    private var expired = -1L

    /** Days the log keeps: 0 (none), 1, 7 or 30. */
    var retentionDays: Int
        get() = prefs.getInt(RETENTION, DEFAULT_RETENTION)
        set(days) {
            require(days in RETENTION_CHOICES)
            prefs.edit().putInt(RETENTION, days).apply()
            worker.execute { if (days == 0) wipeNow() else expire(force = true) }
        }

    /** Writes a batch of records from the engine (core/net/src/log.rs). */
    fun write(batch: ByteArray) {
        worker.execute {
            try {
                writeNow(batch)
            } catch (e: GeneralSecurityException) {
                // No destination in the message: only that writing failed.
                Log.w(TAG, "Records could not be sealed")
            } catch (e: android.database.SQLException) {
                Log.w(TAG, "Records could not be stored")
            }
        }
    }

    /** Deletes the database and the key pair; [done] runs on the log's thread once nothing is left. */
    fun wipe(done: () -> Unit = {}) {
        worker.execute {
            wipeNow()
            done()
        }
    }

    /** Waits until everything given to the log so far is written, at most [seconds]. */
    fun settle(seconds: Long = 10) {
        worker.submit {}.get(seconds, TimeUnit.SECONDS)
    }

    /** Days held and records held; no destination. */
    fun counts(): Pair<Int, Int> = worker.submit<Pair<Int, Int>> {
        val db = existing() ?: return@submit 0 to 0
        val days = db.readableDatabase.rawQuery("SELECT COUNT(DISTINCT day) FROM records", null).use { it.moveToFirst(); it.getInt(0) }
        val rows = db.readableDatabase.rawQuery("SELECT COUNT(*) FROM records", null).use { it.moveToFirst(); it.getInt(0) }
        days to rows
    }.get(10, TimeUnit.SECONDS)

    /** Whether the log's key pair exists: not before the first record, nor after a wipe. */
    val hasKey: Boolean get() = wrap.exists()

    /** Whether the key pair works only on an unlocked phone (ADR 0037). */
    val unlockedOnly: Boolean get() = (wrap as? KeystoreWrap)?.unlockedOnly ?: true

    /** The records of [day] (days since 1970, local), or null when an earlier day cannot be opened now: a locked phone. */
    fun read(day: Long): List<LogRecord>? = worker.submit<List<LogRecord>?> {
        val db = existing() ?: return@submit emptyList()
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
                    val key = keys[day]?.takeIf { (id, _) -> id == keyId }?.second ?: wrap.unwrap(it.getBlob(1))
                    key?.let { k -> Sealer(k, day, keyId) }
                } ?: return@submit null
                sealer.open(it.getBlob(3), it.getBlob(2))?.let(LogRecord::parse)?.let(records::add)
            }
        }
        records
    }.get(30, TimeUnit.SECONDS)

    private fun writeNow(batch: ByteArray) {
        if (retentionDays == 0) return
        val records = LogRecord.batch(batch)
        if (records.isEmpty()) return
        val db = open().writableDatabase
        db.beginTransaction()
        try {
            for ((record, bytes) in records) {
                val day = localDay(record.start)
                val (keyId, sealer) = sealerFor(db, day)
                val token = sealer.token(record.uid)
                db.insertOrThrow(
                    "records", null,
                    ContentValues().apply {
                        put("day", day)
                        put("key", keyId)
                        put("app", token)
                        put("sealed", sealer.seal(bytes, token))
                    },
                )
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
        forgetOldKeys()
        expire(force = false)
    }

    /** The key for [day]: the one in memory, else a fresh one, stored only wrapped. */
    private fun sealerFor(db: SQLiteDatabase, day: Long): Pair<Long, Sealer> {
        keys[day]?.let { (id, _) -> return id to sealers.getValue(day) }
        val key = Sealer.newDayKey()
        val id = db.insertOrThrow("day_keys", null, ContentValues().apply { put("day", day); put("wrapped", wrap.wrap(key)) })
        keys[day] = id to key
        sealers[day] = Sealer(key, day, id)
        return id to sealers.getValue(day)
    }

    /** Clears from memory every day key but the newest two days' (best effort: the JVM may keep copies). */
    private fun forgetOldKeys() {
        val newest = keys.keys.maxOrNull() ?: return
        for (day in keys.keys.filter { it < newest - 1 }) {
            keys.remove(day)?.second?.fill(0)
            sealers.remove(day)
        }
    }

    /** Deletes the days past retention, rows and keys together; once a day unless [force]. */
    private fun expire(force: Boolean) {
        val today = localDay(System.currentTimeMillis())
        if (!force && expired == today) return
        expired = today
        val db = existing() ?: return
        val first = today - retentionDays + 1
        val writable = db.writableDatabase
        writable.beginTransaction()
        try {
            writable.delete("records", "day < ?", arrayOf(first.toString()))
            writable.delete("day_keys", "day < ?", arrayOf(first.toString()))
            writable.setTransactionSuccessful()
        } finally {
            writable.endTransaction()
        }
        for (day in keys.keys.filter { it < first }) {
            keys.remove(day)?.second?.fill(0)
            sealers.remove(day)
        }
    }

    private fun wipeNow() {
        for ((_, key) in keys.values) key.fill(0)
        keys.clear()
        sealers.clear()
        database?.close()
        database = null
        context.deleteDatabase(NAME)
        wrap.destroy()
    }

    private fun open(): Database = database ?: Database(context).also { database = it }

    private fun existing(): Database? = database ?: if (context.getDatabasePath(NAME).exists()) open() else null

    private class Database(context: Context) : SQLiteOpenHelper(context, NAME, null, 1) {
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
        private const val RETENTION = "retention_days"
        private const val DEFAULT_RETENTION = 30
        val RETENTION_CHOICES = listOf(0, 1, 7, 30)

        @Volatile
        private var instance: ConnectionLog? = null

        /** The process's one log. */
        fun of(context: Context): ConnectionLog =
            instance ?: synchronized(this) { instance ?: ConnectionLog(context.applicationContext).also { instance = it } }

        /** The local day of a moment, as days since 1970. */
        fun localDay(millis: Long): Long = Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()).toLocalDate().toEpochDay()

        /** Today, as days since 1970, local. */
        fun today(): Long = LocalDate.now().toEpochDay()
    }
}
