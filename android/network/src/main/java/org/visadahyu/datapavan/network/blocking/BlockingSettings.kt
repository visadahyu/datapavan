package org.visadahyu.datapavan.network.blocking

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * The user's tracker blocking (W8, part 3a; ADR 0053), in the preferences `blocking` of the network process: whether it
 * is on (off until the user turns it on), whether it includes browsers, whether it blocks the user's tool's own tracker
 * lookups by DNS, the global pause, and the undo: apps allowed for an hour ([allowApp]) and rows allowed in one app
 * until blocked again ([allowEntries]). Apps and rows are kept by package and host, never by UID, which an app gets
 * anew when it is installed again; [Handover] gives them UIDs each time it hands the setting over.
 *
 * No alarm ends an allowance: its end is a time on the phone's clock, and what is left of it is worked out at each
 * decision ([Allowances.left]), at most an hour for an app and ten minutes for the pause, so that a clock set back
 * cannot stretch one; the engine then holds the rest as a deadline on the time since the phone started. Nothing of
 * what blocking counted is kept here or anywhere else (ADR 0047): the engine's tallies are memory only.
 *
 * ADR 0047's profile keeps these behind the network part's lock and wipes them with a wipe, as the apps left out of the
 * tunnel are (`left_out`): W9's wipe calls [wipe] beside them. Nothing else here records what an app did.
 */
class BlockingSettings internal constructor(private val store: Store, private val self: String = "") {
    /** Where the settings are kept: SharedPreferences on the phone ([of]), a map in the JVM tests. */
    interface Store {
        fun boolean(key: String): Boolean
        fun putBoolean(key: String, value: Boolean)
        fun long(key: String): Long
        fun putLong(key: String, value: Long)
        fun strings(key: String): Set<String>
        fun putStrings(key: String, value: Set<String>)
        fun clear()
    }

    /** Whether the user turned blocking on ("Block trackers"); off until then. */
    var on: Boolean
        get() = store.boolean(ON)
        set(value) = store.putBoolean(ON, value)

    /** Whether browsers are covered too ("Also block in browsers"); off until the user includes them. */
    var browsers: Boolean
        get() = store.boolean(BROWSERS)
        set(value) = store.putBoolean(BROWSERS, value)

    /** Whether the user's tool's own tracker lookups are answered with no address, by DNS alone; off until turned on. */
    var toolDns: Boolean
        get() = store.boolean(TOOL_DNS)
        set(value) = store.putBoolean(TOOL_DNS, value)

    /**
     * Pauses blocking in every app for ten minutes from [now] ("Pause blocking for 10 minutes"), naming no app. W9's Quick
     * Settings tile pauses through this same call, and shows only that blocking is paused (ADR 0046: the tile names no app).
     */
    fun pause(now: Long) = store.putLong(PAUSED_UNTIL, now + PAUSE_MS)

    /** Ends the pause ("Block again now"). */
    fun resume() = store.putLong(PAUSED_UNTIL, 0)

    /** When the pause ends, on the phone's clock, or null while there is none; one past its bound is brought back to it. */
    fun pausedUntil(now: Long): Long? {
        val end = store.long(PAUSED_UNTIL)
        val kept = Allowances.clamp(end, now, PAUSE_MS)
        if (kept != end.takeIf { it != 0L }) store.putLong(PAUSED_UNTIL, kept ?: 0)
        return kept
    }

    /** Allows trackers in the app [packageName] for an hour from [now] ("Allow trackers in this app"). */
    fun allowApp(packageName: String, now: Long) {
        if (packageName == self) return
        store.putStrings(APPS, appEnds().filterKeys { it != packageName }.entries.map { "${it.key}\t${it.value}" }.toSet() + "$packageName\t${now + APP_MS}")
    }

    /** Ends the app's allowance before its hour ("Block trackers again"); the rows allowed in it keep theirs. */
    fun blockAppAgain(packageName: String) {
        store.putStrings(APPS, appEnds().filterKeys { it != packageName }.entries.map { "${it.key}\t${it.value}" }.toSet())
    }

    /**
     * The apps allowed now, each with when its allowance ends on the phone's clock: those ended are forgotten, and an
     * end more than an hour after [now] (a clock set back) is brought back to an hour from now and kept so.
     */
    fun appsAllowed(now: Long): Map<String, Long> {
        val ends = appEnds()
        val kept = ends.mapNotNull { (name, end) -> Allowances.clamp(end, now, APP_MS)?.let { name to it } }.toMap()
        if (kept != ends) store.putStrings(APPS, kept.entries.map { "${it.key}\t${it.value}" }.toSet())
        return kept
    }

    /** Allows the rows [hosts] in the app [packageName] until blocked again: one tracker, or one company's (the history). */
    fun allowEntries(packageName: String, hosts: Collection<String>) {
        if (packageName == self) return
        store.putStrings(ENTRIES, store.strings(ENTRIES) + hosts.map { "$packageName\t$it" })
    }

    /** Blocks the rows [hosts] in the app [packageName] again. */
    fun blockEntriesAgain(packageName: String, hosts: Collection<String>) {
        store.putStrings(ENTRIES, store.strings(ENTRIES) - hosts.map { "$packageName\t$it" }.toSet())
    }

    /** The rows allowed, each as its app's package and its host. */
    fun entriesAllowed(): Set<Pair<String, String>> = store.strings(ENTRIES).mapNotNull { line ->
        line.split('\t').takeIf { it.size == 2 && it[0].isNotEmpty() && it[1].isNotEmpty() }?.let { it[0] to it[1] }
    }.toSet()

    /** Forgets everything here, blocking off again: ADR 0047's wipe (W9), beside the apps left out of the tunnel. */
    fun wipe() = store.clear()

    private fun appEnds(): Map<String, Long> = store.strings(APPS).mapNotNull { line ->
        val parts = line.split('\t')
        val end = parts.getOrNull(1)?.toLongOrNull()
        if (parts.size == 2 && parts[0].isNotEmpty() && end != null) parts[0] to end else null
    }.toMap()

    companion object {
        /** How long one tap allows an app: an hour, or until "Block trackers again". */
        const val APP_MS = 60 * 60 * 1000L

        /** How long the global pause lasts: ten minutes, or until "Block again now". */
        const val PAUSE_MS = 10 * 60 * 1000L

        private const val PREFS = "blocking"
        private const val ON = "on"
        private const val BROWSERS = "browsers"
        private const val TOOL_DNS = "tool_dns"
        private const val PAUSED_UNTIL = "paused_until"
        private const val APPS = "apps_allowed"
        private const val ENTRIES = "entries_allowed"

        fun of(context: Context): BlockingSettings {
            val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return BlockingSettings(Preferences(prefs), context.packageName)
        }
    }

    private class Preferences(private val prefs: SharedPreferences) : Store {
        override fun boolean(key: String) = prefs.getBoolean(key, false)
        override fun putBoolean(key: String, value: Boolean) = prefs.edit { putBoolean(key, value) }
        override fun long(key: String) = prefs.getLong(key, 0)
        override fun putLong(key: String, value: Long) = prefs.edit { putLong(key, value) }
        override fun strings(key: String): Set<String> = prefs.getStringSet(key, emptySet()).orEmpty().toSet()
        override fun putStrings(key: String, value: Set<String>) = prefs.edit { putStringSet(key, value) }
        override fun clear() = prefs.edit { clear() }
    }
}

/**
 * The rule every timed allowance keeps (the app's hour, the global pause's ten minutes): what is left of one is worked
 * out at each decision from its end on the phone's clock, never by an alarm, and never more than its length, so that a
 * clock set back cannot stretch it.
 */
object Allowances {
    /** What is left of an allowance ending at [end], at [now], at most [most]: 0 once it ended. */
    fun left(end: Long, now: Long, most: Long): Long = (end - now).coerceIn(0, most)

    /** The end to keep for one ending at [end]: null once it ended (or for none, 0), and at most [most] after [now]. */
    fun clamp(end: Long, now: Long, most: Long): Long? = if (end == 0L || end <= now) null else minOf(end, now + most)
}
