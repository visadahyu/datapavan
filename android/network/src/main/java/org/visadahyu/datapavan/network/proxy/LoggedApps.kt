package org.visadahyu.datapavan.network.proxy

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import androidx.core.content.edit
import org.visadahyu.datapavan.network.NetworkVpnService

/**
 * The user's choice for one app, "Log where APP connects through a proxy" (the proxy record's unit C, R3; ADR 0052,
 * decision 8), in the preferences `logged_proxies` of the network process: one line per package, its kind, its package
 * name and its first install time, never a UID, and nothing of any flow. The kind is `app` for this choice; unit D adds
 * the tools' own choice as a kind of its own in the same lines, which this build keeps as they are and reads nothing of
 * (audit-C 23).
 *
 * Why the first install time: Android gives a removed app's UID to another after a reboot, and a package name can be
 * installed again by anyone. An entry whose package is gone, or whose first install time changed, is dropped at the next
 * hand-over ([handed]) and never comes back; an update keeps the first install time, and so the choice. A UID is handed
 * only while every package that holds it now was chosen, so a package that joins it ends the choice; never Android's own
 * UIDs, a circumvention tool's or Android's PAC handler's. The engine decides what is logged, per flow, and leaves out
 * Android's setting and a local proxy whatever is handed.
 *
 * Under ADR 0047's profile ([setProfile]) nothing of it is written: the lines live in this process alone
 * ([Session.PROCESS], which the screens and the service share), and are lost when it ends; [clearSession], at W9's
 * screen-off, empties them; turning the profile off writes nothing and restores nothing (ADR 0047, decision 4; audit-C
 * major 2). [wipe] empties both, for W9's wipe. Each of these, and each choice, asks the running service to hand the
 * choice to the engine again ([changed]), so that no caller can forget it (audit-C 4). The store sits behind Advanced's
 * lock once W9 brings it, as `BlockingSettings` does; until then it is as readable as the chain's list of apps.
 */
class LoggedApps internal constructor(
    private val store: Store,
    private val session: Session = Session.PROCESS,
    private val changed: () -> Unit = {},
) {
    /** Where the choice is kept: SharedPreferences on the phone ([of]), a map in the JVM tests. */
    interface Store {
        /** The lines kept on disk. */
        fun lines(): Set<String>

        /** Whether ADR 0047's profile keeps the choice in memory only: a flag that names no app. */
        fun memoryOnly(): Boolean

        /** Writes the lines and the flag together, in one edit. */
        fun write(lines: Set<String>, memoryOnly: Boolean)
    }

    /** One package chosen, by its name and its first install time, as Android's package manager gives them. */
    data class Entry(val packageName: String, val firstInstall: Long)

    /**
     * Why an app's choice ended without the user (audit-C 13): it was installed again ([INSTALLED_AGAIN]), Android now
     * counts another app with it ([SHARED]), or Datapavan now knows it as a circumvention tool by its signing key
     * ([TOOL]). Kept in this process for its run, and said on that app's rows; never on disk.
     */
    enum class Ended { INSTALLED_AGAIN, SHARED, TOOL }

    /** What one hand-over gives: the UIDs to hand the engine, sorted; the entries found stale; and why each ended. */
    data class Handed(val uids: List<Int>, val stale: Set<Entry>, val ended: Map<String, Ended>)

    /** What Android's package manager says: a package's UID and first install time, and a UID's packages. */
    interface Packages {
        fun uidOf(packageName: String): Int?
        fun firstInstallOf(packageName: String): Long?
        fun packagesOf(uid: Int): List<String>
    }

    /**
     * What this process holds of the choice: its lines while the profile keeps them in memory only, and which apps'
     * choices ended in this run, and why. One for the whole network process ([PROCESS]); a test makes its own.
     */
    class Session {
        internal var lines: Set<String> = emptySet()
        internal val ended = HashMap<String, Ended>()

        companion object {
            /** The network process's own, which its screens and its service share. */
            val PROCESS = Session()
        }
    }

    /** Whether the profile keeps the choice in memory only. */
    val memoryOnly: Boolean get() = synchronized(session) { store.memoryOnly() }

    /** The packages chosen, with their first install times, as kept: on disk, or in memory under the profile. */
    fun entries(): Set<Entry> = synchronized(session) { current().mapNotNull(::entryOf).toSet() }

    /** Chooses one app: every package of its UID with its first install time, for a shared UID ([entriesOfUid]). */
    fun choose(entries: Collection<Entry>) {
        if (entries.isEmpty()) return
        val names = entries.map { it.packageName }.toSet()
        synchronized(session) {
            put(current().filterNot { entryOf(it)?.packageName in names }.toSet() + entries.map(::line))
            names.forEach(session.ended::remove)
        }
        changed()
    }

    /** Ends the choice for the packages [packages]: from now on the engine strips what they kept (R6). */
    fun stop(packages: Collection<String>) {
        synchronized(session) { put(current().filterNot { entryOf(it)?.packageName in packages }.toSet()) }
        changed()
    }

    /**
     * Forgets what the hand-over found stale, and keeps why each app's choice ended, in memory, for its rows. The service
     * calls it as it hands the choice, so it asks for no hand-over again.
     */
    fun drop(handed: Handed) {
        if (handed.stale.isEmpty() && handed.ended.isEmpty()) return
        synchronized(session) {
            if (handed.stale.isNotEmpty()) put(current() - handed.stale.map(::line).toSet())
            session.ended.putAll(handed.ended)
        }
    }

    /** Why each package's choice ended in this run, by package. */
    fun ended(): Map<String, Ended> = synchronized(session) { HashMap(session.ended) }

    /**
     * The app UIDs the hand-over hands now, for the screens, by the same rule ([handed]), so that a row and the engine
     * agree on an app installed again or become a tool meanwhile (audit-C 12). It writes nothing.
     */
    fun chosen(packages: Packages, tools: Set<Int>, pacHandler: Int?): Set<Int> =
        handed(entries(), packages, tools, pacHandler, toolsRead = true).uids.toSet()

    /**
     * ADR 0047's profile on or off, by W9's switch (and the debug builds' `tunnel-profile on|off`). On, the lines on disk
     * are deleted and kept in memory for this session; off, the session's go and nothing is written, so that a choice
     * made while nothing was recorded never starts a record (audit-C major 2).
     */
    fun setProfile(on: Boolean) {
        synchronized(session) {
            when {
                on && !store.memoryOnly() -> {
                    session.lines = store.lines()
                    store.write(emptySet(), memoryOnly = true)
                }
                !on && store.memoryOnly() -> {
                    session.lines = emptySet()
                    session.ended.clear()
                    store.write(emptySet(), memoryOnly = false)
                }
            }
        }
        changed()
    }

    /** At W9's screen-off under the profile: the session's choices, and why any ended, go. Outside it, nothing. */
    fun clearSession() {
        synchronized(session) {
            if (!store.memoryOnly()) return
            session.lines = emptySet()
            session.ended.clear()
        }
        changed()
    }

    /** ADR 0047's wipe (W9): every choice, on disk and in memory, and why any ended; the profile's flag stays. */
    fun wipe() {
        synchronized(session) {
            session.lines = emptySet()
            session.ended.clear()
            store.write(emptySet(), store.memoryOnly())
        }
        changed()
    }

    private fun current(): Set<String> = if (store.memoryOnly()) session.lines else store.lines()

    private fun put(lines: Set<String>) {
        if (store.memoryOnly()) session.lines = lines else store.write(lines, memoryOnly = false)
    }

    companion object {
        private const val PREFS = "logged_proxies"
        private const val LINES = "lines"
        private const val MEMORY_ONLY = "memory_only"

        /** The kind of a line of this choice; unit D's tools are a kind of their own. */
        private const val APP = "app"

        /**
         * The store of this process, whose changes the running service hands to the engine at once
         * ([NetworkVpnService.ACTION_APPLY_PROXIES]).
         */
        fun of(context: Context): LoggedApps {
            val app = context.applicationContext
            return LoggedApps(Preferences(app.getSharedPreferences(PREFS, Context.MODE_PRIVATE))) { apply(app) }
        }

        /** Has the running service hand the choice to the engine again; nothing while the tunnel is off. */
        private fun apply(context: Context) {
            if (!NetworkVpnService.running.value) return
            try {
                context.startService(Intent(context, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_PROXIES))
            } catch (e: IllegalStateException) {
                // Android refused a start from the background: the next hand-over carries it.
            } catch (e: SecurityException) {
                // Likewise.
            }
        }

        /**
         * The UIDs to hand the engine of the chosen [entries], and the entries stale, as a pure function the JVM tests
         * hold. An entry whose package is missing, or whose first install time differs, is stale, and needs no tools. For
         * each UID of the others, its entries are stale when it is not an application UID, when a package holds it now
         * that was not chosen, or, once the tools were read in this run ([toolsRead]), when it is a circumvention tool's
         * ([tools]) or Android's PAC handler's ([pacHandler]); else it is handed. Before the tools were read, no UID is
         * handed: a tool whose key is known is then never covered in the seconds after a start.
         */
        fun handed(entries: Set<Entry>, packages: Packages, tools: Set<Int>, pacHandler: Int?, toolsRead: Boolean): Handed {
            val stale = HashSet<Entry>()
            val ended = HashMap<String, Ended>()
            val byUid = HashMap<Int, MutableList<Entry>>()
            for (entry in entries) {
                val uid = packages.uidOf(entry.packageName)
                val installed = packages.firstInstallOf(entry.packageName)
                when {
                    // Removed: nothing to tell, the app is gone.
                    uid == null || installed == null -> stale += entry
                    installed != entry.firstInstall -> {
                        stale += entry
                        ended[entry.packageName] = Ended.INSTALLED_AGAIN
                    }
                    else -> byUid.getOrPut(uid) { mutableListOf() } += entry
                }
            }
            val uids = mutableListOf<Int>()
            for ((uid, fresh) in byUid) {
                val chosen = fresh.map { it.packageName }.toSet()
                val others = packages.packagesOf(uid).filter { it !in chosen }
                val why = when {
                    !ProxyChoice.application(uid) || others.isNotEmpty() ->
                        if (others.any { ended[it] == Ended.INSTALLED_AGAIN }) Ended.INSTALLED_AGAIN else Ended.SHARED
                    !toolsRead -> continue
                    uid in tools || uid == pacHandler -> Ended.TOOL
                    else -> {
                        uids += uid
                        continue
                    }
                }
                stale += fresh
                for (entry in fresh) ended[entry.packageName] = why
            }
            return Handed(uids.sorted(), stale, ended)
        }

        /** The entries of every package of [uid], each with its first install time, for one choice of a shared UID too. */
        fun entriesOfUid(packages: Packages, uid: Int): List<Entry> =
            packages.packagesOf(uid).sorted().mapNotNull { name -> packages.firstInstallOf(name)?.let { Entry(name, it) } }

        /** Android's package manager as [handed] reads it. Each call asks it once: any thread. */
        @Suppress("DEPRECATION") // getApplicationInfo(String, Int) and getPackageInfo(String, Int): the minimum SDK takes both.
        fun packages(manager: PackageManager): Packages = object : Packages {
            override fun uidOf(packageName: String): Int? = try {
                manager.getApplicationInfo(packageName, 0).uid
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }

            override fun firstInstallOf(packageName: String): Long? = try {
                manager.getPackageInfo(packageName, 0).firstInstallTime
            } catch (e: PackageManager.NameNotFoundException) {
                null
            }

            override fun packagesOf(uid: Int): List<String> = manager.getPackagesForUid(uid)?.toList().orEmpty()
        }

        /**
         * Whether the debug builds' `proxy-log PACKAGE on|off` may write the choice for [packageName]: a package of this
         * project's own (`org.visadahyu.datapavan.` and after), never a real app's, as `messenger-client` refuses one.
         */
        fun debugAllowed(packageName: String): Boolean = packageName.startsWith("org.visadahyu.datapavan.")

        internal fun line(entry: Entry): String = "$APP\t${entry.packageName}\t${entry.firstInstall}"

        /** The entry of a line of this choice's kind; null for another kind's, or a line that does not parse. */
        internal fun entryOf(line: String): Entry? {
            val parts = line.split('\t')
            val time = parts.getOrNull(2)?.toLongOrNull()
            return if (parts.size == 3 && parts[0] == APP && parts[1].isNotEmpty() && time != null) Entry(parts[1], time) else null
        }
    }

    private class Preferences(private val prefs: SharedPreferences) : Store {
        override fun lines(): Set<String> = prefs.getStringSet(LINES, emptySet()).orEmpty().toSet()
        override fun memoryOnly() = prefs.getBoolean(MEMORY_ONLY, false)
        override fun write(lines: Set<String>, memoryOnly: Boolean) = prefs.edit {
            if (lines.isEmpty()) remove(LINES) else putStringSet(LINES, lines)
            putBoolean(MEMORY_ONLY, memoryOnly)
        }
    }
}
