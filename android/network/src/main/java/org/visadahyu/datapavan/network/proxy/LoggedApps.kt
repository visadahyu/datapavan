package org.visadahyu.datapavan.network.proxy

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import androidx.core.content.edit
import org.visadahyu.datapavan.network.NetworkVpnService

/**
 * The user's choice for one app, "Log where APP connects through a proxy" (the proxy record's unit C, R3; ADR 0052,
 * decision 8), and for one circumvention tool, "Log where TOOL connects for itself" (unit D, R10, D7), in the
 * preferences `logged_proxies` of the network process: one line per package, its kind, its package name and its first
 * install time, never a UID, and nothing of any flow. The kind is `app` for an app's choice and `tool` for a tool's
 * ([Kind]); a line of a kind this build does not know stays as it is, and is never read as either (audit-C 23).
 *
 * Why the first install time: Android gives a removed app's UID to another after a reboot, and a package name can be
 * installed again by anyone. An entry whose package is gone, or whose first install time changed, is dropped at the
 * next hand-over ([handed]) and never comes back; an update keeps the first install time, and so the choice. A package
 * found gone is remembered in this process's memory alone ([Ended.REMOVED]), so that, installed again while the process
 * lives, its rows say so, as they do when the network part saw only the new first install time (review C-rest 1). A UID
 * is handed only while every package that holds it now was chosen, so a package that joins it ends the choice; never
 * Android's own UIDs, a circumvention tool's or Android's PAC handler's. A tool's choice is handed only while its UID is
 * a tool's that can carry traffic inside the VPN (`chain.Tools.carriers`); one that is no tool now is dropped, and says
 * nothing (D7). Neither kind is handed before the tools were read in a run (audit-D m8). The engine decides what is
 * logged, per flow, and leaves out a flow it reads as through Android's setting or a local proxy whatever is handed.
 *
 * Under ADR 0047's profile ([setProfile]) nothing of it is written: the lines live in this process alone
 * ([Session.PROCESS], which the screens and the service share), and are lost when it ends; [clearSession], at W9's
 * screen-off, empties them; turning the profile off writes nothing and restores nothing (ADR 0047, decision 4; audit-C
 * major 2). [wipe] empties both, for W9's wipe. Each of these, and each choice, asks the running service to hand the
 * choice to the engine again ([changed]), so that no caller can forget it (audit-C 4). The profile's and the wipe's
 * writes reach the disk before they return (review C-rest 12). The store sits behind Advanced's lock once W9 brings it,
 * as `BlockingSettings` does; until then it is as readable as the chain's list of apps.
 *
 * The network process's alone (review C-rest 5): the session's lines and the service it asks live there, and Android's
 * preferences are not shared safely between processes, so a caller in another process would wipe a copy that the
 * network process then writes back. W9 calls [setProfile], [clearSession] and [wipe] in it, through an intent to the
 * service or a receiver declared in `:network`; [of] refuses any other process.
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

        /** Writes the lines and the flag together, in one edit: on disk before it returns where [durable]. */
        fun write(lines: Set<String>, memoryOnly: Boolean, durable: Boolean = false)
    }

    /** One package chosen, by its name and its first install time, as Android's package manager gives them. */
    data class Entry(val packageName: String, val firstInstall: Long)

    /**
     * The kind of a choice, as its lines write it: [APP], "Log where APP connects through a proxy" (unit C), or [TOOL],
     * "Log where TOOL connects for itself" (unit D).
     */
    enum class Kind(internal val word: String) { APP("app"), TOOL("tool") }

    /**
     * Why an app's choice ended without the user (audit-C 13): it was installed again ([INSTALLED_AGAIN]), Android now
     * counts another app with it ([SHARED]), or Datapavan now counts it as a circumvention tool, by its signing key or
     * as the chain's tool ([TOOL]); each said on that app's rows. Or its package was gone at a hand-over ([REMOVED]),
     * which no row says, and which becomes [INSTALLED_AGAIN] when the package comes back (review C-rest 1). Kept in
     * this process for its life; never on disk.
     */
    enum class Ended { INSTALLED_AGAIN, SHARED, TOOL, REMOVED }

    /**
     * What one hand-over gives: the apps' UIDs to hand the engine, sorted; the apps' entries found stale; and why each
     * ended; then the tools' UIDs to hand the engine, sorted, and the tools' entries found stale (unit D).
     */
    data class Handed(
        val uids: List<Int>,
        val stale: Set<Entry>,
        val ended: Map<String, Ended>,
        val tools: List<Int> = emptyList(),
        val staleTools: Set<Entry> = emptySet(),
    )

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

    /**
     * The packages chosen of the kind [kind], with their first install times, as kept: on disk, or in memory under the
     * profile.
     */
    fun entries(kind: Kind = Kind.APP): Set<Entry> = synchronized(session) { current().mapNotNull { entryOf(it, kind) }.toSet() }

    /**
     * Chooses one app, or with [Kind.TOOL] one tool: every package of its UID with its first install time, for a shared
     * UID ([entriesOfUid]).
     */
    fun choose(entries: Collection<Entry>, kind: Kind = Kind.APP) {
        if (entries.isEmpty()) return
        val names = entries.map { it.packageName }.toSet()
        synchronized(session) {
            put(current().filterNot { entryOf(it, kind)?.packageName in names }.toSet() + entries.map { line(it, kind) })
            if (kind == Kind.APP) names.forEach(session.ended::remove)
        }
        changed()
    }

    /** Ends the choice of the kind [kind] for the packages [packages]: from now on the engine strips what they kept (R6). */
    fun stop(packages: Collection<String>, kind: Kind = Kind.APP) {
        synchronized(session) { put(current().filterNot { entryOf(it, kind)?.packageName in packages }.toSet()) }
        changed()
    }

    /**
     * Forgets what the hand-over found stale, and keeps why each app's choice ended, in memory, for its rows. The service
     * calls it as it hands the choice, so it asks for no hand-over again.
     */
    fun drop(handed: Handed) {
        if (handed.stale.isEmpty() && handed.ended.isEmpty() && handed.staleTools.isEmpty()) return
        synchronized(session) {
            val gone = handed.stale.map { line(it, Kind.APP) } + handed.staleTools.map { line(it, Kind.TOOL) }
            if (gone.isNotEmpty()) put(current() - gone.toSet())
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
        handed(entries(), packages, tools, pacHandler, ready = true).uids.toSet()

    /**
     * The tools' UIDs the hand-over hands now ([handed]'s [Handed.tools]), for the screens, by the same rule, [tools]
     * being the tools whose own connections follow R10 (unit D). It writes nothing.
     */
    fun toolsChosen(packages: Packages, tools: Set<Int>): Set<Int> =
        handed(emptySet(), packages, tools, null, ready = true, toolEntries = entries(Kind.TOOL)).tools.toSet()

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
                    store.write(emptySet(), memoryOnly = true, durable = true)
                }
                !on && store.memoryOnly() -> {
                    session.lines = emptySet()
                    session.ended.clear()
                    store.write(emptySet(), memoryOnly = false, durable = true)
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
            store.write(emptySet(), store.memoryOnly(), durable = true)
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

        /**
         * The store of this process, whose changes the running service hands to the engine at once
         * ([NetworkVpnService.ACTION_APPLY_PROXIES]); in the network process alone (review C-rest 5).
         */
        fun of(context: Context): LoggedApps {
            check(android.app.Application.getProcessName().endsWith(":network")) { "The choice for one app is the network process's alone" }
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
         * hold. An entry whose package is missing, or whose first install time differs, is stale, and needs no tools.
         * For each UID of the others, its entries are stale when it is not an application UID, when a package holds it
         * now that was not chosen, or, once the service is [ready] (the tools read in this run, and under strict
         * Private DNS the setting's names looked up), when it is a circumvention tool's ([tools]) or Android's PAC
         * handler's ([pacHandler]); else it is handed. Before, no UID is handed: a tool whose key is known is then
         * never covered in the seconds after a start, nor a flow to Android's setting before its addresses are known. A
         * package found gone at an earlier hand-over ([before], [Ended.REMOVED]) and installed now was installed again.
         *
         * The tools chosen ([toolEntries], unit D, D7) by the same rule, but the other way round: once [ready], a tool's
         * UID is handed only while it is one of [tools], the tools whose own connections follow R10, and its entries are
         * stale while it is not (its key changed, or the chain's tool is another now). Before, none is handed and none is
         * found stale for it, as the apps wait (audit-D m8): a choice is never lost in the seconds after a start. A
         * tool's choice that ended keeps no reason: its rows say nothing of it.
         */
        fun handed(
            entries: Set<Entry>,
            packages: Packages,
            tools: Set<Int>,
            pacHandler: Int?,
            ready: Boolean,
            before: Map<String, Ended> = emptyMap(),
            toolEntries: Set<Entry> = emptySet(),
        ): Handed {
            val stale = HashSet<Entry>()
            val ended = HashMap<String, Ended>()
            for ((name, why) in before) {
                if (why == Ended.REMOVED && packages.firstInstallOf(name) != null) ended[name] = Ended.INSTALLED_AGAIN
            }
            val byUid = HashMap<Int, MutableList<Entry>>()
            for (entry in entries) {
                val uid = packages.uidOf(entry.packageName)
                val installed = packages.firstInstallOf(entry.packageName)
                when {
                    // Removed: remembered in memory, so that its rows say so if it comes back while the process lives.
                    uid == null || installed == null -> {
                        stale += entry
                        ended[entry.packageName] = Ended.REMOVED
                    }
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
                    !ready -> continue
                    uid in tools || uid == pacHandler -> Ended.TOOL
                    else -> {
                        uids += uid
                        continue
                    }
                }
                stale += fresh
                for (entry in fresh) ended[entry.packageName] = why
            }
            val staleTools = HashSet<Entry>()
            val toolsByUid = HashMap<Int, MutableList<Entry>>()
            for (entry in toolEntries) {
                val uid = packages.uidOf(entry.packageName)
                if (uid == null || packages.firstInstallOf(entry.packageName) != entry.firstInstall) {
                    staleTools += entry
                } else {
                    toolsByUid.getOrPut(uid) { mutableListOf() } += entry
                }
            }
            val toolUids = mutableListOf<Int>()
            for ((uid, fresh) in toolsByUid) {
                val chosen = fresh.map { it.packageName }.toSet()
                when {
                    !ProxyChoice.application(uid) || packages.packagesOf(uid).any { it !in chosen } -> staleTools += fresh
                    !ready -> continue
                    uid in tools -> toolUids += uid
                    else -> staleTools += fresh
                }
            }
            return Handed(uids.sorted(), stale, ended, toolUids.sorted(), staleTools)
        }

        /** The entries of every package of [uid], each with its first install time, for one choice of a shared UID too. */
        fun entriesOfUid(packages: Packages, uid: Int): List<Entry> =
            packages.packagesOf(uid).sorted().mapNotNull { name -> packages.firstInstallOf(name)?.let { Entry(name, it) } }

        /**
         * What one choice of [uid] writes, once its confirmation said yes having named the packages [named] (review
         * C-rest 9): the entries of those alone, so that a package that joined the UID while it was open is never
         * chosen unnamed, and the next hand-over ends the choice as one Android counts another app with
         * ([Ended.SHARED]). A confirmation that named none, the app's names not read yet, chooses a UID of one package
         * alone.
         */
        fun entriesNamed(packages: Packages, uid: Int, named: Collection<String>): List<Entry> {
            val entries = entriesOfUid(packages, uid)
            return if (named.isEmpty()) entries.takeIf { it.size == 1 }.orEmpty() else entries.filter { it.packageName in named }
        }

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
         * Whether the debug builds' `proxy-log PACKAGE on|off` and `tool-log PACKAGE on|off` may write the choice for
         * [packageName]: a package of this project's own (`org.visadahyu.datapavan.` and after), never a real app's, as
         * `messenger-client` refuses one.
         */
        fun debugAllowed(packageName: String): Boolean = packageName.startsWith("org.visadahyu.datapavan.")

        internal fun line(entry: Entry, kind: Kind = Kind.APP): String = "${kind.word}\t${entry.packageName}\t${entry.firstInstall}"

        /** The entry of a line of the kind [kind]; null for another kind's, or a line that does not parse. */
        internal fun entryOf(line: String, kind: Kind = Kind.APP): Entry? {
            val parts = line.split('\t')
            val time = parts.getOrNull(2)?.toLongOrNull()
            return if (parts.size == 3 && parts[0] == kind.word && parts[1].isNotEmpty() && time != null) Entry(parts[1], time) else null
        }
    }

    private class Preferences(private val prefs: SharedPreferences) : Store {
        override fun lines(): Set<String> = prefs.getStringSet(LINES, emptySet()).orEmpty().toSet()
        override fun memoryOnly() = prefs.getBoolean(MEMORY_ONLY, false)
        override fun write(lines: Set<String>, memoryOnly: Boolean, durable: Boolean) = prefs.edit(commit = durable) {
            if (lines.isEmpty()) remove(LINES) else putStringSet(LINES, lines)
            putBoolean(MEMORY_ONLY, memoryOnly)
        }
    }
}
