package org.visadahyu.datapavan.watch.tunnel

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * The WireGuard configurations Watch keeps (W7, part 2, ADR 0035), each in a slot of its own, numbered from 1 and
 * never numbered again while an app is routed to it: its text and its name, each wrapped by [wrap] (the Keystore's
 * AES-256-GCM key, [KeystoreWrap]) with the slot's number bound to it, in files under [dir], which is in Watch's
 * `noBackupFilesDir`: out of cloud backup and device-to-device transfer, as the application's data extraction
 * rules also say of every file of both editions. Beside them, in plain text, what Watch must read without opening
 * a key, so that a configuration that cannot be opened still holds its apps: the slots in order, the default
 * first; which have "Local network directly"; the next slot's number; and each app routed to a slot, by package
 * name, as the chain keeps its apps (ADR 0047's table lists both).
 *
 * The text never becomes a `String`: it is handed in and out as bytes, which the caller zeroes after use. A change
 * leaves the store as it was or changes it whole (W7, part 2, fix round, security review M3): every wrap is made
 * first, so that a Keystore error changes nothing; then every file the change writes is written beside its own,
 * flushed to the disk, so that a full disk changes nothing either; and only then is each put in place of its own
 * by a rename, which takes no space. One store per process ([of]); its methods hold its lock.
 */
class TunnelStore(private val dir: File, private val wrap: Wrap, private val disk: Disk = Disk.SYNCED) {
    /** Writes a file's bytes to the disk, flushed; the tests' own fills up. */
    fun interface Disk {
        fun write(file: File, bytes: ByteArray)

        companion object {
            val SYNCED = Disk { file, bytes ->
                FileOutputStream(file).use { out ->
                    out.write(bytes)
                    out.fd.sync()
                }
            }
        }
    }

    /** A change that named a slot no configuration holds any more: removed while the confirmation was open. */
    class SlotGone(slot: Int) : IllegalArgumentException("No configuration in slot $slot")

    /** What the store keeps in plain text. */
    data class State(
        /** The slots that hold a configuration, the default first. */
        val order: List<Int> = emptyList(),
        /** The slots whose apps reach the local network directly (ADR 0035, question 8). */
        val local: Set<Int> = emptySet(),
        /** The number the next configuration takes. */
        val next: Int = 1,
        /** Each app sent through a tunnel, by package name, to its slot; a slot removed with its apps waiting stays. */
        val routes: Map<String, Int> = emptyMap(),
    ) {
        /** The default tunnel's slot, the first. */
        val default: Int? get() = order.firstOrNull()

        /** Whether the engine's bound is reached. */
        val full: Boolean get() = order.size >= MAX
    }

    /** A configuration's name, as far as it can be read now. */
    sealed interface Name {
        data class Known(val name: String) : Name

        /** The key works only on an unlocked phone, which is locked. */
        data object Locked : Name

        /** The Keystore or the disk erred: it cannot be opened now, and Watch tries again ([Opened.Unavailable]). */
        data object Unavailable : Name

        /** The key is gone or the wrap damaged: the configuration cannot be opened again. */
        data object Lost : Name

        /** No configuration holds the slot: it was removed, its apps perhaps still waiting. */
        data object Removed : Name
    }

    private val stateFile = File(dir, STATE)

    /** Names read since the store's last change: reading one opens a wrap, which StrongBox makes slow. */
    private val names = mutableMapOf<Int, Name.Known>()

    @Synchronized
    fun state(): State = read()

    /**
     * Keeps a new configuration under [name] (see [cleanName]), with "Local network directly" as [local] and the
     * [apps] sent through it, in one change, and returns its slot; null when the engine's bound ([MAX]) is reached.
     * [text] is the caller's, which it zeroes.
     */
    @Synchronized
    fun add(name: String, text: ByteArray, local: Boolean = false, apps: Set<String> = emptySet()): Int? {
        require(apps.all { PACKAGE.matches(it) }) { "Not a package name" }
        val state = read()
        if (state.full) return null
        val slot = generateSequence(state.next) { it + 1 }.first { it !in state.order && it !in state.routes.values }
        val added = state.copy(
            order = state.order + slot,
            local = if (local) state.local + slot else state.local,
            next = slot + 1,
            routes = state.routes + apps.associateWith { slot },
        )
        commit(
            listOf(
                file(slot, Wrap.Part.TEXT) to wrap.wrap(slot, Wrap.Part.TEXT, text),
                file(slot, Wrap.Part.NAME) to wrappedName(slot, name),
                stateFile to encode(added),
            ),
        )
        wrote(slot)
        return slot
    }

    /**
     * Puts [text] in place of the slot's configuration, its apps and switches kept, and [name] if given; [SlotGone]
     * when the slot was removed meanwhile.
     */
    @Synchronized
    fun replace(slot: Int, text: ByteArray, name: String?) {
        if (slot !in read().order) throw SlotGone(slot)
        commit(
            listOfNotNull(
                file(slot, Wrap.Part.TEXT) to wrap.wrap(slot, Wrap.Part.TEXT, text),
                name?.let { file(slot, Wrap.Part.NAME) to wrappedName(slot, it) },
            ),
        )
        wrote(slot)
    }

    /** Names the slot's configuration anew; its text is not opened. */
    @Synchronized
    fun rename(slot: Int, name: String) {
        if (slot !in read().order) throw SlotGone(slot)
        commit(listOf(file(slot, Wrap.Part.NAME) to wrappedName(slot, name)))
        names.remove(slot)
    }

    /**
     * Removes the slot's configuration. Its apps stay routed to the slot and wait, never going directly, while
     * [appsWait] (the screen asks the user); otherwise they go their other way, directly or through the tool.
     */
    @Synchronized
    fun remove(slot: Int, appsWait: Boolean) {
        val state = read()
        // The state first: a disk that fails leaves the configuration as it was; its wraps go once it is out.
        write(
            state.copy(
                order = state.order - slot,
                local = state.local - slot,
                routes = if (appsWait) state.routes else state.routes.filterValues { it != slot },
            ),
        )
        for (part in Wrap.Part.entries) file(slot, part).delete()
        names.remove(slot)
    }

    @Synchronized
    fun setLocal(slot: Int, on: Boolean) {
        val state = read()
        if (slot !in state.order) return
        write(state.copy(local = if (on) state.local + slot else state.local - slot))
    }

    /** Makes the slot's configuration the default tunnel: flows of no app and ping take it while any app is tunnelled. */
    @Synchronized
    fun setDefault(slot: Int) {
        val state = read()
        if (slot !in state.order) return
        write(state.copy(order = listOf(slot) + (state.order - slot)))
    }

    /** Sends the app [packageName] through the slot's configuration, or, with null, its other way. */
    @Synchronized
    fun route(packageName: String, slot: Int?) {
        require(PACKAGE.matches(packageName)) { "Not a package name" }
        val state = read()
        write(state.copy(routes = if (slot == null) state.routes - packageName else state.routes + (packageName to slot)))
    }

    /** The slot's name, read from its wrap the first time. */
    @Synchronized
    fun name(slot: Int): Name {
        names[slot]?.let { return it }
        val file = file(slot, Wrap.Part.NAME)
        if (!file.isFile) return Name.Removed
        val wrapped = try {
            file.readBytes()
        } catch (e: IOException) {
            return Name.Unavailable
        }
        return when (val opened = wrap.unwrap(slot, Wrap.Part.NAME, wrapped)) {
            is Opened.Plain -> Name.Known(String(opened.bytes, Charsets.UTF_8)).also {
                opened.bytes.fill(0)
                names[slot] = it
            }
            Opened.Locked -> Name.Locked
            Opened.Unavailable -> Name.Unavailable
            Opened.Lost -> Name.Lost
        }
    }

    /**
     * The slot's configuration, for the engine: the bytes in [Opened.Plain] are the caller's to zero. A file that
     * cannot be read now is [Opened.Unavailable], as a Keystore error is: tried again, never taken as lost.
     */
    @Synchronized
    fun text(slot: Int): Opened {
        val file = file(slot, Wrap.Part.TEXT)
        if (!file.isFile) return Opened.Lost
        val wrapped = try {
            file.readBytes()
        } catch (e: IOException) {
            return Opened.Unavailable
        }
        return wrap.unwrap(slot, Wrap.Part.TEXT, wrapped)
    }

    /** Where the key lives, for the screen. */
    fun home(): KeyHome = wrap.home()

    /**
     * What the slot's text was last written as, for the service to tell a configuration that changed from one it
     * already set: the file's time and length, and the count of this process's writes of it, so that two writes
     * within a tick of the file's time still differ. The IV is not read: that would read the file.
     */
    @Synchronized
    fun stamp(slot: Int): Long = file(slot, Wrap.Part.TEXT).let { it.lastModified() * 31 + it.length() + writes.getOrDefault(slot, 0) }

    /** The writes of each slot's text by this process, so that two within a file time's tick still differ. */
    private val writes = mutableMapOf<Int, Long>()

    private fun wrote(slot: Int) {
        writes[slot] = writes.getOrDefault(slot, 0) + 1
        names.remove(slot)
    }

    private fun wrappedName(slot: Int, name: String): ByteArray = wrap.wrap(slot, Wrap.Part.NAME, cleanName(name).toByteArray(Charsets.UTF_8))

    private fun file(slot: Int, part: Wrap.Part) = File(dir, "$slot.${part.label}")

    /**
     * Puts each file's bytes in place of it, all or none as far as the disk allows: each is first written to a new
     * file beside its own and flushed, and any failure there deletes them all and leaves every file as it was; then
     * each new file is renamed onto its own, which replaces it whole and needs no space.
     */
    private fun commit(files: List<Pair<File, ByteArray>>) {
        dir.mkdirs()
        val staged = mutableListOf<Pair<File, File>>()
        try {
            for ((target, bytes) in files) {
                val fresh = File(dir, "${target.name}.new")
                staged += fresh to target
                disk.write(fresh, bytes)
            }
            for ((fresh, target) in staged) {
                Files.move(fresh.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (e: IOException) {
            for ((fresh, _) in staged) fresh.delete()
            throw e
        }
    }

    private fun read(): State {
        if (!stateFile.isFile) return State()
        var order = emptyList<Int>()
        val local = mutableSetOf<Int>()
        var next = 1
        val routes = mutableMapOf<String, Int>()
        for (line in stateFile.readLines()) {
            val words = line.split(' ').filter { it.isNotEmpty() }
            when (words.firstOrNull()) {
                "order" -> order = words.drop(1).mapNotNull { it.toIntOrNull()?.takeIf { slot -> slot > 0 } }.distinct()
                "local" -> local += words.drop(1).mapNotNull { it.toIntOrNull() }
                "next" -> next = words.getOrNull(1)?.toIntOrNull()?.takeIf { it > 0 } ?: next
                "route" -> {
                    val app = words.getOrNull(1)?.takeIf { PACKAGE.matches(it) }
                    val slot = words.getOrNull(2)?.toIntOrNull()?.takeIf { it > 0 }
                    if (app != null && slot != null) routes[app] = slot
                }
            }
        }
        // A slot whose text is gone (a crash between two writes) is not offered; its apps keep waiting.
        order = order.filter { file(it, Wrap.Part.TEXT).isFile }
        return State(order, local intersect order.toSet(), next, routes)
    }

    private fun write(state: State) = commit(listOf(stateFile to encode(state)))

    private fun encode(state: State): ByteArray = buildString {
        append("order ${state.order.joinToString(" ")}\n")
        append("local ${state.local.sorted().joinToString(" ")}\n")
        append("next ${state.next}\n")
        for ((app, slot) in state.routes.toSortedMap()) append("route $app $slot\n")
    }.toByteArray(Charsets.US_ASCII)

    companion object {
        /** The engine's bound on configurations at once (core/net's `MAX_TUNNELS`). */
        const val MAX = 8

        /** The record's version, bound into each wrap's associated data. */
        const val VERSION: Byte = 1

        /** The longest name kept, in characters. */
        const val NAME_LENGTH = 64

        /**
         * How long after its [attempt]th try in a row a configuration that could not be opened now is tried again:
         * a pause that grows, bounded, then null, and it waits for the next change, start or unlock (fix round,
         * security review m2).
         */
        fun retryAfterMs(attempt: Int): Long? = RETRIES_MS.getOrNull(attempt)

        private val RETRIES_MS = listOf(2_000L, 5_000L, 15_000L, 30_000L, 60_000L)

        private const val STATE = "state"
        private val PACKAGE = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

        /**
         * A name as kept: no control or formatting characters (a direction override would reorder the screen's
         * sentence around it), spaces made one, at most [NAME_LENGTH] characters.
         */
        fun cleanName(name: String): String {
            val kept = name.replace(Regex("\\s+"), " ")
                .filterNot { Character.isISOControl(it) || Character.getType(it) == Character.FORMAT.toInt() }
                .replace(Regex(" +"), " ")
                .trim()
            if (kept.length <= NAME_LENGTH) return kept
            // Not between the two halves of a character outside the basic plane.
            val end = if (Character.isHighSurrogate(kept[NAME_LENGTH - 1])) NAME_LENGTH - 1 else NAME_LENGTH
            return kept.substring(0, end).trim()
        }

        @Volatile
        private var store: TunnelStore? = null

        /** The process's store, in `noBackupFilesDir/tunnels`. */
        fun of(context: Context): TunnelStore = store ?: synchronized(this) {
            store ?: run {
                val app = context.applicationContext
                // An error the Keystore gives without saying why is told by the lock's own state.
                KeystoreWrap.locked = { app.getSystemService(android.app.KeyguardManager::class.java)?.isDeviceLocked == true }
                TunnelStore(File(app.noBackupFilesDir, "tunnels"), KeystoreWrap()).also { store = it }
            }
        }
    }
}
