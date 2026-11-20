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
 * The text never becomes a `String`: it is handed in and out as bytes, which the caller zeroes after use. Writes
 * go to a new file that replaces the old one whole, so that a crash leaves either. One store per process
 * ([of]); its methods hold its lock.
 */
class TunnelStore(private val dir: File, private val wrap: Wrap) {
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
     * Keeps a new configuration under [name] (see [cleanName]) and returns its slot; null when the engine's bound
     * ([MAX]) is reached. [text] is the caller's, which it zeroes.
     */
    @Synchronized
    fun add(name: String, text: ByteArray): Int? {
        val state = read()
        if (state.full) return null
        val slot = generateSequence(state.next) { it + 1 }.first { it !in state.order && it !in state.routes.values }
        put(slot, Wrap.Part.TEXT, text)
        putName(slot, name)
        write(state.copy(order = state.order + slot, next = slot + 1))
        return slot
    }

    /** Puts [text] in place of the slot's configuration, its apps and switches kept, and [name] if given. */
    @Synchronized
    fun replace(slot: Int, text: ByteArray, name: String?) {
        require(slot in read().order) { "No configuration in slot $slot" }
        put(slot, Wrap.Part.TEXT, text)
        if (name != null) putName(slot, name)
    }

    /** Names the slot's configuration anew; its text is not opened. */
    @Synchronized
    fun rename(slot: Int, name: String) {
        require(slot in read().order) { "No configuration in slot $slot" }
        putName(slot, name)
    }

    /**
     * Removes the slot's configuration. Its apps stay routed to the slot and wait, never going directly, while
     * [appsWait] (the screen asks the user); otherwise they go their other way, directly or through the tool.
     */
    @Synchronized
    fun remove(slot: Int, appsWait: Boolean) {
        val state = read()
        for (part in Wrap.Part.entries) file(slot, part).delete()
        names.remove(slot)
        write(
            state.copy(
                order = state.order - slot,
                local = state.local - slot,
                routes = if (appsWait) state.routes else state.routes.filterValues { it != slot },
            ),
        )
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
        val wrapped = file(slot, Wrap.Part.NAME).takeIf { it.isFile }?.readBytes() ?: return Name.Removed
        return when (val opened = wrap.unwrap(slot, Wrap.Part.NAME, wrapped)) {
            is Opened.Plain -> Name.Known(String(opened.bytes, Charsets.UTF_8)).also {
                opened.bytes.fill(0)
                names[slot] = it
            }
            Opened.Locked -> Name.Locked
            Opened.Lost -> Name.Lost
        }
    }

    /** The slot's configuration, for the engine: the bytes in [Opened.Plain] are the caller's to zero. */
    @Synchronized
    fun text(slot: Int): Opened {
        val wrapped = file(slot, Wrap.Part.TEXT).takeIf { it.isFile }?.readBytes() ?: return Opened.Lost
        return wrap.unwrap(slot, Wrap.Part.TEXT, wrapped)
    }

    /** Where the key lives, for the screen. */
    fun home(): KeyHome = wrap.home()

    /**
     * What the slot's text was last written as, for the service to tell a configuration that changed from one it
     * already set: the file's time and length, which every write changes, with its IV.
     */
    @Synchronized
    fun stamp(slot: Int): Long = file(slot, Wrap.Part.TEXT).let { it.lastModified() * 31 + it.length() + writes.getOrDefault(slot, 0) }

    /** The writes of each slot's text by this process, so that two within a file time's tick still differ. */
    private val writes = mutableMapOf<Int, Long>()

    private fun putName(slot: Int, name: String) {
        val bytes = cleanName(name).toByteArray(Charsets.UTF_8)
        put(slot, Wrap.Part.NAME, bytes)
        names.remove(slot)
    }

    private fun put(slot: Int, part: Wrap.Part, plain: ByteArray) {
        replaceWith(file(slot, part), wrap.wrap(slot, part, plain))
        if (part == Wrap.Part.TEXT) writes[slot] = writes.getOrDefault(slot, 0) + 1
    }

    private fun file(slot: Int, part: Wrap.Part) = File(dir, "$slot.${part.label}")

    /** Writes [bytes] to a new file beside [target], flushed to the disk, and puts it in place of [target] whole. */
    private fun replaceWith(target: File, bytes: ByteArray) {
        dir.mkdirs()
        val fresh = File(dir, "${target.name}.new")
        FileOutputStream(fresh).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        try {
            Files.move(fresh.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: IOException) {
            fresh.delete()
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

    private fun write(state: State) {
        val text = buildString {
            append("order ${state.order.joinToString(" ")}\n")
            append("local ${state.local.sorted().joinToString(" ")}\n")
            append("next ${state.next}\n")
            for ((app, slot) in state.routes.toSortedMap()) append("route $app $slot\n")
        }
        replaceWith(stateFile, text.toByteArray(Charsets.US_ASCII))
    }

    companion object {
        /** The engine's bound on configurations at once (core/net's `MAX_TUNNELS`). */
        const val MAX = 8

        /** The record's version, bound into each wrap's associated data. */
        const val VERSION: Byte = 1

        /** The longest name kept, in characters. */
        const val NAME_LENGTH = 64

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
