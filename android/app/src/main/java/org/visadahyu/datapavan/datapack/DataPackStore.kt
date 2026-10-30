package org.visadahyu.datapavan.datapack

import android.content.ContentResolver
import android.content.Context
import android.content.res.AssetManager
import android.net.Uri
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream

/**
 * The data the app uses: its own pack from the APK, or a newer pack the user imported through the
 * system file picker (ADR 0015, decision 11). Datapavan has no network access, so this is the only
 * way data changes between app updates. An imported pack is stored as it arrived, signature and all,
 * in app-private storage that backups exclude, and its signature is checked again whenever it is
 * loaded.
 */
class DataPackStore private constructor(
    private val assets: AssetManager,
    private val resolver: ContentResolver,
    private val directory: File,
) {
    /** The pack in the APK. A build that cannot read its own data is broken, so this fails loudly. */
    val bundled: DataPack by lazy {
        val bytes = assets.open(BUNDLED_ASSET).use { it.readBytes() }
        when (val reading = PackReader.payload(bytes)) {
            is PackReading.Read -> reading.pack
            is PackReading.Refused -> error("$BUNDLED_ASSET: ${reading.reason}")
        }
    }

    private class Installed(val pack: DataPack, val chain: List<String>)

    @Volatile
    private var installed: Installed? = null
    private var loaded = false

    /** The pack the audit uses now. */
    val active: DataPack get() = installedPack()?.pack ?: bundled

    /** Whether [active] was imported rather than shipped with the app. */
    val isImported: Boolean get() = installedPack() != null

    /** The keys that may sign the next pack. Empty until the project's data-signing key exists. */
    val trustedKeys: List<String> get() = DataPackRules.trustedKeys(bundled, installedPack()?.pack)

    /** A file of the active pack, or of the APK's pack if a newer pack happens to lack it. */
    fun file(path: String): ByteArray? = active.file(path) ?: bundled.file(path)

    fun text(path: String): String? = file(path)?.toString(Charsets.UTF_8)

    /** Imports the pack the user picked, if it is signed by a trusted key and newer than [active]. */
    fun import(uri: Uri): ImportResult {
        val bytes = try {
            resolver.openInputStream(uri)?.use { readAtMost(it, MAX_PACK_BYTES) }
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        } ?: return ImportResult.Refused(PackRefusal.UNREADABLE)
        return import(bytes)
    }

    @Synchronized
    fun import(bytes: ByteArray): ImportResult {
        if (bytes.size > MAX_PACK_BYTES) return ImportResult.Refused(PackRefusal.TOO_LARGE)
        val trusted = trustedKeys
        if (trusted.isEmpty()) return ImportResult.Refused(PackRefusal.NO_TRUSTED_KEYS)
        val reading = when (val read = PackReader.signed(bytes, trusted)) {
            is PackReading.Refused -> return ImportResult.Refused(read.reason)
            is PackReading.Read -> read
        }
        DataPackRules.refusal(reading.pack, active)?.let { return ImportResult.Refused(it) }
        val chain = DataPackRules.chainAfter(bundled, installedPack()?.chain.orEmpty(), trusted[reading.signer])
        try {
            write(chainFile, chain.joinToString("\n", postfix = "\n").toByteArray(Charsets.US_ASCII))
            write(packFile, bytes)
        } catch (_: IOException) {
            return ImportResult.Refused(PackRefusal.UNREADABLE)
        }
        installed = Installed(reading.pack, chain)
        return ImportResult.Imported(reading.pack)
    }

    @Synchronized
    private fun installedPack(): Installed? {
        if (!loaded) {
            installed = loadInstalled()
            loaded = true
        }
        return installed
    }

    /** The imported pack, checked again; one that no longer applies is deleted. */
    private fun loadInstalled(): Installed? {
        if (!packFile.exists()) return null
        val found = try {
            val chain = chainFile.readLines().filter { it.isNotEmpty() }
            val reading = chain.lastOrNull()?.let { PackReader.signed(packFile.readBytes(), listOf(it)) }
            (reading as? PackReading.Read)?.pack
                ?.takeIf { DataPackRules.keep(bundled, it, chain) }
                ?.let { Installed(it, chain) }
        } catch (_: IOException) {
            null
        }
        if (found == null) {
            packFile.delete()
            chainFile.delete()
        }
        return found
    }

    private val packFile: File get() = File(directory, "installed.pack")
    private val chainFile: File get() = File(directory, "installed.chain")

    /** Writes through a temporary file, so a crash leaves the old file or the new one. */
    private fun write(file: File, bytes: ByteArray) {
        directory.mkdirs()
        val temporary = File(directory, file.name + ".tmp")
        temporary.writeBytes(bytes)
        if (!temporary.renameTo(file)) throw IOException("cannot replace $file")
    }

    companion object {
        const val BUNDLED_ASSET = "data/bundled.payload"
        /** As `MAX_PACK_BYTES` in the Rust engine. */
        const val MAX_PACK_BYTES = 32 shl 20

        @Volatile
        private var instance: DataPackStore? = null

        fun get(context: Context): DataPackStore = instance ?: synchronized(this) {
            instance ?: DataPackStore(context.assets, context.contentResolver, File(context.noBackupFilesDir, "datapack"))
                .also { instance = it }
        }

        /** Reads at most [limit] + 1 bytes, so that a larger file is recognised without reading it all. */
        internal fun readAtMost(input: InputStream, limit: Int): ByteArray {
            val buffer = ByteArrayOutputStream()
            val chunk = ByteArray(64 shl 10)
            while (buffer.size() <= limit) {
                val read = input.read(chunk, 0, minOf(chunk.size, limit + 1 - buffer.size()))
                if (read < 0) break
                buffer.write(chunk, 0, read)
            }
            return buffer.toByteArray()
        }
    }
}

/** The outcome of an import. */
sealed interface ImportResult {
    data class Imported(val pack: DataPack) : ImportResult
    data class Refused(val reason: PackRefusal) : ImportResult
}
