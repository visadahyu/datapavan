package org.visadahyu.datapavan.audit

import android.content.Context
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import org.visadahyu.datapavan.core.NativeCore
import org.visadahyu.datapavan.datapack.DataPackStore
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.ZipFile

/** One tracker from the εxodus database (`data/exodus/trackers.tsv`, ADR 0015). */
data class TrackerInfo(val id: Int, val name: String, val categories: List<String>, val website: String)

/** The trackers in one app, by εxodus id. */
data class AppTrackers(
    /** Trackers whose code the app contains. */
    val embedded: List<Int>,
    /** Trackers that the app's code refers to without containing them. */
    val referencedOnly: List<Int>,
    /** The app's code could not be read, so it was not checked. */
    val unreadable: Boolean = false,
)

/** The tracker signatures, from the data pack. */
object TrackerData {
    const val PATH = "exodus/trackers.tsv"

    /** Reads id, name, categories and website from each line; comments start with `#`. */
    fun parse(tsv: String): Map<Int, TrackerInfo> = tsv.lineSequence()
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .mapNotNull { line ->
            val columns = line.split('\t')
            val id = columns.getOrNull(0)?.toIntOrNull() ?: return@mapNotNull null
            if (columns.size != 6) return@mapNotNull null
            TrackerInfo(id, columns[1], columns[2].split(',').filter { it.isNotEmpty() }, columns[3])
        }
        .associateBy { it.id }
}

/**
 * Finds trackers in every installed app: it reads each DEX file of the app's base APK and of every
 * split, and the Rust engine matches their classes against the εxodus signatures. Results are kept
 * in a cache file and reused while the app and the signatures stay the same, because the first scan
 * of a phone reads several gigabytes.
 */
class TrackerScanner(private val context: Context) {
    private val data = DataPackStore.get(context)

    /** Traffic-sharing, remote-support and screen-recording SDKs, found in the same pass (ADR 0019). */
    val sdkList: SdkList by lazy { SdkList.parse(data.text(SdkList.SDKS_PATH).orEmpty(), data.text(SdkList.SIGNATURES_PATH).orEmpty()) }

    // Missing only from a broken pack; then nothing is found rather than the app failing. Every line
    // keeps its trailing tabs: an empty last column is still a column.
    private val exodus: String by lazy { data.text(TrackerData.PATH).orEmpty().let { if (it.isEmpty() || it.endsWith("\n")) it else it + "\n" } }
    private val tsv: String by lazy { exodus + sdkList.signatureTsv() }

    /** The trackers of the data pack in use, by εxodus id, and the SDKs of [sdkList] by their ids. */
    val trackers: Map<Int, TrackerInfo> by lazy { TrackerData.parse(tsv) }

    /** Scans [apps], calling [onProgress] with the number done after each one. */
    suspend fun scan(apps: List<AppFacts>, onProgress: (done: Int, total: Int) -> Unit): Map<String, AppTrackers> = coroutineScope {
        // Signature data the engine cannot read must not stop the audit: without the SDK list, and
        // then without any signatures, the scan finds less instead of the app failing.
        val signatures = listOf(tsv, exodus).firstOrNull { candidate ->
            try {
                NativeCore.loadTrackers(candidate)
                true
            } catch (_: RuntimeException) {
                false
            }
        } ?: return@coroutineScope emptyMap()
        // Native-library names are part of the data a cached result was made with.
        val dataVersion = sha256(signatures + sdkList.nativeLibraries.toSortedMap())
        val cached = ScanCache.read(cacheFile, dataVersion)
        val done = AtomicInteger()
        // Saved every few apps as well, so that a first scan cut short (the user leaves, Android
        // stops the app) does not start again from the beginning.
        val completed = ConcurrentHashMap<String, Pair<Long, AppTrackers>>()
        val save = Mutex()
        suspend fun saveCache(entries: Map<String, Pair<Long, AppTrackers>>) = save.withLock {
            ScanCache.write(cacheFile, dataVersion, entries.map { (name, entry) -> Triple(name, entry.first, entry.second) })
        }
        // Two at a time: each holds a whole DEX file in memory, and low-end phones have little.
        val permits = Semaphore(PARALLEL_SCANS)
        apps.map { app ->
            async(Dispatchers.IO) {
                val result = cached[app.packageName]?.takeIf { it.first == app.lastUpdate }?.second
                    ?: permits.withPermit { scanApp(app.packageName) }
                completed[app.packageName] = app.lastUpdate to result
                val count = done.incrementAndGet()
                onProgress(count, apps.size)
                if (count % SAVE_EVERY == 0) saveCache(cached + completed)
            }
        }.awaitAll()
        // Only the apps installed now; uninstalled apps drop out of the cache.
        saveCache(completed)
        completed.mapValues { (_, entry) -> entry.second }
    }

    private val cacheFile: File get() = File(context.noBackupFilesDir, "tracker-scan.tsv")

    private fun scanApp(packageName: String): AppTrackers {
        val info = try {
            context.packageManager.getApplicationInfo(packageName, 0)
        } catch (_: PackageManager.NameNotFoundException) {
            return AppTrackers(emptyList(), emptyList(), unreadable = true)
        }
        val embedded = sortedSetOf<Int>()
        val referenced = sortedSetOf<Int>()
        val apks = listOfNotNull(info.sourceDir) + info.splitSourceDirs.orEmpty()
        return try {
            for (apk in apks) {
                ZipFile(apk).use { zip ->
                    embedded += sdkList.nativeMatches(zip.entries().asSequence().map { it.name })
                    for (entry in zip.entries()) {
                        if (!DEX_ENTRY.matches(entry.name)) continue
                        // The size comes from the APK's directory. A file far larger than any real
                        // one could exhaust memory, so it makes the app unreadable instead.
                        if (entry.size !in 0..MAX_DEX_BYTES) throw IOException("${entry.name}: ${entry.size} bytes")
                        val dex = ByteArray(entry.size.toInt())
                        zip.getInputStream(entry).use { DataInputStream(it).readFully(dex) }
                        val found = NativeCore.scanDex(dex)
                        val count = found.firstOrNull() ?: 0
                        embedded += found.drop(1).take(count)
                        referenced += found.drop(1 + count)
                    }
                }
            }
            AppTrackers(embedded.toList(), (referenced - embedded).toList())
        } catch (_: IOException) {
            AppTrackers(emptyList(), emptyList(), unreadable = true)
        } catch (_: SecurityException) {
            AppTrackers(emptyList(), emptyList(), unreadable = true)
        } catch (_: RuntimeException) {
            // A malformed DEX file, reported by the Rust parser.
            AppTrackers(emptyList(), emptyList(), unreadable = true)
        }
    }

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(Locale.ROOT, it) }

    private companion object {
        const val PARALLEL_SCANS = 2
        const val SAVE_EVERY = 20
        const val MAX_DEX_BYTES = 48L * 1024 * 1024
        val DEX_ENTRY = Regex("classes\\d*\\.dex")
    }
}

/**
 * The scan results of earlier runs, one line per app: package, last update time, whether it was
 * unreadable, embedded ids, referenced-only ids. The first line names the signature data they were
 * made with, so new signatures start a new scan.
 */
internal object ScanCache {
    fun read(file: File, dataVersion: String): Map<String, Pair<Long, AppTrackers>> {
        val lines = try {
            file.readLines()
        } catch (_: IOException) {
            return emptyMap()
        }
        if (lines.firstOrNull() != "data\t$dataVersion") return emptyMap()
        return lines.drop(1).mapNotNull { line ->
            val columns = line.split('\t')
            if (columns.size != 5) return@mapNotNull null
            val lastUpdate = columns[1].toLongOrNull() ?: return@mapNotNull null
            columns[0] to (lastUpdate to AppTrackers(ids(columns[3]), ids(columns[4]), unreadable = columns[2] == "1"))
        }.toMap()
    }

    fun write(file: File, dataVersion: String, entries: List<Triple<String, Long, AppTrackers>>) {
        val text = buildString {
            append("data\t").append(dataVersion).append('\n')
            for ((packageName, lastUpdate, result) in entries) {
                append(packageName).append('\t').append(lastUpdate).append('\t')
                append(if (result.unreadable) "1" else "0").append('\t')
                append(result.embedded.joinToString(",")).append('\t')
                append(result.referencedOnly.joinToString(",")).append('\n')
            }
        }
        val temporary = File(file.parentFile, file.name + ".new")
        try {
            temporary.writeText(text)
            if (!temporary.renameTo(file)) temporary.delete()
        } catch (_: IOException) {
            temporary.delete()
        }
    }

    private fun ids(column: String): List<Int> = column.split(',').mapNotNull { it.toIntOrNull() }
}
