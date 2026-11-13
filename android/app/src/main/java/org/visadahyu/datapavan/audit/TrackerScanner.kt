package org.visadahyu.datapavan.audit

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.RemoteException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.datapack.DataPackStore
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

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

    /** SDK capabilities that need a system service, found in the same pass (ADR 0021). */
    val needs: ServiceNeeds by lazy {
        ServiceNeeds.parse(
            data.text(ServiceNeeds.SERVICES_PATH).orEmpty(),
            data.text(ServiceNeeds.CAPABILITIES_PATH).orEmpty(),
            data.text(ServiceNeeds.SIGNERS_PATH).orEmpty(),
        )
    }

    // Missing only from a broken pack; then nothing is found rather than the app failing. Every line
    // keeps its trailing tabs: an empty last column is still a column.
    private val exodus: String by lazy { data.text(TrackerData.PATH).orEmpty().let { if (it.isEmpty() || it.endsWith("\n")) it else it + "\n" } }
    /** Which company runs each SDK's service, found in the same pass (ADR 0020). */
    val owners: Owners by lazy {
        Owners.parse(data.text(Owners.ENTITIES_PATH).orEmpty(), data.text(Owners.OPERATORS_PATH).orEmpty(), data.text(Owners.PUBLISHERS_PATH).orEmpty())
    }

    private val withSdks: String by lazy { exodus + sdkList.signatureTsv() }
    private val tsv: String by lazy {
        listOf(sdkList.signatureTsv(), needs.signatureTsv(), owners.signatureTsv()).filter { it.isNotEmpty() }.joinToString("\n", prefix = exodus)
    }

    /**
     * The trackers of the data pack in use, by εxodus id, and the SDKs of [sdkList], capabilities of
     * [needs] and SDK operators of [owners] by their ids.
     */
    val trackers: Map<Int, TrackerInfo> by lazy { TrackerData.parse(tsv) }

    /**
     * Scans [apps], calling [onProgress] with the number done after each one. The APKs are parsed in an
     * isolated process (ParserService); this process only opens them and reads the answers.
     */
    suspend fun scan(apps: List<AppFacts>, onProgress: (done: Int, total: Int) -> Unit): Map<String, AppTrackers> =
        withContext(Dispatchers.IO) { Parsers(context).use { parsers -> scan(parsers, apps, onProgress) } }

    private suspend fun scan(parsers: Parsers, apps: List<AppFacts>, onProgress: (done: Int, total: Int) -> Unit): Map<String, AppTrackers> = coroutineScope {
        // Signature data the engine cannot read must not stop the audit: without the capabilities and
        // owners, then without the SDK list, and then without any signatures, the scan finds less
        // instead of the app failing. Without the parsers' process, nothing can be scanned.
        val signatures = listOf(tsv, withSdks, exodus).firstOrNull { candidate ->
            try {
                parsers.loadSignatures(candidate)
            } catch (_: RemoteException) {
                return@coroutineScope apps.associate { it.packageName to UNREADABLE }
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
        val permits = Semaphore(parallelScans())
        apps.map { app ->
            async(Dispatchers.IO) {
                val result = cached[app.packageName]?.takeIf { it.first == app.lastUpdate }?.second
                    ?: permits.withPermit { scanApp(parsers, app.packageName) }
                // A failure of the parsers' process is not kept, so that the next audit tries again.
                if (result !== UNREADABLE_BY_PARSERS) completed[app.packageName] = app.lastUpdate to result
                val count = done.incrementAndGet()
                onProgress(count, apps.size)
                if (count % SAVE_EVERY == 0) saveCache(cached + completed)
            }
        }.awaitAll()
        // Only the apps installed now; uninstalled apps drop out of the cache.
        saveCache(completed)
        completed.mapValues { (_, entry) -> entry.second } +
            apps.filter { !completed.containsKey(it.packageName) }.associate { it.packageName to UNREADABLE }
    }

    private val cacheFile: File get() = File(context.noBackupFilesDir, "tracker-scan.tsv")

    /**
     * How many apps to scan at once. A scan maps most DEX files, but holds a compressed one in
     * memory, up to tens of megabytes: one at a time on phones that Android counts as low on memory
     * and on 2 GB phones, two on 3 and 4 GB phones, four from 6 GB, and never more than the
     * processor has cores.
     */
    private fun parallelScans(): Int {
        val activity = context.getSystemService(ActivityManager::class.java) ?: return 1
        if (activity.isLowRamDevice) return 1
        val memory = ActivityManager.MemoryInfo().also { activity.getMemoryInfo(it) }.totalMem
        val byMemory = when {
            memory < 2_500L * MIB -> 1
            memory < 5_000L * MIB -> 2
            else -> 4
        }
        return byMemory.coerceAtMost(Runtime.getRuntime().availableProcessors()).coerceAtLeast(1)
    }

    private fun scanApp(parsers: Parsers, packageName: String): AppTrackers {
        val info = try {
            context.packageManager.getApplicationInfo(packageName, 0)
        } catch (_: PackageManager.NameNotFoundException) {
            return UNREADABLE
        }
        val embedded = sortedSetOf<Int>()
        val referenced = sortedSetOf<Int>()
        val apks = listOfNotNull(info.sourceDir) + info.splitSourceDirs.orEmpty()
        return try {
            for (apk in apks) {
                val scan = parsers.scanApk(apk)
                if (scan.getBoolean(ApkScan.UNREADABLE)) return UNREADABLE
                embedded += sdkList.nativeMatches(scan.getStringArrayList(ApkScan.LIBRARIES).orEmpty().asSequence())
                embedded += scan.getIntArray(ApkScan.EMBEDDED)?.toList().orEmpty()
                referenced += scan.getIntArray(ApkScan.REFERENCED)?.toList().orEmpty()
            }
            AppTrackers(embedded.toList(), (referenced - embedded).toList())
        } catch (_: IOException) {
            UNREADABLE
        } catch (_: SecurityException) {
            UNREADABLE
        } catch (_: RemoteException) {
            // The parsers' process died twice on this app, or could not be bound again.
            UNREADABLE_BY_PARSERS
        }
    }

    private fun sha256(text: String): String =
        MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(Locale.ROOT, it) }

    private companion object {
        const val SAVE_EVERY = 20
        const val MIB = 1024L * 1024
        val UNREADABLE = AppTrackers(emptyList(), emptyList(), unreadable = true)

        /** The same answer, when the parsers' process failed rather than the app's code. */
        val UNREADABLE_BY_PARSERS = AppTrackers(emptyList(), emptyList(), unreadable = true)
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
