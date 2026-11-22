package org.visadahyu.datapavan.network.blocking

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.core.net.toUri
import java.io.File
import java.io.IOException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.visadahyu.datapavan.audit.appSigning
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.network.NetworkPacks
import org.visadahyu.datapavan.network.chain.ChainSettings

/**
 * What Watch worked out for tracker blocking from the phone and the data pack (W8, part 3a; ADR 0053), for the engine's
 * setting ([Handover]) and for "Now" and the history alike, so that the screens say what the engine was told: the
 * [table] as Kotlin read it ([BlockingTable.EMPTY] for none, or one refused), the engine's [counts] of it (rows, `block`,
 * `keep`, `code`; empty for none), the εxodus [trackers] that name its rows, the UIDs [covered], the [browsers] found,
 * the rows [decided] for each covered UID ([Grades.forApp]), and each installed package's UID ([uids]), by which
 * allowances kept by package are handed over. Nothing here is written anywhere.
 */
internal class BlockingFacts(
    val table: BlockingTable,
    val counts: IntArray,
    val trackers: List<TrackerCode.Tracker>,
    val covered: Set<Int>,
    val browsers: List<String>,
    val decided: Map<Int, Map<String, Grades.Decided>>,
    val uids: Map<String, Int>,
) {
    /** Whether [row] is blocked in the app [uid] while blocking is on: covered, and graded or decided `block` for it. */
    fun blocks(uid: Int?, row: BlockingTable.Row): Boolean = uid != null && uid in covered && Grades.blocks(row, decided[uid])

    companion object {
        /** Nothing read: no table, nothing covered. */
        val NONE = BlockingFacts(BlockingTable.EMPTY, IntArray(0), emptyList(), emptySet(), emptyList(), emptyMap(), emptyMap())

        /**
         * Reads the facts on the calling thread, which must not be the main one: the data pack the audit verifies (its
         * `blocking/hosts.tsv`, with [LabRow] after it, `blocking/exceptions.tsv` and `exodus/trackers.tsv`), the apps
         * installed and the browsers among them, the user's tool, the audit's scan of each app's code, and the signing
         * certificates of the apps an exception names. [hand] hands the table's bytes to the engine and returns its
         * counts, or is null for a screen that only reads; [covering] is false while blocking is off, when nothing is
         * covered and only the table is read.
         */
        fun read(context: Context, browsersIncluded: Boolean, covering: Boolean, hand: ((ByteArray) -> IntArray)?): BlockingFacts {
            val store = try {
                DataPackStore.read(context, NetworkPacks)
            } catch (e: RuntimeException) {
                null
            }
            val bytes = tableBytes(store?.file(BlockingTable.PATH))
            val text = String(bytes, Charsets.UTF_8)
            val kotlin = BlockingTable.parse(text)
            val counts = hand?.invoke(bytes) ?: kotlin?.let { table ->
                intArrayOf(table.rows.size) + BlockingTable.Grade.entries.map { grade -> table.rows.count { it.grade == grade } }
            } ?: IntArray(0)
            // A table the engine refused, or one the two sides read apart, is no table to speak of or to block by.
            val table = if (counts.isEmpty()) BlockingTable.EMPTY else kotlin ?: BlockingTable.EMPTY
            val trackers = TrackerCode.parse(store?.text(TrackerCode.PATH).orEmpty())
            if (!covering || table.rows.isEmpty()) {
                return BlockingFacts(table, counts, trackers, emptySet(), emptyList(), emptyMap(), emptyMap())
            }
            val packageManager = context.packageManager
            val installed = installed(packageManager)
            val uids = installed.associate { it.packageName to it.uid }
            val browsers = Coverage.browsers(browserAnswers(packageManager))
            val tool = ChainSettings.of(context).lastTool?.packageName?.let(uids::get)
            val covered = Coverage.covered(
                installed.map { Coverage.App(it.uid, it.packageName, it.system) },
                self = context.applicationInfo.uid,
                playServices = uids[Coverage.PLAY_SERVICES],
                tool = tool,
                browsers = browsers,
                includeBrowsers = browsersIncluded,
            )
            val scans = try {
                ScanResults.parse(File(context.noBackupFilesDir, ScanResults.FILE).readText())
            } catch (e: IOException) {
                emptyMap()
            }
            val exceptions = Exceptions.parse(store?.text(Exceptions.PATH).orEmpty())
            val byUid = installed.groupBy { it.uid }
            val decided = covered.associateWith { uid ->
                val packages = byUid[uid].orEmpty()
                val known = packages.mapNotNull { ScanResults.embedded(scans, it.packageName, it.lastUpdate) }
                val named = packages.filter { app -> exceptions.any { it.packageName == app.packageName } }
                val excepted = Grades.excepted(exceptions, named.map { it.packageName to signing(packageManager, it.packageName) })
                Grades.forApp(table, trackers, known.takeIf { it.isNotEmpty() }?.flatten()?.toSet(), excepted)
            }.filterValues { it.isNotEmpty() }
            return BlockingFacts(table, counts, trackers, covered, browsers.toList(), decided, uids)
        }

        /** The table's bytes as the engine reads them: the pack's, then the lab's row in a debug build ([LabRow]). */
        internal fun tableBytes(pack: ByteArray?): ByteArray {
            val own = pack ?: ByteArray(0)
            if (LabRow.ROW.isEmpty()) return own
            val separator = if (own.isEmpty() || own.last() == '\n'.code.toByte()) ByteArray(0) else byteArrayOf('\n'.code.toByte())
            return own + separator + LabRow.ROW.toByteArray(Charsets.UTF_8)
        }

        private class Installed(val uid: Int, val packageName: String, val system: Boolean, val lastUpdate: Long)

        /** Every installed package; Datapavan Advanced holds QUERY_ALL_PACKAGES, the audit's (ADR 0014). */
        @SuppressLint("QueryPermissionsNeeded")
        private fun installed(packageManager: PackageManager): List<Installed> {
            @Suppress("DEPRECATION")
            val packages = packageManager.getInstalledPackages(0)
            return packages.mapNotNull { info ->
                val app = info.applicationInfo ?: return@mapNotNull null
                val system = app.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                Installed(app.uid, info.packageName, system, info.lastUpdateTime)
            }
        }

        /**
         * The apps that open [Coverage.BROWSER_PROBE], a host no app claims, each with how many hosts its filter names
         * (null where Android gave none): every match, not only the default's.
         */
        @SuppressLint("QueryPermissionsNeeded")
        private fun browserAnswers(packageManager: PackageManager): List<Pair<String, Int?>> {
            val view = Intent(Intent.ACTION_VIEW, Coverage.BROWSER_PROBE.toUri()).addCategory(Intent.CATEGORY_BROWSABLE)
            @Suppress("DEPRECATION")
            val answers = packageManager.queryIntentActivities(view, PackageManager.MATCH_ALL or PackageManager.GET_RESOLVED_FILTER)
            return answers.mapNotNull { answer ->
                val name = answer.activityInfo?.packageName ?: return@mapNotNull null
                name to answer.filter?.countDataAuthorities()
            }
        }

        private fun signing(packageManager: PackageManager, name: String) = try {
            appSigning(packageManager.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES))
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }
}

/**
 * The facts the running service last handed the engine, for the screens of Watch's process; null before it handed any
 * in this process, and then a screen reads its own ([BlockingFacts.read] with no hand).
 */
internal object BlockingState {
    private val state = MutableStateFlow<BlockingFacts?>(null)

    val facts: StateFlow<BlockingFacts?> = state.asStateFlow()

    fun publish(facts: BlockingFacts) {
        state.value = facts
    }
}
