package org.visadahyu.datapavan.watch

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.safety.ScreenProtection
import org.visadahyu.datapavan.watch.activity.AppNames
import org.visadahyu.datapavan.watch.activity.History
import org.visadahyu.datapavan.watch.activity.Snapshot
import org.visadahyu.datapavan.watch.log.ConnectionLog
import org.visadahyu.datapavan.watch.ui.HistoryView
import org.visadahyu.datapavan.watch.ui.NowScreen
import org.visadahyu.datapavan.watch.ui.NowView
import org.visadahyu.datapavan.watch.ui.WatchTheme

/**
 * Watch's view "Now" and each app's history (ADR 0046, decision 2 (d)), in Watch's process, opened by a
 * non-exported intent as Watch's screen is: from Watch's screen, and in Advanced from the audit's page of an
 * app, with [EXTRA_PACKAGE], a package name and nothing else, to show that app. The summary and the tile
 * (W9) open it the same way. It goes behind Watch's own lock when W9 brings it (ADR 0040).
 *
 * The engine's snapshot is read once a second while the view is on screen, and not at all otherwise
 * (the call costs about a millisecond); names, the table of trackers and the log are read off the main
 * thread.
 */
class NowActivity : ComponentActivity() {
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "watch-now") }.asCoroutineDispatcher()
    private val snapshot = mutableStateOf<Snapshot?>(null)
    private val names = mutableStateMapOf<Int?, AppNames.Named>()
    private val trackers = mutableStateMapOf<String, List<String>>()
    private val history = mutableStateOf<HistoryView?>(null)
    private val only = mutableStateOf<String?>(null)
    private lateinit var appNames: AppNames

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dark = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
        // Every screen is protected (ADR 0040); debug builds may keep it off for screenshots taken by a script.
        val testBuild = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        ScreenProtection.attach(this, screenshotsForTests = testBuild && intent.getBooleanExtra(EXTRA_SCREENSHOTS, false))
        appNames = AppNames.of(packageManager)
        // Only a package name crosses from the audit's page; anything else in the intent is not read.
        only.value = intent.getStringExtra(EXTRA_PACKAGE)?.takeIf { it.isNotBlank() }
        setContent {
            val running by WatchVpnService.running.collectAsState()
            WatchTheme {
                NowScreen(
                    view = NowView(
                        snapshot = snapshot.value,
                        running = running,
                        names = names,
                        trackers = trackers,
                        only = only.value,
                    ),
                    history = history.value,
                    onAll = { only.value = null },
                    onHistory = ::openHistory,
                    onDay = ::showDay,
                    onCloseHistory = { history.value = null },
                    onAllowAccess = { org.visadahyu.datapavan.audit.openUsageAccess(this) },
                )
            }
        }
        lifecycleScope.launch {
            withContext(worker) { loadTrackers(this@NowActivity) }
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (true) {
                    refresh()
                    delay(REFRESH_MS)
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        worker.close()
    }

    /** One second's snapshot, the names of new UIDs and the trackers of new destinations, off the main thread. */
    private suspend fun refresh() {
        val read = withContext(worker) {
            val read = Snapshot.parse(Engine.nativeActivity())
            val uids = read?.apps.orEmpty().map { it.uid }.filter { it !in names }
            val named = uids.associateWith(appNames::of)
            val hosts = read?.apps.orEmpty().flatMap { app -> app.destinations.flatMap(::hostsOf) }.distinct()
                .filter { it !in trackers }
            Triple(read, named, matchTrackers(hosts))
        }
        names.putAll(read.second)
        keep(read.third)
        snapshot.value = read.first
    }

    /** Keeps the trackers found, at most [TRACKERS_KEPT] hosts' at a time. */
    private fun keep(found: Map<String, List<String>>) {
        if (trackers.size + found.size > TRACKERS_KEPT) trackers.clear()
        trackers.putAll(found)
    }

    private fun openHistory(uid: Int?) {
        val named = names[uid] ?: return
        val log = ConnectionLog.of(this)
        val days = History.days(log.today(), log.retentionDays)
        val secure = getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
        history.value = HistoryView(named, log.retentionDays, log.lockNow(), secure, days, 0, null, reading = days.isNotEmpty())
        if (days.isNotEmpty()) showDay(0)
    }

    /** Reads the day at [index] of the history shown, off the main thread: the log opens only when it can. */
    private fun showDay(index: Int) {
        val shown = history.value ?: return
        val day = shown.days.getOrNull(index) ?: return
        history.value = shown.copy(index = index, day = null, reading = true)
        lifecycleScope.launch {
            val read = withContext(worker) {
                val records = ConnectionLog.of(this@NowActivity).read(day)
                records?.let { History.day(day, it, shown.app.uid, shown.app.installedAt) }
            }
            val hosts = read?.entries.orEmpty().flatMap { listOf(it.name to it.port, it.dnsName to it.port, it.address to it.port) }
                .filter { it.first.isNotEmpty() }.map { "${it.first}\t${it.second}" }.distinct().filter { it !in trackers }
            keep(withContext(worker) { matchTrackers(hosts) })
            val now = history.value
            if (now != null && now.index == index && now.app == shown.app) {
                history.value = now.copy(day = read, reading = false, closed = read == null)
            }
        }
    }

    companion object {
        /** Watch's "Now" screen, for the intents that open it (Watch's screen, the audit, and W9's summary and tile). */
        const val CLASS_NAME = "org.visadahyu.datapavan.watch.NowActivity"

        /** The one app to show, by package name: the only thing that crosses from the audit's page. */
        const val EXTRA_PACKAGE = "package"

        /** Debug builds: keep the screen unprotected, for screenshots taken by a script. */
        const val EXTRA_SCREENSHOTS = "screenshots_for_tests"

        private const val REFRESH_MS = 1_000L

        /** At most this many hosts' trackers are kept for the view; past it they are looked up anew. */
        private const val TRACKERS_KEPT = 4_096

        @Volatile
        private var trackersLoaded = false

        /**
         * Hands the engine's library the network signatures of `exodus/trackers.tsv` in the data pack the audit
         * verifies, the current one, once in the process's life and again after an import: it is read anew each
         * time this screen opens, and no copy of the pack is kept. Returns what the library read: how many trackers
         * have a network signature, how many alternatives it read and how many it refused; empty for none.
         */
        internal fun loadTrackers(context: Context): IntArray {
            val table = try {
                DataPackStore.read(context, WatchPacks).file(TRACKERS)
            } catch (e: RuntimeException) {
                null
            } ?: return IntArray(0)
            return Engine.nativeTrackers(table).also { trackersLoaded = it.isNotEmpty() }
        }

        /** The text the engine's library matches for a destination: its name, the DNS name and its address, at its port. */
        internal fun hostsOf(destination: Snapshot.Destination): List<String> =
            listOf(destination.name, destination.dnsName, destination.address.hostAddress.orEmpty())
                .filter { it.isNotEmpty() }.distinct().map { "$it\t${destination.port}" }

        /** The trackers of each host (`host<TAB>port`), from the engine's library; none before the table loads. */
        internal fun matchTrackers(hosts: List<String>): Map<String, List<String>> {
            if (hosts.isEmpty() || !trackersLoaded) return emptyMap()
            val lines = Engine.nativeTrackersOf(hosts.take(TRACKERS_KEPT).joinToString("\n")).split('\n')
            return hosts.take(TRACKERS_KEPT).withIndex().associate { (i, host) ->
                host to lines.getOrNull(i).orEmpty().split('\t').filter { it.isNotEmpty() }
            }
        }

        private const val TRACKERS = "exodus/trackers.tsv"

        /** The intent that opens "Now", for [packageName] alone if given. */
        fun intent(context: Context, packageName: String? = null): Intent =
            Intent().setClassName(context, CLASS_NAME).apply { packageName?.let { putExtra(EXTRA_PACKAGE, it) } }
    }
}
