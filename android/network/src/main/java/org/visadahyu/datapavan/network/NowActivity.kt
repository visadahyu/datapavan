package org.visadahyu.datapavan.network

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import java.time.LocalDate
import java.util.concurrent.Executors
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.audit.Owners
import org.visadahyu.datapavan.audit.appSigning
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.safety.ScreenProtection
import org.visadahyu.datapavan.network.activity.AppNames
import org.visadahyu.datapavan.network.activity.Companies
import org.visadahyu.datapavan.network.activity.History
import org.visadahyu.datapavan.network.activity.NowRows
import org.visadahyu.datapavan.network.activity.Snapshot
import org.visadahyu.datapavan.network.activity.TrackerMarks
import org.visadahyu.datapavan.network.blocking.BlockingFacts
import org.visadahyu.datapavan.network.blocking.BlockingSettings
import org.visadahyu.datapavan.network.blocking.BlockingState
import org.visadahyu.datapavan.network.blocking.Tallies
import org.visadahyu.datapavan.network.log.ConnectionLog
import org.visadahyu.datapavan.network.ui.BlockingActions
import org.visadahyu.datapavan.network.ui.BlockingView
import org.visadahyu.datapavan.network.ui.HistoryView
import org.visadahyu.datapavan.network.ui.NowScreen
import org.visadahyu.datapavan.network.ui.NowView
import org.visadahyu.datapavan.network.ui.RowNames
import org.visadahyu.datapavan.network.ui.NetworkTheme
import org.visadahyu.datapavan.network.ui.ProxyChoiceActions
import org.visadahyu.datapavan.network.ui.ProxyChoices
import org.visadahyu.datapavan.network.ui.rowOf
import org.visadahyu.datapavan.network.proxy.LoggedApps
import org.visadahyu.datapavan.network.proxy.ProxyChoice

/**
 * The network part's view "Now" and each app's history (ADR 0046, decision 2 (d)), in the network process, opened by a
 * non-exported intent as the network screen is: from the network screen, and in Advanced from the audit's page of an
 * app, with [EXTRA_PACKAGE], a package name and nothing else, to show that app. The summary and the tile
 * (W9) open it the same way. It goes behind the network part's own lock when W9 brings it (ADR 0040).
 *
 * The engine's snapshot is read once a second while "Now" is on screen, and not at all otherwise, nor while
 * an app's history shows (the call costs about a millisecond); names, the tables of trackers and companies,
 * and the log are read off the main thread. The window, the rows' order and the history shown are kept
 * across the history and a rotation (review c1 of W5's third part, screens, M2); what the view holds of the
 * engine's memory and of the log is dropped when it leaves the screen, and read again when it comes back
 * (m9), so that a clear of the live memory leaves no copy here.
 *
 * Tracker blocking (W8, part 3a; ADR 0053) is read with each snapshot: what the engine counted in memory, the facts the
 * service handed it, and the user's allowances. The one-tap undo writes the allowance and has the running service hand
 * the setting again at once; it takes effect within seconds, since apps keep a failed lookup for a moment. A row's link
 * to "Log where apps connect ..." opens the network screen above this one, which stays where the user was beneath it,
 * the same app's row or its history ([MainActivity.logSwitchIntent]; the brief's point 11).
 *
 * The user's choice for one app, "Log where APP connects through a proxy" (the proxy record's unit C, R3), is read with
 * each snapshot and when a history opens ([readChoices]): its rows' links and its page's switch write the store
 * ([LoggedApps]) off the main thread, which has the running service hand it to the engine at once.
 */
class NowActivity : ComponentActivity() {
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "network-now") }.asCoroutineDispatcher()
    private val snapshot = mutableStateOf<Snapshot?>(null)
    private val names = mutableStateMapOf<Int?, AppNames.Named>()
    private val groups = mutableStateMapOf<Int?, String?>()
    private val trackers = mutableStateMapOf<String, List<TrackerMarks.Match>>()

    /**
     * The WireGuard configurations' names by tunnel number, read off the main thread with each snapshot (W7, part 2),
     * so that a rename, or a name that could not be read a moment ago, shows within a second (fix round, screens
     * review, nit); the store keeps each name it opened until it changes, so a read costs no Keystore.
     */
    private val tunnelNames = mutableStateMapOf<Long, String>()
    private val history = mutableStateOf<HistoryView?>(null)
    private val only = mutableStateOf<String?>(null)
    private val window = mutableIntStateOf(Snapshot.TEN_MINUTES)
    private val order = NowRows.Order()

    /** Tracker blocking as last read ([readBlocking]). */
    private val blocking = mutableStateOf(BlockingView())

    /** The facts this screen read itself, where the service handed none in this process; worker only. */
    private var ownFacts: BlockingFacts? = null

    /** The undo: each tap writes the allowance, and the running service hands the setting again. */
    private val blockingActions = BlockingActions(
        onAllowApp = { packages -> changeBlocking { settings, now -> packages.forEach { settings.allowApp(it, now) } } },
        onBlockAppAgain = { packages -> changeBlocking { settings, _ -> packages.forEach(settings::blockAppAgain) } },
        onAllowEntries = { packages, hosts -> changeBlocking { settings, _ -> packages.forEach { settings.allowEntries(it, hosts) } } },
        onBlockEntriesAgain = { packages, hosts -> changeBlocking { settings, _ -> packages.forEach { settings.blockEntriesAgain(it, hosts) } } },
    )

    /** The user's choice for one app as last read ([readChoices]; unit C). */
    private val choices = mutableStateOf(ProxyChoices())

    /** The apps whose choice the user ended on this screen, by app UID, for the note of what stays (audit-C 8). Main thread. */
    @Volatile
    private var stopped: Set<Int> = emptySet()

    /** The circumvention tools' UIDs this screen read itself, while the service published none; worker only. */
    private var ownTools: Set<Int>? = null

    /** Whether the SDK Runtime is on, read once; worker only. */
    private val sdkRuntime by lazy { org.visadahyu.datapavan.network.ui.sdkRuntimeOn() }

    /** The choice's taps: a yes of the confirmation, or a stop, for the app's UID. */
    private val proxyActions = ProxyChoiceActions(onLog = { changeChoice(it, stop = false) }, onStop = { changeChoice(it, stop = true) })

    /** Bumped when the rows are to sort anew, so that the view reads the order again. */
    private val sorts = mutableIntStateOf(0)

    /**
     * Whether the user stopped the counts' updates (WCAG 2.2.2, the accessibility unit): the view then reads nothing new
     * until the user resumes, so that a screen reader or a slow reader is not overtaken by numbers changing each second.
     */
    private val paused = mutableStateOf(false)
    private lateinit var appNames: AppNames

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The window's title is what a screen reader says as the screen opens (the accessibility unit, part 2).
        setTitle(R.string.now_title)
        val dark = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
        // Every screen is protected (ADR 0040); debug builds may keep it off for screenshots taken by a script.
        val testBuild = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        ScreenProtection.attach(this, screenshotsForTests = testBuild && intent.getBooleanExtra(EXTRA_SCREENSHOTS, false))
        appNames = AppNames.of(packageManager)
        // Only a package name crosses from the audit's page; anything else in the intent is not read.
        only.value = if (savedInstanceState != null) {
            savedInstanceState.getString(SAVED_ONLY)
        } else {
            intent.getStringExtra(EXTRA_PACKAGE)?.takeIf { it.isNotBlank() }
        }
        savedInstanceState?.let { saved ->
            window.intValue = saved.getInt(SAVED_WINDOW, Snapshot.TEN_MINUTES)
            paused.value = saved.getBoolean(SAVED_PAUSED)
            NowRows.Order.restore(order, saved.getIntArray(SAVED_ORDER))
            if (saved.getBoolean(SAVED_HISTORY)) {
                val uid = saved.getInt(SAVED_HISTORY_UID).takeIf { !saved.getBoolean(SAVED_HISTORY_NO_APP) }
                openHistory(uid, saved.getInt(SAVED_HISTORY_DAY), saved.getBoolean(SAVED_HISTORY_TOOL))
            }
        }
        setContent {
            val running by NetworkVpnService.running.collectAsState()
            val proxies by org.visadahyu.datapavan.network.proxy.ProxyContext.state.collectAsState()
            NetworkTheme {
                NowScreen(
                    view = NowView(
                        snapshot = snapshot.value,
                        running = running,
                        names = names,
                        groups = groups,
                        trackers = trackers,
                        companies = companies,
                        only = only.value,
                        window = window.intValue,
                        order = order,
                        sorts = sorts.intValue,
                        tunnelNames = tunnelNames,
                        blocking = blocking.value,
                        paused = paused.value,
                        proxies = proxies,
                        choices = choices.value,
                    ),
                    history = history.value,
                    onPause = { paused.value = !paused.value },
                    onWindow = {
                        window.intValue = it
                        sort()
                    },
                    onSort = ::sort,
                    onAll = {
                        only.value = null
                        sort()
                    },
                    onHistory = { uid, tool -> openHistory(uid, 0, tool) },
                    onDay = ::showDay,
                    onCloseHistory = { history.value = null },
                    onAllowAccess = { org.visadahyu.datapavan.audit.openUsageAccess(this) },
                    // A row the switch "Log where apps connect ..." leaves out opens the network screen at it, above
                    // this one.
                    onLogSwitch = { startActivity(MainActivity.logSwitchIntent(this)) },
                    blockingActions = blockingActions,
                    proxyActions = proxyActions,
                )
            }
        }
        lifecycleScope.launch {
            withContext(worker) { loadTables(this@NowActivity) }
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                // A history shown when the view left the screen is read again as it comes back.
                history.value?.takeIf { it.day == null && !it.reading }?.let { showDay(it.index) }
                while (true) {
                    // While paused, the view reads once more only when it has nothing to show: after a rotation, or on
                    // coming back to the screen, which drops what it held (onStop). Otherwise it would show no app at all.
                    if (history.value == null && (!paused.value || snapshot.value == null)) refresh()
                    delay(REFRESH_MS)
                }
            }
        }
    }

    /** The rows sort anew: the user asked, changed the window, or asked for every app again. */
    private fun sort() {
        order.sort()
        sorts.intValue++
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(SAVED_WINDOW, window.intValue)
        outState.putBoolean(SAVED_PAUSED, paused.value)
        outState.putIntArray(SAVED_ORDER, NowRows.Order.save(order))
        outState.putString(SAVED_ONLY, only.value)
        history.value?.let {
            outState.putBoolean(SAVED_HISTORY, true)
            outState.putBoolean(SAVED_HISTORY_NO_APP, it.app.uid == null)
            outState.putInt(SAVED_HISTORY_UID, it.app.uid ?: 0)
            outState.putInt(SAVED_HISTORY_DAY, it.index)
            outState.putBoolean(SAVED_HISTORY_TOOL, it.tool)
        }
    }

    /**
     * Off the screen, the view keeps no copy of what the engine or the log hold: the snapshot, the trackers
     * by destination and the day read are dropped, and read again when it comes back (review c1, screens, m9).
     */
    override fun onStop() {
        super.onStop()
        snapshot.value = null
        trackers.clear()
        history.value = history.value?.copy(day = null, reading = false, closed = false)
        blocking.value = blocking.value.copy(tallies = emptyList())
    }

    override fun onDestroy() {
        super.onDestroy()
        worker.close()
    }

    /** One second's snapshot, the names and companies of new UIDs and the trackers of new destinations, off the main thread. */
    private suspend fun refresh() {
        val known = names.keys.toSet()
        val seen = trackers.keys.toSet()
        val read = withContext(worker) {
            val read = Snapshot.parse(Engine.nativeActivity())
            // An SDK Runtime UID's app too, whose name its choice's confirmation shows (unit C).
            val uids = read?.apps.orEmpty().map { it.uid }
            val named = (uids + uids.map { it?.let(ProxyChoice::appOf) }).distinct().filter { it !in known }.associateWith(appNames::of)
            val grouped = named.mapValues { (_, app) -> groupOf(app) }
            val blocked = readBlocking()
            // The rows blocking counted, at port 443, for the marks that group a company's trackers under one allow.
            val rows = blocked.tallies.mapNotNull { blocked.facts?.table?.row(it.host) }.map(RowNames::host)
            val hosts = (read?.apps.orEmpty().flatMap { app -> app.destinations.flatMap(::hostsOf) } + rows).distinct().filter { it !in seen }
            Fetched(read, named, grouped, matchTrackers(hosts), namesOf(tunnelsOf(read)), blocked, readChoices())
        }
        tunnelNames.putAll(read.tunnels)
        names.putAll(read.named)
        groups.putAll(read.grouped)
        keep(read.trackers)
        blocking.value = read.blocking
        choices.value = read.choices
        snapshot.value = read.snapshot
    }

    /**
     * The user's choice for one app as it stands, off the main thread (unit C): the app UIDs the hand-over gives the
     * engine now, by the same rule ([LoggedApps.chosen]), why any ended in this run, the switch of every app, and the
     * circumvention tools and Android's PAC handler, as the service published them or, while it published none, as this
     * screen reads them itself, once.
     */
    private fun readChoices(): ProxyChoices {
        val published = org.visadahyu.datapavan.network.proxy.ProxyContext.state.value
        val tools = published.tools.keys.ifEmpty {
            ownTools ?: org.visadahyu.datapavan.network.chain.Tools.uids(this).keys.also { ownTools = it }
        }
        val pacHandler = published.pacHandler ?: org.visadahyu.datapavan.network.proxy.PacHandler.uid(packageManager)
        val store = LoggedApps.of(this)
        return ProxyChoices(
            switchOn = org.visadahyu.datapavan.network.chain.ChainSettings.of(this).logDestinations,
            chosen = store.chosen(LoggedApps.packages(packageManager), tools, pacHandler),
            ended = store.ended(),
            stopped = stopped,
            tools = tools,
            pacHandler = pacHandler,
            user = android.os.Process.myUid() / ProxyChoice.PER_USER_RANGE,
            sdkRuntime = sdkRuntime,
        )
    }

    /**
     * A choice for the app [app] turned on, once its confirmation said yes, or off ([stop]): every package of its UID with
     * its first install time written off the main thread, which has the running service hand it to the engine at once,
     * and the view read again.
     */
    private fun changeChoice(app: Int, stop: Boolean) {
        stopped = if (stop) stopped + app else stopped - app
        lifecycleScope.launch {
            choices.value = withContext(worker) {
                val store = LoggedApps.of(this@NowActivity)
                val packages = LoggedApps.packages(packageManager)
                if (stop) store.stop(packages.packagesOf(app)) else store.choose(LoggedApps.entriesOfUid(packages, app))
                readChoices()
            }
        }
    }

    /**
     * Tracker blocking as it stands, off the main thread: the facts the service last handed the engine (or this screen's
     * own reading, where it handed none in this process), what the engine counted in memory, and the user's allowances
     * and pause, ended ones forgotten.
     */
    private fun readBlocking(): BlockingView {
        val settings = BlockingSettings.of(this)
        val now = System.currentTimeMillis()
        val facts = BlockingState.facts.value ?: ownFacts
            ?: BlockingFacts.read(this, settings.browsers, covering = settings.on, hand = null).also { ownFacts = it }
        val tallies = if (NetworkVpnService.running.value) Tallies.parse(Engine.nativeBlocked()) else emptyList()
        return BlockingView(settings.on, facts, tallies, settings.appsAllowed(now), settings.entriesAllowed(), settings.pausedUntil(now))
    }

    /** A tap of the undo: the allowance written, handed to the running service at once, and the view read again. */
    private fun changeBlocking(change: (BlockingSettings, Long) -> Unit) {
        change(BlockingSettings.of(this), System.currentTimeMillis())
        if (NetworkVpnService.running.value) {
            startService(
                Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_BLOCKING)
                    .putExtra(NetworkVpnService.EXTRA_FULL, false),
            )
        }
        lifecycleScope.launch { blocking.value = withContext(worker) { readBlocking() } }
    }

    /**
     * Whether "Log where apps connect ..." leaves the destinations of the app of [packages] out ([tool] whether it is the
     * user's tool): the switch off, and the app the tool, chained to it, or sent through a WireGuard configuration. A
     * state of the configurations that cannot be read now counts as sent through one, so that no host is named on a
     * guess.
     */
    private fun hidesHosts(packages: List<String>, tool: Boolean): Boolean {
        val chain = org.visadahyu.datapavan.network.chain.ChainSettings.of(this)
        if (chain.logDestinations) return false
        if (tool) return true
        val chained = chain.on && chain.lastTool != null && (chain.allApps || packages.any { it in chain.apps })
        val tunnelled = try {
            org.visadahyu.datapavan.network.tunnel.TunnelStore.of(this).state().routes.keys.any { it in packages }
        } catch (e: java.io.IOException) {
            true
        } catch (e: java.security.GeneralSecurityException) {
            true
        }
        return chained || tunnelled
    }

    private class Fetched(
        val snapshot: Snapshot?,
        val named: Map<Int?, AppNames.Named>,
        val grouped: Map<Int?, String?>,
        val trackers: Map<String, List<TrackerMarks.Match>>,
        val tunnels: Map<Long, String>,
        val blocking: BlockingView,
        val choices: ProxyChoices,
    )

    /** The tunnels a snapshot names, by number. */
    private fun tunnelsOf(snapshot: Snapshot?): Set<Long> = snapshot?.apps.orEmpty()
        .flatMap { app -> listOf(app.throughTunnel) + app.destinations.map { it.tunnel } }
        .filter { it != 0L }.toSet()

    /**
     * The names of the tunnels [ids], from the store (worker): a configuration's own, isolated so that it keeps its
     * direction, or a plain phrase for one since removed or that cannot be opened now.
     */
    private fun namesOf(ids: Collection<Long>): Map<Long, String> {
        val store = org.visadahyu.datapavan.network.tunnel.TunnelStore.of(this)
        return ids.filter { it <= Int.MAX_VALUE }.associateWith { id ->
            when (val name = store.name(id.toInt())) {
                is org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Known -> org.visadahyu.datapavan.ui.isolate(name.name)
                org.visadahyu.datapavan.network.tunnel.TunnelStore.Name.Removed -> getString(R.string.tunnel_removed_name)
                else -> getString(R.string.tunnel_closed_name)
            }
        }
    }

    /** The company group of an app's packages, by their signing, where the owners' table knows it (worker). */
    private fun groupOf(app: AppNames.Named): String? {
        val table = companies ?: return null
        return table.groupOfApp(
            app.packages.map { name ->
                name to try {
                    appSigning(packageManager.getPackageInfo(name, PackageManager.GET_SIGNING_CERTIFICATES))
                } catch (e: PackageManager.NameNotFoundException) {
                    null
                }
            },
        )
    }

    /** Keeps the trackers found, at most [TRACKERS_KEPT] hosts' at a time. */
    private fun keep(found: Map<String, List<TrackerMarks.Match>>) {
        if (trackers.size + found.size > TRACKERS_KEPT) trackers.clear()
        trackers.putAll(found)
    }

    /**
     * Opens the history of the app [uid] at the day [index], [tool] whether it is the user's tool: its name,
     * the log's retention and lock, and the phone's screen lock, all read off the main thread (review c1,
     * screens, nit 11: the Keystore was asked on it).
     */
    private fun openHistory(uid: Int?, index: Int, tool: Boolean) {
        lifecycleScope.launch {
            val shown = withContext(worker) {
                val named = names[uid] ?: appNames.of(uid)
                val log = ConnectionLog.of(this@NowActivity)
                val days = History.days(log.today(), log.retentionDays)
                val secure = getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
                // A proxy of the app in "Now" draws its switch for the choice (unit C; audit-C 25).
                val seen = snapshot.value?.apps.orEmpty().any { it.uid == uid && it.destinations.any { place -> place.proxy != null } }
                Triple(
                    HistoryView(
                        named, log.retentionDays, log.lockNow(), secure, days, 0, null, reading = false, tool = tool,
                        hideHosts = hidesHosts(named.packages, tool), proxiesSeen = seen,
                    ),
                    readBlocking(),
                    readChoices(),
                )
            }.let { (view, blocked, chosen) ->
                blocking.value = blocked
                choices.value = chosen
                view
            }
            history.value = shown
            if (shown.days.isNotEmpty()) showDay(index.coerceIn(0, shown.days.size - 1))
        }
    }

    /** Reads the day at [index] of the history shown, off the main thread: the log opens only when it can. */
    private fun showDay(index: Int) {
        val shown = history.value ?: return
        val day = shown.days.getOrNull(index) ?: return
        history.value = shown.copy(index = index, day = null, reading = true, closed = false)
        val seen = trackers.keys.toSet()
        lifecycleScope.launch {
            val read = withContext(worker) {
                val records = ConnectionLog.of(this@NowActivity).read(day)
                records?.let { History.day(day, it, shown.app.uid, shown.app.installedAt) }
            }
            val tunnels = read?.entries.orEmpty().map { it.tunnel }.filter { it != 0L }
            tunnelNames.putAll(withContext(worker) { namesOf(tunnels) })
            // An entry the log keeps no destination of is no host to match (review c1, screens, M3).
            // The rows of tracker blocking the day's segments reached, at port 443, for the marks that group a company's
            // trackers under one allow (W8, part 3a).
            val table = blocking.value.facts?.table
            val rows = if (table == null) emptyList() else (
                read?.entries.orEmpty().flatMap { entry ->
                    listOfNotNull(rowOf(entry, table)) + if (entry.blocked) table.ofSdk(entry.blockedSdk) else emptyList()
                } + blocking.value.tallies.mapNotNull { table.row(it.host) }
                ).map(RowNames::host)
            val hosts = (
                read?.entries.orEmpty().filter { !it.unlogged }
                    .flatMap { listOf(it.name to it.port, it.dnsName to it.port, it.address to it.port) }
                    .filter { it.first.isNotEmpty() }.map { "${it.first}\t${it.second}" } + rows
                ).distinct().filter { it !in seen }
            keep(withContext(worker) { matchTrackers(hosts) })
            val now = history.value
            if (now != null && now.index == index && now.app == shown.app) {
                // Once any day read holds a proxy record of the app, its switch for the choice stays (audit-C 25).
                val seen = now.proxiesSeen || read?.entries.orEmpty().any { it.proxy != null }
                history.value = now.copy(day = read, reading = false, closed = read == null, proxiesSeen = seen)
            }
        }
    }

    companion object {
        /**
         * The network part's "Now" screen, for the intents that open it (the network screen, the audit, and W9's
         * summary and tile).
         */
        const val CLASS_NAME = "org.visadahyu.datapavan.network.NowActivity"

        /** The one app to show, by package name: the only thing that crosses from the audit's page. */
        const val EXTRA_PACKAGE = "package"

        /** Debug builds: keep the screen unprotected, for screenshots taken by a script. */
        const val EXTRA_SCREENSHOTS = "screenshots_for_tests"

        private const val REFRESH_MS = 1_000L

        /** At most this many hosts' trackers are kept for the view; past it they are looked up anew. */
        private const val TRACKERS_KEPT = 4_096

        private const val SAVED_WINDOW = "window"
        private const val SAVED_PAUSED = "paused"
        private const val SAVED_ORDER = "order"
        private const val SAVED_ONLY = "only"
        private const val SAVED_HISTORY = "history"
        private const val SAVED_HISTORY_UID = "history_uid"
        private const val SAVED_HISTORY_NO_APP = "history_no_app"
        private const val SAVED_HISTORY_DAY = "history_day"
        private const val SAVED_HISTORY_TOOL = "history_tool"

        @Volatile
        private var trackersLoaded = false

        /** The companies of `data/owners`, from the same pack, for [TrackerMarks]; null where the pack holds none. */
        @Volatile
        internal var companies: Companies? = null
            private set

        /**
         * Hands the engine's library the network signatures of `exodus/trackers.tsv` in the data pack the audit
         * verifies, the current one, and reads the owners' tables (ADR 0020) from the same pack, once each time
         * this screen opens; no copy of the pack is kept. The network process only reads the pack's files: it never
         * deletes them, which the audit's process does for a pack that no longer applies (review c1, engine,
         * m5). Returns what the library read: how many trackers have a network signature, how many alternatives
         * it read and how many it refused; empty for none.
         */
        internal fun loadTables(context: Context): IntArray {
            val store = try {
                DataPackStore.read(context, NetworkPacks)
            } catch (e: RuntimeException) {
                return IntArray(0)
            }
            val text = { path: String -> store.text(path) }
            companies = try {
                val owners = Owners.parse(text(Owners.ENTITIES_PATH).orEmpty(), "", text(Owners.PUBLISHERS_PATH).orEmpty())
                Companies(owners, text(PUBLISHER_SOURCES).orEmpty(), LocalDate.now().toString(), text(ASNS).orEmpty())
            } catch (e: RuntimeException) {
                null
            }
            val table = store.file(TRACKERS) ?: return IntArray(0)
            trackersById = TrackerMarks.byId(String(table, Charsets.UTF_8))
            return Engine.nativeTrackers(table).also { trackersLoaded = it.isNotEmpty() }
        }

        /** Each tracker of the same table by its εxodus id, for the marks the engine kept of a proxied flow (ADR 0052). */
        @Volatile
        private var trackersById: Map<Int, TrackerMarks.Match> = emptyMap()

        /** The trackers the engine matched on a proxied flow's names before it left them out, by their ids ([LogRecord.Proxy.trackers]). */
        internal fun trackersOf(ids: List<Int>): List<TrackerMarks.Match> = ids.mapNotNull { trackersById[it] }

        /** The text the engine's library matches for a destination: its name, the DNS name and its address, at its port. */
        internal fun hostsOf(destination: Snapshot.Destination): List<String> =
            listOf(destination.name, destination.dnsName, destination.address.hostAddress.orEmpty())
                .filter { it.isNotEmpty() }.distinct().map { "$it\t${destination.port}" }

        /** The matches of each host (`host<TAB>port`), from the engine's library; none before the table loads. */
        internal fun matchTrackers(hosts: List<String>): Map<String, List<TrackerMarks.Match>> {
            if (hosts.isEmpty() || !trackersLoaded) return emptyMap()
            val asked = hosts.take(TRACKERS_KEPT)
            val lines = Engine.nativeTrackersOf(asked.joinToString("\n")).split('\n')
            return asked.withIndex().associate { (i, host) -> host to TrackerMarks.parse(lines.getOrNull(i).orEmpty()) }
        }

        private const val TRACKERS = "exodus/trackers.tsv"
        private const val PUBLISHER_SOURCES = "owners/publisher-sources.tsv"
        private const val ASNS = "owners/asns.tsv"

        /** The intent that opens "Now", for [packageName] alone if given. */
        fun intent(context: Context, packageName: String? = null): Intent =
            Intent().setClassName(context, CLASS_NAME).apply { packageName?.let { putExtra(EXTRA_PACKAGE, it) } }
    }
}
