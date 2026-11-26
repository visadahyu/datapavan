package org.visadahyu.datapavan.network

import android.app.KeyguardManager
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.res.Configuration
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import android.os.CancellationSignal
import android.content.pm.PackageManager
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import java.io.File
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.visadahyu.datapavan.safety.ScreenProtection
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.network.tunnel.Changes
import org.visadahyu.datapavan.network.tunnel.DocumentRead
import org.visadahyu.datapavan.network.tunnel.Import
import org.visadahyu.datapavan.network.tunnel.Refusals
import org.visadahyu.datapavan.network.tunnel.Routes
import org.visadahyu.datapavan.network.tunnel.TunnelStates
import org.visadahyu.datapavan.network.tunnel.TunnelStore
import org.visadahyu.datapavan.network.tunnel.qr.Capture
import org.visadahyu.datapavan.network.tunnel.qr.QrClient
import org.visadahyu.datapavan.network.tunnel.qr.QrDecode
import org.visadahyu.datapavan.network.ui.ConfigurationView
import org.visadahyu.datapavan.network.ui.PendingView
import org.visadahyu.datapavan.network.ui.TunnelActions
import org.visadahyu.datapavan.network.ui.TunnelsView
import org.visadahyu.datapavan.network.chain.ChainSettings
import org.visadahyu.datapavan.network.chain.ToolKeys
import org.visadahyu.datapavan.network.chain.ToolSearch
import org.visadahyu.datapavan.network.chain.Tools
import org.visadahyu.datapavan.network.guides.Guides
import org.visadahyu.datapavan.network.log.ConnectionLog
import org.visadahyu.datapavan.network.ui.AppChoice
import org.visadahyu.datapavan.network.ui.ChainActions
import org.visadahyu.datapavan.network.ui.ChainView
import org.visadahyu.datapavan.network.ui.LogSwitch
import org.visadahyu.datapavan.network.ui.NetworkScreen
import org.visadahyu.datapavan.network.ui.NetworkTheme

class MainActivity : ComponentActivity() {
    /** Android refused the VPN consent the last time the network part asked. */
    private val refused = mutableStateOf(false)

    /** How long the connection log keeps its records, and whether the user just deleted it. */
    private val retention = mutableIntStateOf(0)
    private val deleted = mutableStateOf(false)

    /** Whether the phone has a screen lock (a PIN, pattern or password), read again each time the screen opens. */
    private val screenLock = mutableStateOf(false)

    /** The user's circumvention tool and the chain through it (W6). */
    private val chain = mutableStateOf(
        ChainView(null, on = false, allApps = true, apps = emptySet(), logDestinations = false, udp = false, user = null, password = null, choices = emptyList()),
    )

    /** The names of apps that go directly (W8, part 1): the user's setting, the way now, the data pack's ways. */
    private val dns = mutableStateOf(
        org.visadahyu.datapavan.network.ui.DnsView(
            running = false, status = null, choice = org.visadahyu.datapavan.network.dns.DnsSettings.Choice.Odoh,
            strict = false, only = false, notify = false, notifyRefused = false, pairs = "", catalogue = null, probe = null,
        ),
    )

    /**
     * Android 13 and later: the fallback's notification shows only once the user allows the network part's
     * notifications, so "Notify me" asks for that when it is turned on; refused, it stays off and the screen says why
     * (W8's fix round, review R-M3).
     */
    private val askNotifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) setNotify(true) else dns.value = dns.value.copy(notify = false, notifyRefused = true)
    }

    /** Whether Android lets the network part post notifications. */
    private fun notificationsAllowed(): Boolean = android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU ||
        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    /**
     * "Notify me": kept, and the notification shown or taken away at once. It is no part of the engine's setting, so
     * the engine is not told, and keeps what it learned (review R-m1).
     */
    private fun setNotify(on: Boolean) {
        org.visadahyu.datapavan.network.dns.DnsSettings.of(this).notify = on
        dns.value = dns.value.copy(notify = on, notifyRefused = false)
        Notices.show(this, Notices.Kind.DNS_FALLBACK, on && dns.value.status?.fallbackSeconds != null)
    }

    /** The apps the user left out of the tunnel (ADR 0041). */
    private val leftOut = mutableStateOf(emptySet<String>())

    /** Tracker blocking's settings and its global pause (W8, part 3a; ADR 0053), read again each second while shown. */
    private val blocking = mutableStateOf(org.visadahyu.datapavan.network.ui.BlockingSettingsView())

    /** Reads blocking's settings, the pause's end (an ended one forgotten), and whether the user's tool carries the apps. */
    private fun readBlocking() {
        val settings = org.visadahyu.datapavan.network.blocking.BlockingSettings.of(this)
        val chain = ChainSettings.of(this)
        blocking.value = org.visadahyu.datapavan.network.ui.BlockingSettingsView(
            on = settings.on,
            browsers = settings.browsers,
            toolDns = settings.toolDns,
            toolChained = chain.on && chain.lastTool != null,
            pausedUntil = settings.pausedUntil(System.currentTimeMillis()),
        )
    }

    /**
     * A change of blocking, kept and handed to the running tunnel: [full] for a setting that changes what is covered,
     * which has the service read the apps again; not for the pause, which it hands at once.
     */
    private fun changeBlocking(full: Boolean, change: (org.visadahyu.datapavan.network.blocking.BlockingSettings) -> Unit) {
        change(org.visadahyu.datapavan.network.blocking.BlockingSettings.of(this))
        readBlocking()
        if (NetworkVpnService.running.value) {
            startService(
                Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_BLOCKING)
                    .putExtra(NetworkVpnService.EXTRA_FULL, full),
            )
        }
    }

    private val blockingActions = org.visadahyu.datapavan.network.ui.BlockingSettingsActions(
        onOn = { on -> changeBlocking(full = true) { it.on = on } },
        onBrowsers = { on -> changeBlocking(full = true) { it.browsers = on } },
        onToolDns = { on -> changeBlocking(full = false) { it.toolDns = on } },
        onPause = { changeBlocking(full = false) { it.pause(System.currentTimeMillis()) } },
        onResume = { changeBlocking(full = false) { it.resume() } },
    )

    /**
     * What the screen knows for the switch "Log where apps connect ..." (LogSwitch): whether an app's own proxy was
     * seen since the engine started, read with the configurations' states, and whether a row linked to it.
     */
    private val logSwitch = mutableStateOf(LogSwitch.View())

    /** Debug builds: the only apps the end-to-end test sends through the tunnel, comma-separated. */
    private var onlyApps: String? = null

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startTunnel() else refused.value = true
    }

    /**
     * The WireGuard configurations and the import (W7, part 2), kept across the screen's recreation, the confirmation
     * among them (fix round, screens review M1).
     */
    private val model: TunnelModel by lazy { ViewModelProvider(this)[TunnelModel::class.java] }
    private val tunnels get() = model.tunnels

    /** Where the store and the Keystore are used: off the main thread, one thing at a time, never a document's read. */
    private val worker get() = TunnelModel.worker

    /** The slot the import under way replaces, or null for a new configuration. Not secret: kept across a restart. */
    private var replacing: Int?
        get() = model.replacing
        set(value) {
            model.replacing = value
        }

    /** The camera's photo under way, and its URI, while the camera has it. */
    private var capture: File? = null

    /** A configuration's file, from the documents screen: no storage permission. */
    private val openFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(::importFile) }

    /** A picture of a QR code, from the photo picker (the documents screen where there is none): no permission. */
    private val pickPicture = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> uri?.let(::importPicture) }

    /** A photo of a QR code, taken by the phone's own camera for the network part, which never holds CAMERA. */
    private val takePhoto = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        photoTaken(result.resultCode == RESULT_OK)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The window's title is what a screen reader says as the screen opens (the accessibility unit, part 2).
        setTitle(R.string.network_title)
        val dark = resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
        // Every screen is protected (ADR 0040). Debug builds may keep it off for screenshots taken by a
        // script, never release builds.
        val testBuild = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        ScreenProtection.attach(this, screenshotsForTests = testBuild && intent.getBooleanExtra(EXTRA_SCREENSHOTS, false))
        val log = ConnectionLog.of(this)
        retention.intValue = log.retentionDays
        leftOut.value = LeftOut.of(this).apps
        readBlocking()
        // The switch as stored, before the tool's search shows the rest of the chain: every place draws this one.
        chain.value = chain.value.copy(logDestinations = ChainSettings.of(this).logDestinations)
        // A row of "Now" or the history linked to the switch: drawn, and brought into view once; drawn still after a
        // rotation.
        val asked = savedInstanceState?.getBoolean(SAVED_LOG_SWITCH) ?: intent.getBooleanExtra(EXTRA_LOG_SWITCH, false)
        if (asked) logSwitch.value = logSwitch.value.copy(asked = true, asks = if (savedInstanceState == null) 1 else 0)
        // A camera's photo this screen asked for before it was recreated is read when the camera answers; any other
        // left is deleted (W7, part 2). The import's slot comes back with it; a pending configuration's bytes stay
        // in this process alone (TunnelModel), never in the saved state.
        savedInstanceState?.getInt(SAVED_REPLACING, 0)?.takeIf { it > 0 }?.let { if (replacing == null) replacing = it }
        capture = savedInstanceState?.getString(SAVED_CAPTURE)?.let { File(it) }
        pendingCapture = capture?.name
        Capture.deleteLeftovers(this, keep = capture?.name)
        refreshTunnels()
        // A confirmation open before the screen was made anew comes back with it; its apps are read again.
        if (tunnels.value.pending != null && model.held.now == null) tunnels.value = tunnels.value.copy(pending = null)
        if (tunnels.value.pending?.replacing == null && tunnels.value.pending != null) loadChoices()
        // Each configuration's state, fresh while the screen is shown, not read while it is not.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    readStates()
                    readDns()
                    // The pause ends by itself: the screen says so within a second.
                    readBlocking()
                    delay(STATES_EVERY_MS)
                }
            }
        }
        setContent {
            val running by NetworkVpnService.running.collectAsState()
            val privateDns by NetworkVpnService.privateDns.collectAsState()
            val logLock by log.lock.collectAsState()
            NetworkTheme {
                NetworkScreen(
                    running = running,
                    privateDns = privateDns,
                    refused = refused.value,
                    retentionDays = retention.intValue,
                    deleted = deleted.value,
                    logLock = logLock,
                    screenLock = screenLock.value,
                    // An app left out does not pass through the network part, so it cannot be chained either.
                    chain = chain.value.copy(choices = chain.value.choices.filter { it.packageName !in leftOut.value }),
                    chainActions = chainActions,
                    tunnels = tunnels.value,
                    tunnelActions = tunnelActions,
                    onStart = ::requestStart,
                    onStop = ::stopTunnel,
                    onRetention = { days ->
                        log.retentionDays = days
                        retention.intValue = days
                        deleted.value = false
                    },
                    onDelete = { log.wipe { gone -> runOnUiThread { deleted.value = gone } } },
                    leftOut = leftOut.value,
                    choices = chain.value.choices,
                    onLoadApps = { if (chain.value.choices.isEmpty()) loadChoices() },
                    onLeaveOut = ::leaveOut,
                    onNow = { startActivity(NowActivity.intent(this)) },
                    dns = dns.value,
                    dnsActions = dnsActions,
                    logSwitch = logSwitch.value,
                    onLogSwitchShown = { logSwitch.value = logSwitch.value.copy(asks = 0) },
                    blocking = blocking.value,
                    blockingActions = blockingActions,
                )
            }
        }
        // Debug builds only: scripts/verify-network.sh starts the tunnel for its own apps from adb, since
        // the VPN service itself is not exported.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (debuggable && savedInstanceState == null && intent.getBooleanExtra(EXTRA_START, false)) {
            onlyApps = intent.getStringExtra(NetworkVpnService.EXTRA_ONLY_APPS)
            requestStart()
        }
        if (debuggable && intent.getBooleanExtra(EXTRA_STOP, false)) stopTunnel()
        if (debuggable) openNow(intent)
    }

    /**
     * Debug builds only: the emulator checks open "Now" through this screen, which debug builds export, with
     * `now` true and, for one app, `now_package`; the screenshot switch goes along.
     */
    private fun openNow(intent: Intent) {
        if (!intent.getBooleanExtra(EXTRA_NOW, false)) return
        startActivity(
            NowActivity.intent(this, intent.getStringExtra(EXTRA_NOW_PACKAGE))
                .putExtra(NowActivity.EXTRA_SCREENSHOTS, intent.getBooleanExtra(EXTRA_SCREENSHOTS, false)),
        )
    }

    /** The screen opens: the log deletes what retention no longer keeps, whether or not traffic flows. */
    override fun onStart() {
        super.onStart()
        ConnectionLog.of(this).expire()
        // The screen lock is set in Settings, so it can only have changed while this screen was away.
        screenLock.value = getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
        // The tool may have been started, stopped or installed while this screen was away.
        searchTool()
        countChosen()
    }

    /**
     * How many apps and tools the user chose to log one by one (the proxy record's units C and D), for the switch's note,
     * one count, read off the main thread by the rule the hand-over uses: a choice made in "Now" while this screen was
     * away shows when it comes back. The tools as the service published them or, while it published none, as this screen
     * reads them, as "Now" does, so that the count and the rows agree while the tunnel is off (review C-rest 14).
     */
    private fun countChosen() {
        worker.execute {
            val published = org.visadahyu.datapavan.network.proxy.ProxyContext.state.value
            val store = org.visadahyu.datapavan.network.proxy.LoggedApps.of(this)
            val packages = org.visadahyu.datapavan.network.proxy.LoggedApps.packages(packageManager)
            val tools = published.carriers.keys.ifEmpty { org.visadahyu.datapavan.network.chain.Tools.read(this).carriers.keys }
            val count = store.chosenCount(
                packages,
                tools,
                published.pacHandler ?: org.visadahyu.datapavan.network.proxy.PacHandler.uid(packageManager),
                ready = !NetworkVpnService.running.value || published.handReady,
            )
            runOnUiThread { if (count != logSwitch.value.chosen) logSwitch.value = logSwitch.value.copy(chosen = count) }
        }
    }

    private val chainActions = ChainActions(
        onSearch = ::searchTool,
        onOn = { on -> changeChain { settings -> settings.on = on } },
        onAllApps = { all ->
            changeChain { settings -> settings.allApps = all }
            if (!all && chain.value.choices.isEmpty()) loadChoices()
        },
        onApp = { packageName, chosen ->
            changeChain { settings -> settings.apps = if (chosen) settings.apps + packageName else settings.apps - packageName }
        },
        onLogDestinations = { on -> changeChain { settings -> settings.logDestinations = on } },
        onUdp = { on -> changeChain { settings -> settings.udp = on } },
        onCopyPassword = ::copyPassword,
        onPrivateDnsSettings = ::openPrivateDnsSettings,
        onGuide = { link -> startActivity(GuideActivity.intent(this, link.guide, link.packageName)) },
    )

    /**
     * Opens the network settings, where Android keeps Private DNS. Android's own Settings app marks the
     * Private DNS row when asked by its key; other makers' Settings apps ignore the request, and the
     * screen tells the user where to look. A phone without that page gets the main settings.
     */
    private fun openPrivateDnsSettings() {
        val row = "private_dns_settings"
        val network = Intent(Settings.ACTION_WIRELESS_SETTINGS)
            .putExtra(":settings:fragment_args_key", row)
            .putExtra(":settings:show_fragment_args", Bundle().apply { putString(":settings:fragment_args_key", row) })
        try {
            startActivity(network)
        } catch (e: ActivityNotFoundException) {
            startActivity(Intent(Settings.ACTION_SETTINGS))
        }
    }

    /** Looks for the user's tool off the main thread, and shows what it found. */
    private fun searchTool() {
        chain.value = chain.value.copy(search = null)
        Thread {
            val search = Tools.search(this, "screen")
            val settings = ChainSettings.of(this)
            val found = (search as? ToolSearch.Answering)?.found
            found?.let(settings::remember)
            // A tool that takes a password gets the network part's; one that cannot is not offered one.
            val password = found?.takeIf { it.tool.auth != "none" }?.let { settings.password() }
            val key = found?.let { ToolKeys.verdict(this, it.tool.packageName) }
            // Whether the tool found is one whose own connections follow R10 (unit D), for what its open proxy lets other
            // apps keep out of the log (audit-D M4): as the service published the tools, or as this screen reads them.
            val counted = found != null && found.uid in org.visadahyu.datapavan.network.proxy.ProxyContext.state.value.carriers.keys
                .ifEmpty { Tools.read(this).carriers.keys }
            // The tool the chain went through last names the switch that turns the chain off while
            // that tool does not answer, or is no longer installed.
            val table = Tools.table(this)
            val chainedName = settings.lastTool?.packageName?.let { chained ->
                table.firstOrNull { it.packageName == chained }?.name ?: chained
            }
            // Every installed tool's guide (W8, part 3b): which one runs as a VPN is not Android's to tell.
            val guides = Guides.installed(Guides.book(this), table, ::installed)
            runOnUiThread {
                chain.value = chain.value.copy(
                    search = search,
                    key = key,
                    counted = counted,
                    user = password?.let { ChainSettings.userFor(found.tool.packageName) },
                    password = password,
                    chainedName = chainedName,
                    guides = guides,
                )
                showSettings()
                if (found != null) applyChain()
            }
        }.apply { name = "network-tool" }.start()
    }

    /** Shows the chain's settings as stored. */
    private fun showSettings() {
        val settings = ChainSettings.of(this)
        chain.value = chain.value.copy(
            on = settings.on,
            allApps = settings.allApps,
            apps = settings.apps,
            logDestinations = settings.logDestinations,
            udp = settings.udp,
        )
        if (!settings.allApps && chain.value.choices.isEmpty()) loadChoices()
    }

    /**
     * Leaves an app out of the tunnel, or takes it back (ADR 0041). An app left out leaves the chain too,
     * since it no longer passes through the network part. A tunnel that is up is set up again for the change.
     */
    private fun leaveOut(packageName: String, out: Boolean) {
        val store = LeftOut.of(this)
        store.apps = if (out) store.apps + packageName else store.apps - packageName
        leftOut.value = store.apps
        if (out && packageName in ChainSettings.of(this).apps) changeChain { it.apps = it.apps - packageName }
        if (NetworkVpnService.running.value) {
            startService(Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_LEFT_OUT))
        }
    }

    private fun changeChain(change: (ChainSettings) -> Unit) {
        change(ChainSettings.of(this))
        showSettings()
        applyChain()
    }

    /** Hands the chain to the running tunnel; one that starts later reads it itself. */
    private fun applyChain() {
        if (NetworkVpnService.running.value) {
            startService(Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_CHAIN))
        }
    }

    /** The apps the user can open, by name, but the network part and the tool: the ones the user may chain. */
    private fun loadChoices() {
        Thread {
            val tool = ChainSettings.of(this).lastTool?.packageName
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            @Suppress("DEPRECATION")
            val choices = packageManager.queryIntentActivities(launcher, 0)
                .map { it.activityInfo.applicationInfo }
                .distinctBy { it.packageName }
                .filter { it.packageName != packageName && it.packageName != tool }
                .map { AppChoice(it.packageName, packageManager.getApplicationLabel(it).toString()) }
                .sortedBy { it.label.lowercase() }
            runOnUiThread {
                chain.value = chain.value.copy(choices = choices)
                // A configuration waiting for the apps it proposes gets them now, the name and switch the user
                // changed meanwhile kept (fix round, screens review m3).
                proposeApps()
            }
        }.apply { name = "network-apps" }.start()
    }

    /** Copies the network part's password for the tool, marked sensitive so that Android does not show it. */
    private fun copyPassword() {
        val password = chain.value.password ?: return
        val clip = ClipData.newPlainText(getString(R.string.chain_copy), password)
        clip.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
        getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        replacing?.let { outState.putInt(SAVED_REPLACING, it) }
        capture?.let { outState.putString(SAVED_CAPTURE, it.path) }
        outState.putBoolean(SAVED_LOG_SWITCH, logSwitch.value.asked)
    }

    override fun onDestroy() {
        super.onDestroy()
        // A configuration not yet saved stays in the model for the screen that comes back, which zeroes it when the
        // screen finishes (TunnelModel.onCleared). A photo the camera never answered for goes now, its write grant
        // taken back first, so that the camera cannot write it again (fix round, security review m7).
        if (isFinishing) {
            // A second screen opened above "Now" by a row's link (LogSwitch.LINK_FLAGS) may finish while the first still
            // waits for the camera: only the screen whose photo it is lets go of it.
            capture?.let { file ->
                Capture.abandon(file) { Capture.revoke(this, Capture.uri(this, file)) }
                if (pendingCapture == file.name) pendingCapture = null
            }
            capture = null
        }
    }

    private val tunnelActions = TunnelActions(
        onAddFile = {
            replacing = null
            openFile.launch(arrayOf("*/*"))
        },
        onAddCamera = ::takeQrPhoto,
        onAddPicture = {
            replacing = null
            pickPicture.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
        },
        onReplace = { slot ->
            replacing = slot
            openFile.launch(arrayOf("*/*"))
        },
        onDefault = { slot -> changeTunnels { it.setDefault(slot) } },
        onRename = { slot, name -> changeTunnels { it.rename(slot, name) } },
        onRemove = { slot, wait -> changeTunnels { it.remove(slot, appsWait = wait) } },
        onLocal = { slot, on -> changeTunnels { it.setLocal(slot, on) } },
        onLogDestinations = { on ->
            changeChain { settings -> settings.logDestinations = on }
            changeTunnels { }
        },
        onPendingName = { name -> tunnels.value.pending?.let { tunnels.value = tunnels.value.copy(pending = it.copy(name = name)) } },
        onPendingApp = { app, chosen ->
            tunnels.value.pending?.let {
                tunnels.value = tunnels.value.copy(pending = it.copy(chosen = if (chosen) it.chosen + app else it.chosen - app))
            }
        },
        onPendingLocal = { on -> tunnels.value.pending?.let { tunnels.value = tunnels.value.copy(pending = it.copy(local = on)) } },
        onSave = ::savePending,
        onCancel = {
            dropPending()
            tunnels.value = tunnels.value.copy(pending = null)
        },
        onRoute = ::route,
        onLoadApps = { if (chain.value.choices.isEmpty()) loadChoices() },
        onLostChoice = ::chooseAfterLoss,
    )

    /**
     * What the user chose once what the network part kept could no longer be opened: the store forgets it all, marker
     * and wraps, the apps go their way, and with [again] the documents screen opens for a configuration (the
     * maintainer's word of 2026-11-20).
     */
    private fun chooseAfterLoss(again: Boolean) {
        worker.execute {
            val failed = Changes.run { TunnelStore.of(this).forget() }
            runOnUiThread {
                refreshTunnels()
                applyTunnels()
                if (failed != null) {
                    say(Refusals.words(resources, failed))
                } else if (again) {
                    replacing = null
                    openFile.launch(arrayOf("*/*"))
                }
            }
        }
    }

    /** Reads the configurations and their names off the main thread, and shows them. */
    private fun refreshTunnels() {
        worker.execute {
            val store = TunnelStore.of(this)
            val read = try {
                val state = store.state()
                val slots = (state.order + state.routes.values).distinct()
                Triple(state, slots.associateWith { store.name(it) }, if (state.order.isEmpty()) null else store.home())
            } catch (e: java.io.IOException) {
                // The state could not be read now: the screen keeps what it showed, and the next change reads again.
                null
            } catch (e: TunnelStore.StateLost) {
                // Lost for good: the screen asks the user what the apps do, which every app waits for meanwhile.
                runOnUiThread {
                    tunnels.value = tunnels.value.copy(lost = true, configurations = emptyList(), routes = emptyMap(), pending = null)
                }
                null
            } catch (e: java.security.GeneralSecurityException) {
                null
            } ?: return@execute
            val (state, names, home) = read
            runOnUiThread {
                val shown = names.mapValues { (_, name) -> nameFor(name) }
                tunnels.value = tunnels.value.copy(
                    lost = false,
                    configurations = state.order.map { slot ->
                        ConfigurationView(
                            slot = slot,
                            name = names[slot] ?: TunnelStore.Name.Removed,
                            local = slot in state.local,
                            apps = state.routes.count { (app, s) -> s == slot && app !in leftOut.value },
                            shown = TunnelStates.shown(NetworkVpnService.running.value, names[slot], null),
                            plainDns = false,
                        )
                    },
                    home = home,
                    full = state.full,
                    routes = state.routes,
                    names = shown,
                    logDestinations = ChainSettings.of(this).logDestinations,
                )
                readStates()
            }
        }
    }

    /** A configuration's name for a sentence. */
    private fun nameFor(name: TunnelStore.Name): String = when (name) {
        is TunnelStore.Name.Known -> isolate(name.name)
        TunnelStore.Name.Locked, TunnelStore.Name.Unavailable, TunnelStore.Name.Lost -> getString(R.string.tunnel_closed_name)
        TunnelStore.Name.Removed -> getString(R.string.tunnel_removed_name)
    }

    /** Each configuration's state from the engine, while the screen is shown (W7, part 2). */
    /** The user's DNS setting and, while the tunnel runs, the way names go now; the ways themselves once, off this thread. */
    private fun readDns() {
        val settings = org.visadahyu.datapavan.network.dns.DnsSettings.of(this)
        val running = NetworkVpnService.running.value
        val status = if (running) org.visadahyu.datapavan.network.dns.DnsStatus.parse(Engine.nativeDnsStatus()) else null
        // A permission taken back in Android's settings turns "Notify me" off on the screen, and says why.
        val allowed = notificationsAllowed()
        val view = dns.value.copy(
            running = running, status = status, choice = settings.choice, strict = settings.strict, only = settings.only,
            notify = settings.notify && allowed, notifyRefused = dns.value.notifyRefused || (settings.notify && !allowed),
            pairs = settings.pairs,
        )
        if (view != dns.value) dns.value = view
        if (view.catalogue == null && !catalogueAsked) {
            catalogueAsked = true
            worker.execute {
                val catalogue = org.visadahyu.datapavan.network.dns.DnsSettings.catalogue(this)
                runOnUiThread { dns.value = dns.value.copy(catalogue = catalogue) }
            }
        }
    }

    private var catalogueAsked = false

    /** A change of the DNS setting: kept, then handed to the engines, off this thread, since it reads the data pack. */
    private fun changeDns(change: (org.visadahyu.datapavan.network.dns.DnsSettings) -> Unit) {
        change(org.visadahyu.datapavan.network.dns.DnsSettings.of(this))
        readDns()
        worker.execute { org.visadahyu.datapavan.network.dns.DnsSettings.apply(this) }
    }

    private val dnsActions = org.visadahyu.datapavan.network.ui.DnsActions(
        onChoice = { choice ->
            dns.value = dns.value.copy(probe = null)
            changeDns { it.choice = choice }
        },
        onCustom = { choice ->
            // Tested with one query before it is saved; saved only if it answers (W8's fix round, review R-M1).
            dns.value = dns.value.copy(probe = org.visadahyu.datapavan.network.ui.DnsView.Probe.Asking)
            org.visadahyu.datapavan.network.dns.DnsProbe.check(choice) { ms, outcome ->
                runOnUiThread {
                    if (ms != null) {
                        dns.value = dns.value.copy(probe = org.visadahyu.datapavan.network.ui.DnsView.Probe.Answered(ms))
                        changeDns { it.choice = choice }
                    } else {
                        val tampered = outcome == org.visadahyu.datapavan.network.dns.Exchanger.TAMPERED
                        dns.value = dns.value.copy(probe = org.visadahyu.datapavan.network.ui.DnsView.Probe.Failed(tampered))
                    }
                }
            }
        },
        onStrict = { on -> changeDns { it.strict = on } },
        onOnly = { on -> changeDns { it.only = on } },
        onNotify = { on ->
            when {
                !on -> setNotify(false)
                notificationsAllowed() -> setNotify(true)
                else -> askNotifications.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        },
        onPairs = { pairs -> changeDns { it.pairs = pairs } },
    )

    private fun readStates() {
        val running = NetworkVpnService.running.value
        val lines = if (running) TunnelStates.read(Engine.nativeTunnelStates()) else emptyMap()
        val view = tunnels.value
        val configurations = view.configurations.map { c ->
            val line = lines[c.slot]
            c.copy(shown = TunnelStates.shown(running, c.name, line), plainDns = line?.plainDns == true)
        }
        if (configurations != view.configurations) tunnels.value = view.copy(configurations = configurations)
        // An app's own proxy seen since the engine started draws the switch that its rows name (LogSwitch).
        val seen = LogSwitch.seen(logSwitch.value.proxiesSeen, running) { Engine.nativeCounters() }
        if (seen != logSwitch.value.proxiesSeen) logSwitch.value = logSwitch.value.copy(proxiesSeen = seen)
    }

    /**
     * Changes the store off the main thread, then shows it and hands it to the running tunnel, and then runs [after]
     * on the main thread, once the change is on its way to the engine. A change that fails, a full disk, a Keystore
     * error or a slot removed meanwhile, ends alone, the store as it was, and the screen says it was not saved (fix
     * round, security review M3); [after] does not run then.
     */
    private fun changeTunnels(after: () -> Unit = {}, change: (TunnelStore) -> Unit) {
        worker.execute {
            val failed = Changes.run { change(TunnelStore.of(this)) }
            runOnUiThread {
                refreshTunnels()
                applyTunnels()
                if (failed == null) after() else say(Refusals.words(resources, failed))
            }
        }
    }

    /** Hands the configurations and routes to the running tunnel; one that starts later reads them itself. */
    private fun applyTunnels() {
        if (NetworkVpnService.running.value) {
            startService(Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_TUNNELS))
        }
    }

    /**
     * Gives [app] the way [route]: the chain's list and the app's tunnel change together, one way per app, in the
     * order that never sends it directly in between (fix round, security review M2): a tunnel's route first, and the
     * chain's list only once that change is on its way to the engine, behind it; the chain first when the app leaves
     * its tunnel.
     */
    private fun route(app: String, route: Routes.Route) {
        val settings = ChainSettings.of(this)
        val change = Routes.choose(app, route, routesChain())
        val chained = { if (change.chainApps != ChainSettings.of(this).apps) changeChain { it.apps = change.chainApps } }
        if (change.tunnelFirst) {
            changeTunnels(after = chained) { it.route(app, change.tunnel) }
        } else {
            if (change.chainApps != settings.apps) chained()
            changeTunnels { it.route(app, change.tunnel) }
        }
    }

    /** The chain as the routes read it. */
    private fun routesChain(): Routes.Chain {
        val settings = ChainSettings.of(this)
        return Routes.Chain(settings.on, settings.allApps, settings.apps, settings.lastTool?.packageName)
    }

    /**
     * A configuration's file: its name, and at most [Import.MAX_TEXT] bytes of it, read on a thread of its own within
     * [DocumentRead.LIMIT_MS], never on the store's worker, which a slow provider would hold (fix round, security
     * review M2); then read by the engine's parser on the worker.
     */
    private fun importFile(uri: android.net.Uri) {
        tunnels.value = tunnels.value.copy(message = null, photoDeleted = false)
        reading {
            val name = try {
                contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) cursor.getString(0) else null
                }
            } catch (e: RuntimeException) {
                null
            }
            val cancel = CancellationSignal()
            val got = DocumentRead.read(DocumentRead.LIMIT_MS, Import.MAX_TEXT, onLate = cancel::cancel) {
                contentResolver.openFileDescriptor(uri, "r", cancel)?.let { android.os.ParcelFileDescriptor.AutoCloseInputStream(it) }
            }
            when (got) {
                is DocumentRead.Result.Bytes -> worker.execute { read(got.bytes, name, fromPicture = false) }
                DocumentRead.Result.TooLong -> say(Refusals.words(resources, Import.Refused("too-long")))
                DocumentRead.Result.TooSlow -> say(getString(R.string.import_too_slow))
                DocumentRead.Result.Unreadable -> say(getString(R.string.import_unreadable))
            }
        }
    }

    /** Runs [task] on a thread of its own: a document's or a picture's read, which may wait on its provider. */
    private fun reading(task: () -> Unit) {
        Thread(task, "network-import").apply { isDaemon = true }.start()
    }

    /**
     * A picture from the photo picker: opened within [DocumentRead.LIMIT_MS], its QR code read in the decoder's
     * isolated process within that one's own limit, on a thread of its own.
     */
    private fun importPicture(uri: android.net.Uri) {
        tunnels.value = tunnels.value.copy(message = null, reading = true, photoDeleted = false)
        reading {
            val cancel = CancellationSignal()
            val opening = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()
            val late = opening.schedule(cancel::cancel, DocumentRead.LIMIT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
            val result = try {
                contentResolver.openFileDescriptor(uri, "r", cancel)?.let { QrClient.decode(this, it) }
            } catch (e: java.io.IOException) {
                null
            } catch (e: SecurityException) {
                null
            } catch (e: android.os.OperationCanceledException) {
                QrDecode.Result.Failed(QrDecode.Failure.TOO_SLOW)
            } catch (e: RuntimeException) {
                // A provider that no longer has the picture, or refuses it otherwise.
                null
            } finally {
                late.cancel(false)
                opening.shutdown()
            } ?: QrDecode.Result.Failed(QrDecode.Failure.NOT_A_PICTURE)
            readPicture(result, photo = false)
        }
    }

    /** Asks the phone's own camera for a photo of a QR code, written to a file of the network part's own. */
    private fun takeQrPhoto() {
        replacing = null
        tunnels.value = tunnels.value.copy(message = null, photoDeleted = false)
        val file = Capture.newFile(this)
        val uri = Capture.uri(this, file)
        val intent = Capture.intent(this, uri)
        if (intent == null) {
            file.delete()
            say(getString(R.string.qr_no_camera))
            return
        }
        capture = file
        pendingCapture = file.name
        try {
            takePhoto.launch(intent)
        } catch (e: ActivityNotFoundException) {
            Capture.revoke(this, uri)
            file.delete()
            capture = null
            pendingCapture = null
            say(getString(R.string.qr_no_camera))
        }
    }

    /** The camera answered: the grant is taken back, the photo read and deleted on every path. */
    private fun photoTaken(taken: Boolean) {
        val file = capture ?: return
        capture = null
        Capture.revoke(this, Capture.uri(this, file))
        tunnels.value = tunnels.value.copy(reading = taken)
        reading {
            val result = Capture.finish(file, taken) {
                android.os.ParcelFileDescriptor.open(it, android.os.ParcelFileDescriptor.MODE_READ_ONLY).let { picture -> QrClient.decode(this, picture) }
            }
            pendingCapture = null
            if (result == null) {
                runOnUiThread { tunnels.value = tunnels.value.copy(reading = false, photoDeleted = taken) }
            } else {
                readPicture(result, photo = true)
            }
        }
    }

    /** What the decoder gave: the configuration's text, read as a file's on the store's worker, or why not. */
    private fun readPicture(result: QrDecode.Result, photo: Boolean) {
        runOnUiThread { tunnels.value = tunnels.value.copy(reading = false, photoDeleted = photo) }
        when (result) {
            is QrDecode.Result.Text -> worker.execute { read(result.bytes, null, fromPicture = true) }
            is QrDecode.Result.Failed -> say(getString(Refusals.of(result.why)))
        }
    }

    /**
     * Reads [text] with the engine's parser: a refusal in words, or the confirmation, which holds the bytes until
     * the user saves or cancels; refused, they are zeroed at once. Worker thread.
     */
    private fun read(text: ByteArray, fileName: String?, fromPicture: Boolean) {
        val reading = try {
            Import.read(Engine.nativeTunnelParse(text))
        } catch (e: RuntimeException) {
            null
        }
        if (reading !is Import.Described) {
            text.fill(0)
            say((reading as? Import.Refused)?.let { Refusals.words(resources, it) } ?: getString(R.string.refused_unknown))
            return
        }
        val opened = try {
            val store = TunnelStore.of(this)
            val state = store.state()
            val slot = replacing?.takeIf { it in state.order }
            Triple(
                state,
                slot,
                state.order.associateWith { store.name(it) },
            )
        } catch (e: java.io.IOException) {
            null
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
        if (opened == null) {
            text.fill(0)
            say(Refusals.words(resources, Changes.NotSaved.STORAGE))
            return
        }
        val (state, slot, names) = opened
        if (slot == null && state.full) {
            text.fill(0)
            say(Refusals.words(resources, Import.Refused("too-many")))
            return
        }
        val taken = names.values.mapNotNull { (it as? TunnelStore.Name.Known)?.name }
        val replacedName = slot?.let { (names[it] as? TunnelStore.Name.Known)?.name }
        val name = replacedName ?: Import.defaultName(if (fromPicture) null else fileName, { getString(R.string.tunnels_default_name, it) }, taken)
        runOnUiThread {
            model.held.hold(Import.Pending(text, reading, name))
            tunnels.value = tunnels.value.copy(
                message = null,
                pending = PendingView(reading, name, slot, replacedName?.let(::isolate), chosen = emptySet(), local = false),
            )
            if (slot == null) {
                if (chain.value.choices.isEmpty()) loadChoices() else proposeApps()
            }
        }
    }

    /**
     * Reads, once the apps the user can choose are loaded, the apps the pending configuration proposes and how each
     * goes now; the ticks only the first time, so that the user's own changes, its name and switch with them, stay
     * (fix round, screens review M2, m2 and m3). Nothing is said of the apps while they load.
     */
    private fun proposeApps() {
        val view = tunnels.value.pending ?: return
        if (view.replacing != null || chain.value.choices.isEmpty()) return
        val ways = routesChain()
        val slots = tunnels.value.configurations.map { it.slot }
        val routes = tunnels.value.routes
        val proposal = Import.propose(
            view.described,
            chain.value.choices.map { it.packageName },
            packageName,
            leftOut.value,
            installed = ::installed,
            goesDirectly = { app -> Routes.of(app, ways, routes, slots, leftOut.value) == Routes.Route.Direct },
        )
        tunnels.value = tunnels.value.copy(pending = view.with(proposal))
    }

    /** Whether Android has the package installed, whether or not it has an icon to open it. */
    private fun installed(app: String): Boolean = try {
        @Suppress("DEPRECATION")
        packageManager.getApplicationInfo(app, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /**
     * Saves the confirmed configuration, with its name, its apps and its switch, in one change, then zeroes its bytes;
     * a change that fails leaves the store as it was and says so (fix round, security review M3). The new route goes
     * to the engine before a chained app leaves the chain's list, so that it never goes directly in between (M2).
     */
    private fun savePending() {
        val view = tunnels.value.pending ?: return
        val pending = model.held.take() ?: return
        tunnels.value = tunnels.value.copy(pending = null)
        val apps = view.chosen
        worker.execute {
            val saved = Changes.save(TunnelStore.of(this), pending, view.name, view.replacing, view.local, apps)
            runOnUiThread {
                replacing = null
                refreshTunnels()
                applyTunnels()
                when (saved) {
                    // One way per app: a chained app chosen for the tunnel leaves the chain's list, behind its route.
                    is Changes.Saved.Added -> if ((ChainSettings.of(this).apps intersect apps).isNotEmpty()) changeChain { it.apps = it.apps - apps }
                    is Changes.Saved.Replaced -> Unit
                    is Changes.Saved.Not -> say(Refusals.words(resources, saved.why))
                }
            }
        }
    }

    /** Zeroes a configuration not saved. */
    private fun dropPending() {
        model.held.drop()
    }

    /** Shows why an import gave no configuration. Any thread. */
    private fun say(words: String) {
        runOnUiThread { tunnels.value = tunnels.value.copy(message = words, reading = false) }
    }

    /**
     * The activity is single-top: a row's link to the switch (LogSwitch), and a debug start or stop sent while it is
     * open, come here.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(EXTRA_LOG_SWITCH, false)) {
            logSwitch.value = logSwitch.value.copy(asked = true, asks = logSwitch.value.asks + 1)
        }
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!debuggable) return
        if (intent.getBooleanExtra(EXTRA_START, false)) {
            onlyApps = intent.getStringExtra(NetworkVpnService.EXTRA_ONLY_APPS)
            requestStart()
        }
        if (intent.getBooleanExtra(EXTRA_STOP, false)) stopTunnel()
        openNow(intent)
    }

    /** Asks for Android's VPN consent the first time, then starts the tunnel. */
    private fun requestStart() {
        refused.value = false
        val ask = VpnService.prepare(this) ?: return startTunnel()
        try {
            consent.launch(ask)
        } catch (e: ActivityNotFoundException) {
            // Some builds of Android have no consent screen; the network part cannot become the VPN there.
            refused.value = true
        }
    }

    private fun startTunnel() {
        val start = Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_START)
        onlyApps?.let { start.putExtra(NetworkVpnService.EXTRA_ONLY_APPS, it) }
        startService(start)
    }

    private fun stopTunnel() {
        startService(Intent(this, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_STOP))
    }

    companion object {
        /** The name of the camera's photo under way, which a start of the service must not delete. */
        @Volatile
        var pendingCapture: String? = null

        /** How often the configurations' states are read while the screen is shown. */
        private const val STATES_EVERY_MS = 1_000L
        private const val SAVED_REPLACING = "tunnel_replacing"
        private const val SAVED_CAPTURE = "tunnel_capture"
        private const val SAVED_LOG_SWITCH = "log_switch"

        /** A row of "Now" or the history that the switch "Log where apps connect ..." leaves out links to it. */
        private const val EXTRA_LOG_SWITCH = "log_switch"

        /**
         * The network screen at the switch "Log where apps connect ...", for a row of "Now" or the history that links
         * to it: opened above "Now", which stays beneath it as it was, so that Back brings the user to the same app's
         * row or its history (the brief's point 11 of W8 part 3a: the link used `CLEAR_TOP`, which closed "Now"). Its
         * flags are [LogSwitch.LINK_FLAGS], which LogSwitchTest holds.
         */
        internal fun logSwitchIntent(context: android.content.Context): Intent =
            Intent(context, MainActivity::class.java)
                .putExtra(EXTRA_LOG_SWITCH, true)
                .addFlags(LogSwitch.LINK_FLAGS)

        /** ClipDescription.EXTRA_IS_SENSITIVE, which Android 13 added; earlier versions ignore it. */
        private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

        /** Debug builds: start the tunnel at once (scripts/verify-network.sh). */
        private const val EXTRA_START = "start"

        /** Debug builds: keep the screen unprotected, for screenshots taken by a script. */
        private const val EXTRA_SCREENSHOTS = "screenshots_for_tests"

        /** Debug builds: stop the tunnel, so that the engine hands its last records to the log (scripts/verify-log.sh). */
        private const val EXTRA_STOP = "stop"

        /** Debug builds: open "Now" (scripts/verify-activity.sh), for the app [EXTRA_NOW_PACKAGE] names if given. */
        private const val EXTRA_NOW = "now"
        private const val EXTRA_NOW_PACKAGE = "now_package"
    }
}
