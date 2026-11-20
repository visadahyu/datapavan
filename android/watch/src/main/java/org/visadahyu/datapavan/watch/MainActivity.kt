package org.visadahyu.datapavan.watch

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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import java.io.File
import java.util.concurrent.Executors
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.visadahyu.datapavan.safety.ScreenProtection
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.watch.tunnel.Import
import org.visadahyu.datapavan.watch.tunnel.Refusals
import org.visadahyu.datapavan.watch.tunnel.Routes
import org.visadahyu.datapavan.watch.tunnel.TunnelStates
import org.visadahyu.datapavan.watch.tunnel.TunnelStore
import org.visadahyu.datapavan.watch.tunnel.qr.Capture
import org.visadahyu.datapavan.watch.tunnel.qr.QrClient
import org.visadahyu.datapavan.watch.tunnel.qr.QrDecode
import org.visadahyu.datapavan.watch.ui.ConfigurationView
import org.visadahyu.datapavan.watch.ui.PendingView
import org.visadahyu.datapavan.watch.ui.TunnelActions
import org.visadahyu.datapavan.watch.ui.TunnelsView
import org.visadahyu.datapavan.watch.chain.ChainSettings
import org.visadahyu.datapavan.watch.chain.ToolKeys
import org.visadahyu.datapavan.watch.chain.ToolSearch
import org.visadahyu.datapavan.watch.chain.Tools
import org.visadahyu.datapavan.watch.log.ConnectionLog
import org.visadahyu.datapavan.watch.ui.AppChoice
import org.visadahyu.datapavan.watch.ui.ChainActions
import org.visadahyu.datapavan.watch.ui.ChainView
import org.visadahyu.datapavan.watch.ui.WatchScreen
import org.visadahyu.datapavan.watch.ui.WatchTheme

class MainActivity : ComponentActivity() {
    /** Android refused the VPN consent the last time Watch asked. */
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

    /** The apps the user left out of the tunnel (ADR 0041). */
    private val leftOut = mutableStateOf(emptySet<String>())

    /** Debug builds: the only apps the end-to-end test sends through the tunnel, comma-separated. */
    private var onlyApps: String? = null

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startTunnel() else refused.value = true
    }

    /** The WireGuard configurations and the import (W7, part 2). */
    private val tunnels = mutableStateOf(TunnelsView())

    /** Where the Keystore, the files and the QR decoder are used: off the main thread, one thing at a time. */
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "watch-tunnels").apply { isDaemon = true } }

    /** The slot the import under way replaces, or null for a new configuration. Not secret: kept across a restart. */
    private var replacing: Int? = null

    /** The camera's photo under way, and its URI, while the camera has it. */
    private var capture: File? = null

    /** A configuration's file, from the documents screen: no storage permission. */
    private val openFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(::importFile) }

    /** A picture of a QR code, from the photo picker (the documents screen where there is none): no permission. */
    private val pickPicture = registerForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri -> uri?.let(::importPicture) }

    /** A photo of a QR code, taken by the phone's own camera for Watch, which never holds CAMERA. */
    private val takePhoto = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        photoTaken(result.resultCode == RESULT_OK)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        // A camera's photo this screen asked for before it was recreated is read when the camera answers; any other
        // left is deleted (W7, part 2). The import's slot comes back with it; a pending configuration's bytes stay
        // in this process alone (pendingImport), never in the saved state.
        replacing = savedInstanceState?.getInt(SAVED_REPLACING, 0)?.takeIf { it > 0 }
        capture = savedInstanceState?.getString(SAVED_CAPTURE)?.let { File(it) }
        pendingCapture = capture?.name
        Capture.deleteLeftovers(this, keep = capture?.name)
        refreshTunnels()
        // Each configuration's state, fresh while the screen is shown, not read while it is not.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    readStates()
                    delay(STATES_EVERY_MS)
                }
            }
        }
        setContent {
            val running by WatchVpnService.running.collectAsState()
            val privateDns by WatchVpnService.privateDns.collectAsState()
            val logLock by log.lock.collectAsState()
            WatchTheme {
                WatchScreen(
                    running = running,
                    privateDns = privateDns,
                    refused = refused.value,
                    retentionDays = retention.intValue,
                    deleted = deleted.value,
                    logLock = logLock,
                    screenLock = screenLock.value,
                    // An app left out does not pass through Watch, so it cannot be chained either.
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
                )
            }
        }
        // Debug builds only: scripts/verify-watch.sh starts the tunnel for its own apps from adb, since
        // the VPN service itself is not exported.
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (debuggable && savedInstanceState == null && intent.getBooleanExtra(EXTRA_START, false)) {
            onlyApps = intent.getStringExtra(WatchVpnService.EXTRA_ONLY_APPS)
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
            // A tool that takes a password gets Watch's; one that cannot is not offered one.
            val password = found?.takeIf { it.tool.auth != "none" }?.let { settings.password() }
            val key = found?.let { ToolKeys.verdict(this, it.tool.packageName) }
            // The tool the chain went through last names the switch that turns the chain off while
            // that tool does not answer, or is no longer installed.
            val chainedName = settings.lastTool?.packageName?.let { chained ->
                Tools.table(this).firstOrNull { it.packageName == chained }?.name ?: chained
            }
            runOnUiThread {
                chain.value = chain.value.copy(
                    search = search,
                    key = key,
                    user = password?.let { ChainSettings.userFor(found.tool.packageName) },
                    password = password,
                    chainedName = chainedName,
                )
                showSettings()
                if (found != null) applyChain()
            }
        }.apply { name = "watch-tool" }.start()
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
     * since it no longer passes through Watch. A tunnel that is up is set up again for the change.
     */
    private fun leaveOut(packageName: String, out: Boolean) {
        val store = LeftOut.of(this)
        store.apps = if (out) store.apps + packageName else store.apps - packageName
        leftOut.value = store.apps
        if (out && packageName in ChainSettings.of(this).apps) changeChain { it.apps = it.apps - packageName }
        if (WatchVpnService.running.value) {
            startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_APPLY_LEFT_OUT))
        }
    }

    private fun changeChain(change: (ChainSettings) -> Unit) {
        change(ChainSettings.of(this))
        showSettings()
        applyChain()
    }

    /** Hands the chain to the running tunnel; one that starts later reads it itself. */
    private fun applyChain() {
        if (WatchVpnService.running.value) {
            startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_APPLY_CHAIN))
        }
    }

    /** The apps the user can open, by name, but Watch and the tool: the ones the user may chain. */
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
                // A configuration waiting for the apps it proposes gets them now.
                tunnels.value.pending?.let { if (it.replacing == null) showPending(null, null) }
            }
        }.apply { name = "watch-apps" }.start()
    }

    /** Copies Watch's password for the tool, marked sensitive so that Android does not show it. */
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
    }

    override fun onDestroy() {
        super.onDestroy()
        // A configuration not yet saved stays in this process for the screen that comes back; a screen that is
        // finished drops it.
        if (isFinishing) dropPending()
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
    )

    /** Reads the configurations and their names off the main thread, and shows them. */
    private fun refreshTunnels() {
        worker.execute {
            val store = TunnelStore.of(this)
            val state = store.state()
            val slots = (state.order + state.routes.values).distinct()
            val names = slots.associateWith { store.name(it) }
            val home = if (state.order.isEmpty()) null else store.home()
            runOnUiThread {
                val shown = names.mapValues { (_, name) -> nameFor(name) }
                tunnels.value = tunnels.value.copy(
                    configurations = state.order.map { slot ->
                        ConfigurationView(
                            slot = slot,
                            name = names[slot] ?: TunnelStore.Name.Removed,
                            local = slot in state.local,
                            apps = state.routes.count { (app, s) -> s == slot && app !in leftOut.value },
                            shown = TunnelStates.shown(WatchVpnService.running.value, names[slot], null),
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
        TunnelStore.Name.Locked, TunnelStore.Name.Lost -> getString(R.string.tunnel_closed_name)
        TunnelStore.Name.Removed -> getString(R.string.tunnel_removed_name)
    }

    /** Each configuration's state from the engine, while the screen is shown (W7, part 2). */
    private fun readStates() {
        val running = WatchVpnService.running.value
        val lines = if (running) TunnelStates.read(Engine.nativeTunnelStates()) else emptyMap()
        val view = tunnels.value
        val configurations = view.configurations.map { c ->
            val line = lines[c.slot]
            c.copy(shown = TunnelStates.shown(running, c.name, line), plainDns = line?.plainDns == true)
        }
        if (configurations != view.configurations) tunnels.value = view.copy(configurations = configurations)
    }

    /** Changes the store off the main thread, then shows it and hands it to the running tunnel. */
    private fun changeTunnels(change: (TunnelStore) -> Unit) {
        worker.execute {
            change(TunnelStore.of(this))
            runOnUiThread {
                refreshTunnels()
                applyTunnels()
            }
        }
    }

    /** Hands the configurations and routes to the running tunnel; one that starts later reads them itself. */
    private fun applyTunnels() {
        if (WatchVpnService.running.value) {
            startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_APPLY_TUNNELS))
        }
    }

    /** Gives [app] the way [route]: the chain's list and the app's tunnel change together, one way per app. */
    private fun route(app: String, route: Routes.Route) {
        val settings = ChainSettings.of(this)
        val change = Routes.choose(app, route, routesChain())
        if (change.chainApps != settings.apps) changeChain { it.apps = change.chainApps }
        changeTunnels { it.route(app, change.tunnel) }
    }

    /** The chain as the routes read it. */
    private fun routesChain(): Routes.Chain {
        val settings = ChainSettings.of(this)
        return Routes.Chain(settings.on, settings.allApps, settings.apps, settings.lastTool?.packageName)
    }

    /** A configuration's file: its name, and at most [Import.MAX_TEXT] bytes of it, read off the main thread. */
    private fun importFile(uri: android.net.Uri) {
        tunnels.value = tunnels.value.copy(message = null, photoDeleted = false)
        worker.execute {
            val name = try {
                contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) cursor.getString(0) else null
                }
            } catch (e: RuntimeException) {
                null
            }
            val text = try {
                contentResolver.openInputStream(uri)?.use { readBounded(it) }
            } catch (e: java.io.IOException) {
                null
            } catch (e: SecurityException) {
                null
            }
            when (text) {
                null -> say(getString(R.string.import_unreadable))
                TOO_LONG -> say(Refusals.words(resources, Import.Refused("too-long")))
                else -> read(text, name, fromPicture = false)
            }
        }
    }

    /**
     * At most [Import.MAX_TEXT] bytes of [stream], or [TOO_LONG] when there are more. The buffers it read through
     * are zeroed; the caller zeroes what it returns.
     */
    private fun readBounded(stream: java.io.InputStream): ByteArray {
        val held = ByteArray(Import.MAX_TEXT + 1)
        var length = 0
        try {
            while (length < held.size) {
                val n = stream.read(held, length, held.size - length)
                if (n < 0) break
                length += n
            }
            return if (length > Import.MAX_TEXT) TOO_LONG else held.copyOf(length)
        } finally {
            held.fill(0)
        }
    }

    /** A picture from the photo picker: its QR code read in the decoder's isolated process. */
    private fun importPicture(uri: android.net.Uri) {
        tunnels.value = tunnels.value.copy(message = null, reading = true, photoDeleted = false)
        worker.execute {
            val result = try {
                contentResolver.openFileDescriptor(uri, "r")?.let { QrClient.decode(this, it) }
            } catch (e: java.io.IOException) {
                null
            } catch (e: SecurityException) {
                null
            } ?: QrDecode.Result.Failed(QrDecode.Failure.NOT_A_PICTURE)
            readPicture(result, photo = false)
        }
    }

    /** Asks the phone's own camera for a photo of a QR code, written to a file of Watch's own. */
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
        worker.execute {
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

    /** What the decoder gave: the configuration's text, read as a file's, or why not. Worker thread. */
    private fun readPicture(result: QrDecode.Result, photo: Boolean) {
        runOnUiThread { tunnels.value = tunnels.value.copy(reading = false, photoDeleted = photo) }
        when (result) {
            is QrDecode.Result.Text -> read(result.bytes, null, fromPicture = true)
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
        val store = TunnelStore.of(this)
        val state = store.state()
        val slot = replacing?.takeIf { it in state.order }
        if (slot == null && state.full) {
            text.fill(0)
            say(Refusals.words(resources, Import.Refused("too-many")))
            return
        }
        val taken = state.order.mapNotNull { (store.name(it) as? TunnelStore.Name.Known)?.name }
        val replacedName = slot?.let { (store.name(it) as? TunnelStore.Name.Known)?.name }
        val name = replacedName ?: Import.defaultName(if (fromPicture) null else fileName, { getString(R.string.tunnels_default_name, it) }, taken)
        runOnUiThread {
            dropPending()
            pendingImport = Import.Pending(text, reading, name)
            showPending(slot, replacedName?.let(::isolate))
        }
    }

    /** Shows the pending configuration's confirmation, with the apps it proposes once the apps are loaded. */
    private fun showPending(slot: Int?, replacedName: String?) {
        val pending = pendingImport ?: return
        val proposal = Import.propose(pending.described, chain.value.choices.map { it.packageName }, packageName, leftOut.value)
        tunnels.value = tunnels.value.copy(
            message = null,
            pending = PendingView(
                described = pending.described,
                name = pending.name,
                replacing = slot,
                replacingName = replacedName,
                chosen = proposal.apps,
                notInstalled = proposal.notInstalled,
                fromFile = pending.described.only.isNotEmpty() || pending.described.except.isNotEmpty(),
                local = false,
            ),
        )
        if (slot == null && chain.value.choices.isEmpty()) loadChoices()
    }

    /** Saves the confirmed configuration, with its name, its apps and its switch, then zeroes its bytes. */
    private fun savePending() {
        val view = tunnels.value.pending ?: return
        val pending = pendingImport ?: return
        pendingImport = null
        tunnels.value = tunnels.value.copy(pending = null)
        val apps = view.chosen
        worker.execute {
            val store = TunnelStore.of(this)
            val text = pending.text
            try {
                if (text == null) return@execute
                val slot = view.replacing
                if (slot != null) {
                    store.replace(slot, text, view.name)
                } else {
                    val added = store.add(view.name, text)
                    if (added == null) {
                        say(Refusals.words(resources, Import.Refused("too-many")))
                        return@execute
                    }
                    store.setLocal(added, view.local)
                    for (app in apps) store.route(app, added)
                    // One way per app: a chained app chosen for the tunnel leaves the chain's list.
                    val settings = ChainSettings.of(this)
                    if ((settings.apps intersect apps).isNotEmpty()) runOnUiThread { changeChain { it.apps = it.apps - apps } }
                }
            } finally {
                pending.close()
                replacing = null
            }
            runOnUiThread {
                refreshTunnels()
                applyTunnels()
            }
        }
    }

    /** Zeroes a configuration not saved. */
    private fun dropPending() {
        pendingImport?.close()
        pendingImport = null
    }

    /** Shows why an import gave no configuration. Any thread. */
    private fun say(words: String) {
        runOnUiThread { tunnels.value = tunnels.value.copy(message = words, reading = false) }
    }

    /** The activity is single-top: a debug start or stop sent while it is open comes here. */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val debuggable = applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        if (!debuggable) return
        if (intent.getBooleanExtra(EXTRA_START, false)) {
            onlyApps = intent.getStringExtra(WatchVpnService.EXTRA_ONLY_APPS)
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
            // Some builds of Android have no consent screen; Watch cannot become the VPN there.
            refused.value = true
        }
    }

    private fun startTunnel() {
        val start = Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_START)
        onlyApps?.let { start.putExtra(WatchVpnService.EXTRA_ONLY_APPS, it) }
        startService(start)
    }

    private fun stopTunnel() {
        startService(Intent(this, WatchVpnService::class.java).setAction(WatchVpnService.ACTION_STOP))
    }

    companion object {
        /**
         * The configuration on its way to the store (W7, part 2), held by Watch's process alone: never in a saved
         * state, which Android copies out of the process. Main thread only.
         */
        private var pendingImport: Import.Pending? = null

        /** The name of the camera's photo under way, which a start of the service must not delete. */
        @Volatile
        var pendingCapture: String? = null

        /** What a file longer than a configuration reads as. */
        private val TOO_LONG = ByteArray(0)

        /** How often the configurations' states are read while the screen is shown. */
        private const val STATES_EVERY_MS = 1_000L
        private const val SAVED_REPLACING = "tunnel_replacing"
        private const val SAVED_CAPTURE = "tunnel_capture"

        /** ClipDescription.EXTRA_IS_SENSITIVE, which Android 13 added; earlier versions ignore it. */
        private const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

        /** Debug builds: start the tunnel at once (scripts/verify-watch.sh). */
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
