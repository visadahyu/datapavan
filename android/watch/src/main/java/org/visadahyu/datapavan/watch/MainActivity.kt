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
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import org.visadahyu.datapavan.safety.ScreenProtection
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
        ChainView(null, on = false, allApps = true, apps = emptySet(), logDestinations = false, user = null, password = null, choices = emptyList()),
    )

    /** The apps the user left out of the tunnel (ADR 0041). */
    private val leftOut = mutableStateOf(emptySet<String>())

    /** Debug builds: the only apps the end-to-end test sends through the tunnel, comma-separated. */
    private var onlyApps: String? = null

    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) startTunnel() else refused.value = true
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
            runOnUiThread { chain.value = chain.value.copy(choices = choices) }
        }.apply { name = "watch-apps" }.start()
    }

    /** Copies Watch's password for the tool, marked sensitive so that Android does not show it. */
    private fun copyPassword() {
        val password = chain.value.password ?: return
        val clip = ClipData.newPlainText(getString(R.string.chain_copy), password)
        clip.description.extras = PersistableBundle().apply { putBoolean(EXTRA_IS_SENSITIVE, true) }
        getSystemService(ClipboardManager::class.java)?.setPrimaryClip(clip)
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

    private companion object {
        /** ClipDescription.EXTRA_IS_SENSITIVE, which Android 13 added; earlier versions ignore it. */
        const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

        /** Debug builds: start the tunnel at once (scripts/verify-watch.sh). */
        const val EXTRA_START = "start"

        /** Debug builds: keep the screen unprotected, for screenshots taken by a script. */
        const val EXTRA_SCREENSHOTS = "screenshots_for_tests"

        /** Debug builds: stop the tunnel, so that the engine hands its last records to the log (scripts/verify-log.sh). */
        const val EXTRA_STOP = "stop"
    }
}
