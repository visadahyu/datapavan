package org.visadahyu.datapavan.network.ui

import android.text.BidiFormatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.safety.ScreenProtection
import org.visadahyu.datapavan.network.PrivateDns
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.log.ConnectionLog

/**
 * The network part's one screen: what it is for, whether it is on, the switch, while it is on what Private DNS
 * hides from it (W3), the user's circumvention tool and the apps sent through it (W6), the WireGuard
 * configurations and each app's way (W7, part 2), what other apps see of a VPN and the apps left out (ADR
 * 0041), how long the connection log keeps its records, with its wipe (W4), and screenshots (ADR 0040). The switch
 * "Log where apps connect ..." is drawn where [LogSwitch.places] says, and brought into view when a row of "Now" or
 * the history linked to it ([logSwitch]); [onLogSwitchShown] is told once it was. Tracker blocking's settings and its
 * global pause follow the names' section ([blocking]; W8, part 3a).
 */
@Composable
internal fun NetworkScreen(
    running: Boolean,
    privateDns: PrivateDns?,
    refused: Boolean,
    retentionDays: Int,
    deleted: Boolean,
    logLock: ConnectionLog.Lock,
    screenLock: Boolean,
    chain: ChainView,
    chainActions: ChainActions,
    tunnels: TunnelsView,
    tunnelActions: TunnelActions,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onRetention: (Int) -> Unit,
    onDelete: () -> Unit,
    leftOut: Set<String>,
    choices: List<AppChoice>,
    onLoadApps: () -> Unit,
    onLeaveOut: (String, Boolean) -> Unit,
    onNow: () -> Unit,
    dns: DnsView,
    dnsActions: DnsActions,
    logSwitch: LogSwitch.View = LogSwitch.View(),
    onLogSwitchShown: () -> Unit = {},
    blocking: BlockingSettingsView = BlockingSettingsView(),
    blockingActions: BlockingSettingsActions = BlockingSettingsActions(),
) {
    val search = chain.search as? org.visadahyu.datapavan.network.chain.ToolSearch.Answering
    val ways = org.visadahyu.datapavan.network.tunnel.Routes.Chain(chain.on, chain.allApps, chain.apps, search?.found?.tool?.packageName)
    val toolName = search?.found?.tool?.name ?: chain.chainedName
    // The import's confirmation takes the screen until the user saves or cancels (W7, part 2).
    tunnels.pending?.let {
        ImportConfirmation(it, choices.filter { app -> app.packageName !in leftOut }, ways, toolName, leftOut, tunnels, tunnelActions)
        return
    }
    val places = LogSwitch.places(
        toolAnswers = search != null,
        tunnels = tunnels.configurations.isNotEmpty() && !tunnels.lost,
        proxiesSeen = logSwitch.proxiesSeen,
        asked = logSwitch.asked,
        on = chain.logDestinations,
    )
    val target = LogSwitch.target(places)
    val requester = remember { BringIntoViewRequester() }
    // Brought into view once per link, after the tool's search, which may draw it in the tool's section instead.
    LaunchedEffect(logSwitch.asks, target, chain.search == null) {
        if (logSwitch.asks > 0 && target != null && chain.search != null) {
            // Once the place just drawn is laid out.
            withFrameNanos { }
            requester.bringIntoView()
            onLogSwitchShown()
        }
    }
    val at = { place: LogSwitch.Place -> requester.takeIf { place == target } }
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(R.string.network_title),
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            Text(stringResource(R.string.network_tagline), style = MaterialTheme.typography.bodyLarge)
            Text(
                stringResource(if (running) R.string.status_on else R.string.status_off),
                style = MaterialTheme.typography.titleMedium,
                // Read out when it changes, also when the change came from outside (another VPN).
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            if (running) {
                OutlinedButton(onClick = onStop) { Text(stringResource(R.string.turn_off)) }
            } else {
                Button(onClick = onStart) { Text(stringResource(R.string.turn_on)) }
            }
            // "Now" (ADR 0046, decision 2 (d)): what apps sent, and whether the user was using them.
            OutlinedButton(onClick = onNow) { Text(stringResource(R.string.now_open)) }
            // Strict Private DNS is said once, in the names' section below (W8's fix round, review R-m5).
            if (running && privateDns != null && privateDns != PrivateDns.Plain && privateDns !is PrivateDns.Strict) {
                PrivateDnsNote(privateDns)
            }
            DnsSection(dns, privateDns, dnsActions)
            BlockingSection(blocking, blockingActions)
            if (refused && !running) {
                Text(
                    stringResource(R.string.consent_refused_quoted, quotedLabel("always_on_vpn")),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                AndroidLabelsNote("always_on_vpn")
            }
            // An app's tunnel wins over the chain's choice: the chain's list shows it so (W7, part 2); an app waiting
            // for a removed configuration is said to wait, never to go through one (fix round, screens review m1).
            val (through, waiting) = org.visadahyu.datapavan.network.tunnel.Routes.split(tunnels.routes, tunnels.configurations.map { it.slot }, leftOut)
            val tunnelled = through.mapValues { (_, slot) -> tunnels.names[slot] ?: stringResource(R.string.tunnel_closed_name) }
            ChainSection(chain, privateDns, chainActions, tunnelled, waiting.keys, logSwitch = at(LogSwitch.Place.CHAIN))
            // One setting, shown alike in every place: the chain's, which every place's change goes through.
            TunnelsSection(tunnels.copy(logDestinations = chain.logDestinations), tunnelActions, leftOut, logSwitch = at(LogSwitch.Place.TUNNELS))
            RoutesSection(
                view = tunnels,
                chain = ways,
                toolName = toolName,
                leftOut = leftOut,
                choices = choices,
                actions = tunnelActions,
            )
            LeftOutSection(leftOut, choices, onLoadApps, onLeaveOut)
            LogSettings(retentionDays, deleted, logLock, screenLock, onRetention, onDelete) {
                if (LogSwitch.Place.ALONE in places) {
                    LogSwitchAlone(chain.logDestinations, chainActions.onLogDestinations, Modifier.bringingIntoView(at(LogSwitch.Place.ALONE)))
                }
            }
            ScreenshotSetting()
        }
    }
}

/** Why the network part reads fewer names while Private DNS encrypts the lookups, and what it still names. */
@Composable
private fun PrivateDnsNote(privateDns: PrivateDns) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // Android's own name for the setting, read from the phone (ADR 0054).
        Text(
            labelAlone("private_dns"),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            when (privateDns) {
                // The provider's name keeps its own direction inside a right-to-left sentence.
                is PrivateDns.Strict -> stringResource(
                    R.string.private_dns_strict_quoted, BidiFormatter.getInstance().unicodeWrap(privateDns.host), quotedLabel("private_dns"),
                )
                else -> stringResource(R.string.private_dns_network)
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(stringResource(R.string.private_dns_still_named), style = MaterialTheme.typography.bodyMedium)
        AndroidLabelsNote("private_dns")
    }
}

/**
 * How long the connection log keeps its records, and its wipe, one tap away (ADR 0037). What it says
 * of earlier days is only what holds on this phone: shut while it is locked once the log's key pair is
 * tied to the lock and the phone has a screen lock; open at any time if the phone has none, or refused
 * that key pair ([screenLock] is whether it has one); nothing before the key pair exists. [logSwitch] draws the
 * switch "Log where apps connect ..." here where no other section does (LogSwitch).
 */
@Composable
private fun LogSettings(
    retentionDays: Int,
    deleted: Boolean,
    logLock: ConnectionLog.Lock,
    screenLock: Boolean,
    onRetention: (Int) -> Unit,
    onDelete: () -> Unit,
    logSwitch: @Composable () -> Unit = {},
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.log_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (retentionDays == 0) {
            Text(stringResource(R.string.log_not_kept), style = MaterialTheme.typography.bodyMedium)
        } else {
            Text(stringResource(R.string.log_encrypted), style = MaterialTheme.typography.bodyMedium)
            when {
                logLock == ConnectionLog.Lock.ANY_TIME -> Text(stringResource(R.string.log_lock_refused), style = MaterialTheme.typography.bodyMedium)
                // Where the screen lock is set, as Android names the setting (ADR 0054).
                !screenLock -> {
                    Text(stringResource(R.string.log_no_screen_lock_quoted, quotedLabel("screen_lock")), style = MaterialTheme.typography.bodyMedium)
                    AndroidLabelsNote("screen_lock")
                }
                logLock == ConnectionLog.Lock.UNLOCKED_ONLY -> Text(stringResource(R.string.log_locked), style = MaterialTheme.typography.bodyMedium)
                else -> Unit
            }
        }
        Text(stringResource(R.string.log_keep), style = MaterialTheme.typography.bodyMedium)
        Column(Modifier.selectableGroup()) {
            for (days in ConnectionLog.RETENTION_CHOICES) {
                val label = if (days == 0) {
                    stringResource(R.string.log_keep_none)
                } else {
                    pluralStringResource(R.plurals.log_keep_days, days, days)
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(selected = days == retentionDays, role = Role.RadioButton) { onRetention(days) }
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    // The row is the control; the button only shows the choice.
                    RadioButton(selected = days == retentionDays, onClick = null)
                    Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
                }
            }
        }
        logSwitch()
        OutlinedButton(onClick = onDelete) { Text(stringResource(R.string.log_delete)) }
        if (deleted) {
            Text(
                stringResource(R.string.log_deleted),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
    }
}

/**
 * Every screen blocks screenshots and screen recordings (ADR 0040). A person who needs a screenshot to ask
 * for help allows it here for one minute; it is blocked again then, or when the network part leaves the screen.
 */
@Composable
private fun ScreenshotSetting() {
    val lifted by ScreenProtection.lifted.collectAsState()
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.screenshots_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            stringResource(if (lifted) R.string.screenshots_allowed else R.string.screenshots_blocked),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        if (lifted) {
            OutlinedButton(onClick = ScreenProtection::protect) { Text(stringResource(R.string.screenshots_block)) }
        } else {
            OutlinedButton(onClick = ScreenProtection::lift) { Text(stringResource(R.string.screenshots_allow)) }
        }
    }
}

/**
 * Every app can tell that a VPN is on, and the network part cannot hide that (ADR 0041): this section says so, and
 * lets the user leave out an app that does not work with the network part. The list of apps opens on request.
 */
@Composable
private fun LeftOutSection(leftOut: Set<String>, choices: List<AppChoice>, onLoadApps: () -> Unit, onLeaveOut: (String, Boolean) -> Unit) {
    var open by rememberSaveable { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.left_out_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(stringResource(R.string.vpn_seen), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.left_out_body), style = MaterialTheme.typography.bodyMedium)
        Text(
            if (leftOut.isEmpty()) {
                stringResource(R.string.left_out_none)
            } else {
                pluralStringResource(R.plurals.left_out_count, leftOut.size, leftOut.size)
            },
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        OutlinedButton(
            onClick = {
                open = !open
                if (open) onLoadApps()
            },
        ) { Text(stringResource(if (open) R.string.left_out_done else R.string.left_out_choose)) }
        if (open) {
            for (app in choices) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .toggleable(value = app.packageName in leftOut, role = Role.Checkbox) { onLeaveOut(app.packageName, it) }
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    // The row is the control; the box only shows the choice.
                    Checkbox(checked = app.packageName in leftOut, onCheckedChange = null)
                    Text(app.label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
                }
            }
        }
    }
}
