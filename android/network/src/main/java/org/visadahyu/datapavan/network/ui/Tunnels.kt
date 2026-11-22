package org.visadahyu.datapavan.network.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.tunnel.Import
import org.visadahyu.datapavan.network.tunnel.KeyHome
import org.visadahyu.datapavan.network.tunnel.Routes
import org.visadahyu.datapavan.network.tunnel.TunnelStates
import org.visadahyu.datapavan.network.tunnel.TunnelStore

/** One configuration as the screen shows it (W7, part 2). */
internal data class ConfigurationView(
    val slot: Int,
    val name: TunnelStore.Name,
    val local: Boolean,
    val apps: Int,
    val shown: TunnelStates.Shown,
    /** Its endpoint's name was resolved only over plain DNS. */
    val plainDns: Boolean,
)

/** A configuration on its way to the store: what it does, the name, and the apps chosen for it. */
internal data class PendingView(
    val described: Import.Described,
    val name: String,
    /** The slot it replaces, keeping that one's apps and switches; null for a new one. */
    val replacing: Int?,
    val replacingName: String?,
    val chosen: Set<String>,
    val local: Boolean,
    /** What the file proposes, read once the apps the user can choose are loaded; null while they load. */
    val proposal: Import.Proposal? = null,
) {
    /** Whether the file names apps, in either of WireGuard's lists. */
    val fromFile: Boolean get() = described.only.isNotEmpty() || described.except.isNotEmpty()

    /**
     * With [next], what the file proposes read anew: its ticks the first time only, so that ticks, a name and a
     * switch the user changed meanwhile stay (fix round, screens review m3).
     */
    fun with(next: Import.Proposal): PendingView = copy(proposal = next, chosen = if (proposal == null) next.ticked else chosen)
}

/** The WireGuard part of the network screen. */
internal data class TunnelsView(
    val configurations: List<ConfigurationView> = emptyList(),
    val home: KeyHome? = null,
    val full: Boolean = false,
    /** What the last import said when it gave no configuration, in words. */
    val message: String? = null,
    val reading: Boolean = false,
    val photoDeleted: Boolean = false,
    val pending: PendingView? = null,
    /** Each app routed to a slot, waiting ones included. */
    val routes: Map<String, Int> = emptyMap(),
    /** Each slot's name as shown, removed ones included. */
    val names: Map<Int, String> = emptyMap(),
    val logDestinations: Boolean = false,
    /** What the network part kept can no longer be opened, and every app is held until the user chooses. */
    val lost: Boolean = false,
) {
    /**
     * The note on the default tunnel (fix round, screens review M4): whenever a configuration exists, since the one
     * or the first carries ping and flows Android names no app for while any app goes through one.
     */
    val defaultNote: Int?
        get() = when (configurations.size) {
            0 -> null
            1 -> R.string.tunnels_default_note_one
            else -> R.string.tunnels_default_note
        }

    /** The apps that wait for a configuration since removed, apps left out aside (fix round, screens review m1). */
    fun waiting(leftOut: Set<String>): Map<String, Int> = Routes.split(routes, configurations.map { it.slot }, leftOut).second
}

/** What the user can do with the configurations and the apps' ways. */
internal class TunnelActions(
    val onAddFile: () -> Unit,
    val onAddCamera: () -> Unit,
    val onAddPicture: () -> Unit,
    val onReplace: (Int) -> Unit,
    val onDefault: (Int) -> Unit,
    val onRename: (Int, String) -> Unit,
    val onRemove: (Int, Boolean) -> Unit,
    val onLocal: (Int, Boolean) -> Unit,
    val onLogDestinations: (Boolean) -> Unit,
    val onPendingName: (String) -> Unit,
    val onPendingApp: (String, Boolean) -> Unit,
    val onPendingLocal: (Boolean) -> Unit,
    val onSave: () -> Unit,
    val onCancel: () -> Unit,
    val onRoute: (String, Routes.Route) -> Unit,
    val onLoadApps: () -> Unit,
    /** After a loss: true to add configurations again at once, false to let the apps go their way. */
    val onLostChoice: (Boolean) -> Unit = {},
)

/** A configuration's name for a sentence, isolated so that it keeps its own direction (ADR 0004). */
@Composable
internal fun shownName(name: TunnelStore.Name?): String = when (name) {
    is TunnelStore.Name.Known -> isolate(name.name)
    TunnelStore.Name.Locked, TunnelStore.Name.Unavailable, TunnelStore.Name.Lost -> stringResource(R.string.tunnel_closed_name)
    TunnelStore.Name.Removed, null -> stringResource(R.string.tunnel_removed_name)
}

/**
 * The WireGuard configurations (W7, part 2; ADR 0035): each with its state, kept fresh while the screen shows,
 * its apps, the default and "Local network directly", and the three ways to add one, with the line that a
 * picture holds the key. Names keep their own direction; nothing here shows a key, and the server's address is
 * shown only on the confirmation.
 */
@Composable
internal fun TunnelsSection(
    view: TunnelsView,
    actions: TunnelActions,
    leftOut: Set<String>,
    /** Brings the switch "Log where apps connect ..." into view, where the screen does so here for a row's link. */
    logSwitch: BringIntoViewRequester? = null,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.semantics { testTagsAsResourceId = true }) {
        Text(
            stringResource(R.string.tunnels_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(stringResource(R.string.tunnels_intro), style = MaterialTheme.typography.bodyMedium)
        if (view.lost) {
            LostCard(actions)
            return@Column
        }
        when (view.home) {
            KeyHome.STRONGBOX -> R.string.tunnels_key_strongbox
            KeyHome.TRUSTED_ENVIRONMENT -> R.string.tunnels_key_tee
            KeyHome.SECURE_HARDWARE -> R.string.tunnels_key_secure_hardware
            KeyHome.SOFTWARE -> R.string.tunnels_key_software
            KeyHome.UNKNOWN, null -> null
        }?.let { Text(stringResource(it), style = MaterialTheme.typography.bodyMedium) }
        if (view.configurations.isEmpty()) Text(stringResource(R.string.tunnels_none), style = MaterialTheme.typography.bodyMedium)
        view.configurations.forEachIndexed { index, configuration ->
            ConfigurationCard(configuration, isDefault = index == 0, several = view.configurations.size > 1, actions = actions)
        }
        view.defaultNote?.let { Text(stringResource(it), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("tunnels-default-note")) }
        val waiting = view.waiting(leftOut).size
        if (waiting > 0) {
            Text(
                pluralStringResource(R.plurals.tunnels_waiting, waiting, waiting),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
            )
        }
        if (view.full) {
            Text(pluralStringResource(R.plurals.tunnels_full, TunnelStore.MAX, TunnelStore.MAX), style = MaterialTheme.typography.bodyMedium)
        } else {
            OutlinedButton(onClick = actions.onAddFile, modifier = Modifier.testTag("tunnel-add-file")) {
                Text(stringResource(R.string.tunnels_add_file))
            }
            OutlinedButton(onClick = actions.onAddCamera, modifier = Modifier.testTag("tunnel-add-camera")) {
                Text(stringResource(R.string.tunnels_add_camera))
            }
            OutlinedButton(onClick = actions.onAddPicture, modifier = Modifier.testTag("tunnel-add-picture")) {
                Text(stringResource(R.string.tunnels_add_picture))
            }
            Text(stringResource(R.string.tunnels_picture_note), style = MaterialTheme.typography.bodyMedium)
        }
        val said = when {
            view.reading -> stringResource(R.string.qr_reading)
            else -> view.message
        }
        if (said != null) {
            Text(
                said,
                style = MaterialTheme.typography.bodyMedium,
                color = if (view.message != null && !view.reading) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("tunnel-message"),
            )
        }
        // The camera's photo is gone once it was read, whatever it held.
        if (view.photoDeleted && !view.reading) {
            Text(stringResource(R.string.qr_photo_deleted), style = MaterialTheme.typography.bodyMedium)
        }
        // The one switch (LogSwitch), here while a configuration exists; its note says all it covers.
        if (view.configurations.isNotEmpty()) {
            Column(Modifier.bringingIntoView(logSwitch), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Switching(stringResource(R.string.log_switch), view.logDestinations, actions.onLogDestinations)
                Text(stringResource(R.string.log_switch_note), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

/**
 * What the network part kept of the configurations can no longer be opened (key A gone for good), and every app is
 * held: the user chooses to add the configurations again or to let the apps go their way; either forgets what was kept.
 */
@Composable
private fun LostCard(actions: TunnelActions) {
    Card(Modifier.fillMaxWidth().testTag("tunnels-lost")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.tunnels_lost_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            Text(stringResource(R.string.tunnels_lost_body), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
            Text(stringResource(R.string.tunnels_lost_note), style = MaterialTheme.typography.bodyMedium)
            Button(onClick = { actions.onLostChoice(true) }, modifier = Modifier.testTag("tunnel-lost-again")) {
                Text(stringResource(R.string.tunnels_lost_again))
            }
            OutlinedButton(onClick = { actions.onLostChoice(false) }, modifier = Modifier.testTag("tunnel-lost-let-go")) {
                Text(stringResource(R.string.tunnels_lost_let_go))
            }
        }
    }
}

@Composable
private fun ConfigurationCard(configuration: ConfigurationView, isDefault: Boolean, several: Boolean, actions: TunnelActions) {
    var renaming by rememberSaveable(configuration.slot) { mutableStateOf(false) }
    var removing by rememberSaveable(configuration.slot) { mutableStateOf(false) }
    val name = shownName(configuration.name)
    Card(Modifier.fillMaxWidth().testTag("tunnel-${configuration.slot}")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(name, style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
            if (isDefault && several) Text(stringResource(R.string.tunnels_default), style = MaterialTheme.typography.labelLarge)
            // Only the state's kind is a live region: the handshake's age, which changes every second, is said beside
            // it, so that TalkBack does not announce each configuration every second (fix round, screens review M3).
            val kind = TunnelStates.kind(configuration.shown)
            Text(
                stringResource(kindWords(kind)),
                style = MaterialTheme.typography.bodyMedium,
                color = when (kind) {
                    TunnelStates.Kind.NOT_ANSWERING, TunnelStates.Kind.LOST, TunnelStates.Kind.LOCKED, TunnelStates.Kind.UNAVAILABLE,
                    TunnelStates.Kind.MISSING,
                    -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurface
                },
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("tunnel-state-${configuration.slot}"),
            )
            (configuration.shown as? TunnelStates.Shown.Connected)?.let { connected ->
                Text(handshakeWords(connected.seconds), style = MaterialTheme.typography.bodyMedium)
            }
            if (configuration.plainDns) Text(stringResource(R.string.tunnel_state_plain_dns), style = MaterialTheme.typography.bodyMedium)
            Text(
                if (configuration.apps == 0) {
                    stringResource(R.string.tunnels_no_apps)
                } else {
                    pluralStringResource(R.plurals.tunnels_apps, configuration.apps, configuration.apps)
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            Switching(stringResource(R.string.tunnels_local), configuration.local) { actions.onLocal(configuration.slot, it) }
            Text(stringResource(R.string.tunnels_local_note), style = MaterialTheme.typography.bodySmall)
            if (renaming) {
                val known = (configuration.name as? TunnelStore.Name.Known)?.name.orEmpty()
                var edited by rememberSaveable(configuration.slot) { mutableStateOf(known) }
                OutlinedTextField(
                    value = edited,
                    onValueChange = { edited = it.take(TunnelStore.NAME_LENGTH) },
                    label = { Text(stringResource(R.string.tunnels_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = {
                        actions.onRename(configuration.slot, edited)
                        renaming = false
                    },
                    enabled = TunnelStore.cleanName(edited).isNotEmpty(),
                ) { Text(stringResource(R.string.tunnels_save_name)) }
            }
            // A row of buttons wraps at a large font size, a column never cuts them.
            Column(verticalArrangement = Arrangement.spacedBy(0.dp)) {
                if (!isDefault) TextButton(onClick = { actions.onDefault(configuration.slot) }) { Text(stringResource(R.string.tunnels_make_default)) }
                if (configuration.name is TunnelStore.Name.Known && !renaming) {
                    TextButton(onClick = { renaming = true }) { Text(stringResource(R.string.tunnels_rename)) }
                }
                TextButton(onClick = { actions.onReplace(configuration.slot) }) { Text(stringResource(R.string.tunnels_replace)) }
                TextButton(onClick = { removing = true }, modifier = Modifier.testTag("tunnel-remove-${configuration.slot}")) {
                    Text(stringResource(R.string.tunnels_remove))
                }
            }
        }
    }
    if (removing) {
        RemoveDialog(name, onRemove = { wait ->
            removing = false
            actions.onRemove(configuration.slot, wait)
        }, onCancel = { removing = false })
    }
}

/**
 * The question a removal asks (ADR 0035; W7, part 2): what the configuration's apps do then. Neither choice is
 * preselected, so that no app goes its other way, directly perhaps, without the user saying so.
 */
@Composable
private fun RemoveDialog(name: String, onRemove: (Boolean) -> Unit, onCancel: () -> Unit) {
    var wait by rememberSaveable { mutableStateOf<Boolean?>(null) }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.tunnels_remove_title, name)) },
        text = {
            Column(Modifier.selectableGroup().semantics { testTagsAsResourceId = true }) {
                for ((value, words) in listOf(true to R.string.tunnels_remove_wait, false to R.string.tunnels_remove_other_way)) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = wait == value, role = Role.RadioButton) { wait = value }
                            .padding(vertical = 4.dp)
                            .testTag(if (value) "tunnel-remove-wait" else "tunnel-remove-other-way"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = wait == value, onClick = null)
                        Text(stringResource(words), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 12.dp))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { wait?.let(onRemove) }, enabled = wait != null, modifier = Modifier.semantics { testTagsAsResourceId = true }.testTag("tunnel-remove-confirm")) {
                Text(stringResource(R.string.tunnels_remove_confirm))
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.tunnels_cancel)) } },
    )
}

/**
 * What a state's kind says, the words of its live region: a kind alone, never a number, so that it changes only when
 * the state does (fix round, screens review M3).
 */
internal fun kindWords(kind: TunnelStates.Kind): Int = when (kind) {
    TunnelStates.Kind.OFF -> R.string.tunnel_state_off
    TunnelStates.Kind.IDLE -> R.string.tunnel_state_idle
    TunnelStates.Kind.NOT_ANSWERING -> R.string.tunnel_state_not_answering
    TunnelStates.Kind.MISSING -> R.string.tunnel_state_missing
    TunnelStates.Kind.LOCKED -> R.string.tunnel_state_locked
    TunnelStates.Kind.UNAVAILABLE -> R.string.tunnel_state_unavailable
    TunnelStates.Kind.LOST -> R.string.tunnel_state_lost
    TunnelStates.Kind.CONNECTED -> R.string.tunnel_state_connected
}

/** How long ago a connected configuration's last handshake was, outside the live region. */
@Composable
private fun handshakeWords(seconds: Long): String = if (seconds < 120) {
    pluralStringResource(R.plurals.tunnel_handshake_seconds, seconds.toInt(), seconds)
} else {
    val minutes = seconds / 60
    pluralStringResource(R.plurals.tunnel_handshake_minutes, minutes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), minutes)
}

/**
 * The confirmation before anything is saved (W7, part 2): what the configuration does, never a key, its name, which
 * the user may change, and the apps it proposes, which the user confirms or changes; nothing is applied silently.
 * The apps the file names come first, each with its way now, and an app that goes another way now is not ticked;
 * one the user ticks says where it moves from (fix round, screens review M2). Back cancels it.
 */
@Composable
internal fun ImportConfirmation(
    pending: PendingView,
    choices: List<AppChoice>,
    chain: Routes.Chain,
    toolName: String?,
    leftOut: Set<String>,
    view: TunnelsView,
    actions: TunnelActions,
) {
    BackHandler(onBack = actions.onCancel)
    val body = MaterialTheme.typography.bodyMedium
    val d = pending.described
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp)
                .semantics { testTagsAsResourceId = true }
                .testTag("tunnel-confirm"),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                if (pending.replacing != null) {
                    stringResource(R.string.import_replace_title, pending.replacingName ?: stringResource(R.string.tunnel_closed_name))
                } else {
                    stringResource(R.string.import_title)
                },
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.semantics { heading() },
            )
            if (pending.replacing != null) Text(stringResource(R.string.import_replace_note), style = body)
            OutlinedTextField(
                value = pending.name,
                onValueChange = { actions.onPendingName(it.take(TunnelStore.NAME_LENGTH)) },
                label = { Text(stringResource(R.string.tunnels_name)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("tunnel-name"),
            )
            Text(stringResource(R.string.import_server, isolateLtr(d.host), d.port), style = body)
            if (d.host.any { it.isLetter() } && ':' !in d.host) {
                Text(stringResource(R.string.import_server_name_quoted, quotedLabel("private_dns")), style = body)
                AndroidLabelsNote("private_dns")
            }
            Text(stringResource(R.string.import_addresses, d.addresses.joinToString(", ") { isolateLtr(it) }), style = body)
            if (!d.ipv6) Text(stringResource(R.string.import_no_ipv6), style = body)
            Text(stringResource(R.string.import_dns, d.dns.joinToString(", ") { isolateLtr(it) }), style = body)
            if (d.everything) {
                Text(stringResource(R.string.import_everything), style = body)
            } else {
                Text(
                    stringResource(R.string.import_narrower, d.allowed.take(SHOWN_NETWORKS).joinToString(", ") { isolateLtr(it) } +
                        if (d.allowed.size > SHOWN_NETWORKS) ", …" else ""),
                    style = body,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Text(stringResource(if (d.preshared) R.string.import_preshared else R.string.import_no_preshared), style = body)
            d.keepalive?.let { Text(pluralStringResource(R.plurals.import_keepalive, it, it), style = body) }
            Text(pluralStringResource(R.plurals.import_mtu, d.mtu, d.mtu), style = body)
            if (pending.replacing == null) {
                Switching(stringResource(R.string.tunnels_local), pending.local, actions.onPendingLocal)
                Text(stringResource(R.string.tunnels_local_note), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.import_apps), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
                val proposal = pending.proposal
                // Nothing is said of the apps, installed or not, while they load (fix round, screens review m2).
                if (proposal == null) {
                    Text(stringResource(R.string.import_apps_loading), style = body)
                } else {
                    ProposedApps(pending, proposal, choices, chain, toolName, leftOut, view, actions)
                }
            }
            Button(
                onClick = actions.onSave,
                enabled = TunnelStore.cleanName(pending.name).isNotEmpty(),
                modifier = Modifier.testTag("tunnel-save"),
            ) { Text(stringResource(R.string.import_save)) }
            OutlinedButton(onClick = actions.onCancel, modifier = Modifier.testTag("tunnel-cancel")) {
                Text(stringResource(R.string.tunnels_cancel))
            }
        }
    }
}

/**
 * The confirmation's apps: what the file proposes first, by name, each with its way now; the apps it leaves out and
 * those it names that cannot go through it, each said apart; then every other app the user can choose.
 */
@Composable
private fun ProposedApps(
    pending: PendingView,
    proposal: Import.Proposal,
    choices: List<AppChoice>,
    chain: Routes.Chain,
    toolName: String?,
    leftOut: Set<String>,
    view: TunnelsView,
    actions: TunnelActions,
) {
    val body = MaterialTheme.typography.bodyMedium
    val labels = choices.associate { it.packageName to it.label }
    val slots = view.configurations.map { it.slot }
    fun named(apps: List<String>) = apps.joinToString(", ") { app -> labels[app]?.let(::isolate) ?: isolateLtr(app) }
    if (pending.fromFile) {
        Text(stringResource(R.string.import_apps_from_file), style = body)
        if (proposal.ticked.size < proposal.proposed.size) Text(stringResource(R.string.import_apps_not_ticked), style = body)
    }
    if (proposal.excluded.isNotEmpty()) {
        Text(stringResource(R.string.import_excluded, named(proposal.excluded)), style = body)
        Text(stringResource(R.string.import_excluded_now), style = body)
    }
    if (proposal.notInstalled.isNotEmpty()) Text(stringResource(R.string.import_not_installed, named(proposal.notInstalled)), style = body)
    if (proposal.notChoosable.isNotEmpty()) Text(stringResource(R.string.import_not_choosable, named(proposal.notChoosable)), style = body)
    if (proposal.leftOut.isNotEmpty()) Text(stringResource(R.string.import_left_out, named(proposal.leftOut)), style = body)
    val first = proposal.proposed.toSet()
    val proposed = proposal.proposed.mapNotNull { app -> choices.firstOrNull { it.packageName == app } }
    val others = choices.filter { it.packageName !in first }
    for (app in proposed) AppRow(app, pending, Routes.of(app.packageName, chain, view.routes, slots, leftOut), toolName, view.names, actions)
    if (proposed.isNotEmpty() && others.isNotEmpty()) {
        Text(stringResource(R.string.import_apps_others), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
    }
    for (app in others) AppRow(app, pending, Routes.of(app.packageName, chain, view.routes, slots, leftOut), toolName, view.names, actions)
}

/** One app of the confirmation: its tick, its name, its way now, and where it moves from once ticked. */
@Composable
private fun AppRow(app: AppChoice, pending: PendingView, way: Routes.Route, toolName: String?, names: Map<Int, String>, actions: TunnelActions) {
    val ticked = app.packageName in pending.chosen
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = ticked, role = Role.Checkbox) { actions.onPendingApp(app.packageName, it) }
            .padding(vertical = 2.dp)
            .testTag("tunnel-app-${app.packageName}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = ticked, onCheckedChange = null)
        Column(Modifier.padding(start = 12.dp)) {
            Text(isolate(app.label), style = MaterialTheme.typography.bodyLarge)
            Text(isolateLtr(app.packageName), style = MaterialTheme.typography.bodySmall)
            val words = routeWords(way, toolName, names)
            if (ticked && way != Routes.Route.Direct) {
                Text(stringResource(R.string.import_app_moves, words), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
            } else {
                Text(stringResource(R.string.import_app_way, words), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

/**
 * Each app's one way, in one place the user can read (W7, part 2): directly, through the tool, or through one
 * configuration; an app routed to a removed configuration waits, an app left out of the network part passes through
 * none. The list opens on request; each app's choices open under it.
 */
@Composable
internal fun RoutesSection(
    view: TunnelsView,
    chain: Routes.Chain,
    toolName: String?,
    leftOut: Set<String>,
    choices: List<AppChoice>,
    actions: TunnelActions,
) {
    var open by rememberSaveable { mutableStateOf(false) }
    var expanded by rememberSaveable { mutableStateOf<String?>(null) }
    val slots = view.configurations.map { it.slot }
    val names = remember(view.names) { view.names }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.semantics { testTagsAsResourceId = true }) {
        Text(stringResource(R.string.routes_title), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
        Text(stringResource(R.string.routes_intro), style = MaterialTheme.typography.bodyMedium)
        if (chain.on && chain.allApps) Text(stringResource(R.string.routes_all_apps_note), style = MaterialTheme.typography.bodyMedium)
        OutlinedButton(
            onClick = {
                open = !open
                if (open) actions.onLoadApps()
            },
            modifier = Modifier.testTag("routes-open"),
        ) { Text(stringResource(if (open) R.string.routes_done else R.string.routes_choose)) }
        if (!open) return@Column
        for (app in choices) {
            val route = Routes.of(app.packageName, chain, view.routes, slots, leftOut)
            Column(Modifier.fillMaxWidth()) {
                // A button that opens the app's choices: TalkBack reads it as one, not as "selected" (fix round, screens
                // review, nit).
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button) {
                            expanded = if (expanded == app.packageName) null else app.packageName
                        }
                        .padding(vertical = 4.dp)
                        .testTag("route-${app.packageName}"),
                ) {
                    Column {
                        Text(isolate(app.label), style = MaterialTheme.typography.bodyLarge)
                        Text(routeWords(route, toolName, names), style = MaterialTheme.typography.bodyMedium)
                    }
                }
                if (expanded == app.packageName && route != Routes.Route.LeftOut) {
                    val offered = Routes.choices(app.packageName, chain, slots).let { if (route is Routes.Route.Waiting) listOf(route) + it else it }
                    Column(Modifier.selectableGroup().padding(start = 16.dp)) {
                        for (choice in offered) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .selectable(selected = choice == route, role = Role.RadioButton) { actions.onRoute(app.packageName, choice) }
                                    .padding(vertical = 4.dp)
                                    .testTag("route-choice-${app.packageName}-${choiceTag(choice)}"),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = choice == route, onClick = null)
                                Text(routeWords(choice, toolName, names), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 12.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

/** A choice's tag for the emulator checks, the same in every language. */
private fun choiceTag(route: Routes.Route): String = when (route) {
    Routes.Route.Direct -> "direct"
    Routes.Route.Tool -> "tool"
    is Routes.Route.Tunnel -> "tunnel-${route.slot}"
    is Routes.Route.Waiting -> "waiting-${route.slot}"
    Routes.Route.LeftOut -> "left-out"
}

@Composable
internal fun routeWords(route: Routes.Route, toolName: String?, names: Map<Int, String>): String = when (route) {
    Routes.Route.Direct -> stringResource(R.string.route_direct)
    Routes.Route.Tool -> toolName?.let { stringResource(R.string.route_tool, isolate(it)) } ?: stringResource(R.string.route_tool_unnamed)
    is Routes.Route.Tunnel -> stringResource(R.string.route_tunnel, names[route.slot] ?: stringResource(R.string.tunnel_closed_name))
    is Routes.Route.Waiting -> stringResource(R.string.route_waiting)
    Routes.Route.LeftOut -> stringResource(R.string.route_left_out)
}

/** A switch whose whole row is the control, with its label. */
@Composable
private fun Switching(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = null)
    }
}

/** How many of a narrower configuration's networks the confirmation names before "…". */
private const val SHOWN_NETWORKS = 8
