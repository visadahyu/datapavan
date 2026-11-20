package org.visadahyu.datapavan.watch.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
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
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.tunnel.Import
import org.visadahyu.datapavan.watch.tunnel.KeyHome
import org.visadahyu.datapavan.watch.tunnel.Routes
import org.visadahyu.datapavan.watch.tunnel.TunnelStates
import org.visadahyu.datapavan.watch.tunnel.TunnelStore

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
    val notInstalled: List<String>,
    val fromFile: Boolean,
    val local: Boolean,
)

/** The WireGuard part of Watch's screen. */
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
)

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
)

/** A configuration's name for a sentence, isolated so that it keeps its own direction (ADR 0004). */
@Composable
internal fun shownName(name: TunnelStore.Name?): String = when (name) {
    is TunnelStore.Name.Known -> isolate(name.name)
    TunnelStore.Name.Locked, TunnelStore.Name.Lost -> stringResource(R.string.tunnel_closed_name)
    TunnelStore.Name.Removed, null -> stringResource(R.string.tunnel_removed_name)
}

/**
 * The WireGuard configurations (W7, part 2; ADR 0035): each with its state, kept fresh while the screen shows,
 * its apps, the default and "Local network directly", and the three ways to add one, with the line that a
 * picture holds the key. Names keep their own direction; nothing here shows a key, and the server's address is
 * shown only on the confirmation.
 */
@Composable
internal fun TunnelsSection(view: TunnelsView, actions: TunnelActions) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.semantics { testTagsAsResourceId = true }) {
        Text(
            stringResource(R.string.tunnels_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(stringResource(R.string.tunnels_intro), style = MaterialTheme.typography.bodyMedium)
        when (view.home) {
            KeyHome.STRONGBOX -> R.string.tunnels_key_strongbox
            KeyHome.TRUSTED_ENVIRONMENT -> R.string.tunnels_key_tee
            KeyHome.SOFTWARE -> R.string.tunnels_key_software
            KeyHome.UNKNOWN, null -> null
        }?.let { Text(stringResource(it), style = MaterialTheme.typography.bodyMedium) }
        if (view.configurations.isEmpty()) Text(stringResource(R.string.tunnels_none), style = MaterialTheme.typography.bodyMedium)
        view.configurations.forEachIndexed { index, configuration ->
            ConfigurationCard(configuration, isDefault = index == 0, several = view.configurations.size > 1, actions = actions)
        }
        if (view.configurations.size > 1) Text(stringResource(R.string.tunnels_default_note), style = MaterialTheme.typography.bodyMedium)
        if (view.full) {
            Text(stringResource(R.string.tunnels_full, TunnelStore.MAX), style = MaterialTheme.typography.bodyMedium)
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
        if (view.configurations.isNotEmpty()) {
            Switching(stringResource(R.string.chain_log_destinations), view.logDestinations, actions.onLogDestinations)
            Text(stringResource(R.string.chain_log_destinations_note), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(R.string.tunnels_log_note), style = MaterialTheme.typography.bodyMedium)
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
            Text(
                stateWords(configuration.shown),
                style = MaterialTheme.typography.bodyMedium,
                color = when (configuration.shown) {
                    TunnelStates.Shown.NotAnswering, TunnelStates.Shown.Lost, TunnelStates.Shown.Locked, TunnelStates.Shown.Missing ->
                        MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurface
                },
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag("tunnel-state-${configuration.slot}"),
            )
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

/** What a configuration's state says. */
@Composable
private fun stateWords(shown: TunnelStates.Shown): String = when (shown) {
    TunnelStates.Shown.Off -> stringResource(R.string.tunnel_state_off)
    TunnelStates.Shown.Idle -> stringResource(R.string.tunnel_state_idle)
    TunnelStates.Shown.NotAnswering -> stringResource(R.string.tunnel_state_not_answering)
    TunnelStates.Shown.Missing -> stringResource(R.string.tunnel_state_missing)
    TunnelStates.Shown.Locked -> stringResource(R.string.tunnel_state_locked)
    TunnelStates.Shown.Lost -> stringResource(R.string.tunnel_state_lost)
    is TunnelStates.Shown.Connected -> if (shown.seconds < 120) {
        pluralStringResource(R.plurals.tunnel_state_seconds, shown.seconds.toInt(), shown.seconds)
    } else {
        val minutes = shown.seconds / 60
        pluralStringResource(R.plurals.tunnel_state_minutes, minutes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), minutes)
    }
}

/**
 * The confirmation before anything is saved (W7, part 2): what the configuration does, never a key, its name, which
 * the user may change, and the apps it proposes, which the user confirms or changes; nothing is applied silently.
 */
@Composable
internal fun ImportConfirmation(pending: PendingView, choices: List<AppChoice>, actions: TunnelActions) {
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
            if (d.host.any { it.isLetter() } && ':' !in d.host) Text(stringResource(R.string.import_server_name), style = body)
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
            d.keepalive?.let { Text(stringResource(R.string.import_keepalive, it), style = body) }
            Text(stringResource(R.string.import_mtu, d.mtu), style = body)
            if (pending.replacing == null) {
                Switching(stringResource(R.string.tunnels_local), pending.local, actions.onPendingLocal)
                Text(stringResource(R.string.tunnels_local_note), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.import_apps), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
                if (pending.fromFile) Text(stringResource(R.string.import_apps_from_file), style = body)
                if (pending.notInstalled.isNotEmpty()) {
                    Text(stringResource(R.string.import_not_installed, pending.notInstalled.joinToString(", ") { isolateLtr(it) }), style = body)
                }
                if (choices.isEmpty()) Text(stringResource(R.string.import_apps_loading), style = body)
                for (app in choices) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .toggleable(value = app.packageName in pending.chosen, role = Role.Checkbox) { actions.onPendingApp(app.packageName, it) }
                            .padding(vertical = 2.dp)
                            .testTag("tunnel-app-${app.packageName}"),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(checked = app.packageName in pending.chosen, onCheckedChange = null)
                        Column(Modifier.padding(start = 12.dp)) {
                            Text(isolate(app.label), style = MaterialTheme.typography.bodyLarge)
                            Text(isolateLtr(app.packageName), style = MaterialTheme.typography.bodySmall)
                        }
                    }
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
 * Each app's one way, in one place the user can read (W7, part 2): directly, through the tool, or through one
 * configuration; an app routed to a removed configuration waits, an app left out of Watch passes through none.
 * The list opens on request; each app's choices open under it.
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
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(selected = expanded == app.packageName, role = Role.Button) {
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
