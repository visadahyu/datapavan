package org.visadahyu.datapavan.network.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.Snapshot
import org.visadahyu.datapavan.ui.isolateLtr

/*
 * A circumvention tool's own row (the proxy record's unit D, R10, as the maintainer decided on 2026-11-25, option (c)):
 * every connection of a tool, chained or not, shows in "Now" in full while it is open and for ten minutes after it
 * ends, the ones it makes directly for the apps sent through it among them; the log keeps them with no address unless
 * the switch is on or the user chose to log where that tool connects for itself. The engine decides what is shown and
 * what is logged; these lines only say it.
 */

/**
 * The lines a tool's card in "Now" says of the tool, as a pure function the JVM tests hold: the chain's tool
 * ([Snapshot.App.isTool]) is the user's circumvention tool, which carries the apps sent through it; another tool whose
 * own connections follow R10 ([ProxyChoices.isTool]) is a circumvention tool Datapavan sends no app through, which other
 * apps may use unseen (audit-D M4). Then, chained or not, while some of its bytes have no place in any of the view's
 * windows ([Snapshot.App.serversHidden], which the engine sets only on a tool's row), that "Now" no longer shows some of
 * its connections, and the rule: said of the view, not of the window chosen, since the engine's bit is the view's
 * (review D-rest n5). And for a tool whose choice the user ended on this screen, what stays of it (m8).
 */
internal fun toolCardLines(app: Snapshot.App, choices: ProxyChoices): List<Int> {
    val lines = mutableListOf<Int>()
    when {
        app.isTool -> lines += R.string.now_is_tool
        choices.isTool(app.uid) -> lines += R.string.now_is_tool_unchained
    }
    if (app.serversHidden) lines += R.string.now_tool_left_out
    if (app.uid != null && app.uid in choices.toolsStopped && !choices.toolChosen(app.uid)) lines += R.string.tool_stopped
    return lines
}

/**
 * Whether the history of [app] opens as a tool's (D8), as a pure function the JVM tests hold: the chain's tool, or another
 * whose own connections follow R10, so that its records the log keeps with no address say why (`History.leftOut`'s
 * `TOOL_SERVERS`), as the chained tool's always did.
 */
internal fun opensAsTool(app: Snapshot.App, choices: ProxyChoices): Boolean = app.isTool || choices.isTool(app.uid)

/**
 * Whether the rows of a [tool] name a blocked connection by its tracker or SDK, never by its host (W8, part 3a; ADR 0053
 * decision 8 (b) as unit D answers it), as a pure function the JVM tests hold: while the switch is off ([switchOn]) and
 * the user did not choose to log where the tool connects for itself ([toolChosen]), as the log keeps it. In "Now" and on
 * the history page alike (review D-rest m5 and m10).
 */
internal fun toolHostsHidden(tool: Boolean, toolChosen: Boolean, switchOn: Boolean): Boolean = tool && !toolChosen && !switchOn

/**
 * The link on a tool's card to its choice (D7), as a pure function the JVM tests hold: to stop it, on the card of a tool
 * the user chose while the switch is off, since the choice alone then keeps where it connects. The link to choose is on
 * its places shown here only ([toolPlaceRow]) and on its page.
 */
internal fun toolCardChoice(app: Snapshot.App, choices: ProxyChoices): Choice? =
    Choice.STOP.takeIf { choices.toolOffered(app.uid) && choices.toolChosen(app.uid) && !choices.switchOn }

/**
 * What a place of the app [uid], named [name] (isolated as the screens set it), says of itself as a tool's own
 * connection (D8), as a pure function the JVM tests hold: a place with no proxy that the engine marks as shown here only
 * ([Snapshot.Destination.shownOnly]) is one "Now" shows for its window, the switch off and the tool not chosen. It says
 * so, with who can see it (D10), and links to the switch, and to the choice while the tool can be chosen. Any other
 * place says nothing of it: an app's own proxy's first hop says so on its proxy row (unit A).
 */
internal fun toolPlaceRow(place: Snapshot.Destination, uid: Int?, name: String, choices: ProxyChoices): ProxyRow? {
    if (!place.shownOnly || place.proxy != null) return null
    val log = Choice.LOG.takeIf { choices.toolOffered(uid) && !choices.toolChosen(uid) && !choices.switchOn }
    return ProxyRow(null, listOf(ProxyLine(R.string.now_tool_live_only, args = listOf(name))), toSwitch = true, toTool = log)
}

/**
 * The taps on the choice for one tool: [onLog] once the confirmation said yes, with the packages it named, of which alone
 * the choice is made, as for an app (review C-rest 9); [onStop] at once, since a choice turned off keeps less. Each
 * takes the tool's UID.
 */
internal class ToolChoiceActions(val onLog: (Int, List<String>) -> Unit = { _, _ -> }, val onStop: (Int) -> Unit = {})

/** A tool's place's, proxy row's or card's link to its choice ([toolPlaceRow], [proxyRow], [toolCardChoice]). */
@Composable
internal fun ToolChoiceLink(choice: Choice, onClick: () -> Unit) {
    TextButton(onClick = onClick, modifier = Modifier.testTag(if (choice == Choice.LOG) "tool-log-link" else "tool-stop-link")) {
        Text(stringResource(if (choice == Choice.LOG) R.string.tool_log_link else R.string.tool_stop_link))
    }
}

/**
 * The lines of a tool's place in "Now" ([toolPlaceRow]), after its own: the window's line, then the link to the switch
 * and the link to the choice.
 */
@Composable
internal fun ToolPlaceLines(row: ProxyRow, onLogSwitch: () -> Unit, onChoice: (Choice) -> Unit) {
    ProxyLines(row.lines)
    if (row.toSwitch) LogSwitchLink(onLogSwitch)
    row.toTool?.let { choice -> ToolChoiceLink(choice) { onChoice(choice) } }
}

/**
 * The switch "Log where TOOL connects for itself" on a tool's page (D7), drawn for any tool the choice can cover
 * ([ProxyChoices.toolOffered]), as the switch of every app is drawn on its own: turning it on asks first ([onAsk]),
 * turning it off acts at once ([onStop]). Under it, while the switch of every app is on, that it logs the tool anyway;
 * and once the user ended it here, what stays.
 */
@Composable
internal fun ToolLogSwitch(name: String, chosen: Boolean, switchOn: Boolean, stopped: Boolean, onAsk: () -> Unit, onStop: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = chosen, role = Role.Switch, onValueChange = { on -> if (on) onAsk() else onStop() })
                .padding(vertical = 4.dp)
                .testTag("tool-log"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.tool_log, name), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Switch(checked = chosen, onCheckedChange = null)
        }
        if (switchOn) Text(stringResource(R.string.tool_log_switch_on), style = MaterialTheme.typography.bodyMedium)
        if (stopped && !chosen) Text(stringResource(R.string.tool_stopped), style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * The confirmation of the choice for the tool [name] (D7; D10): what it logs from now on and what it does not, the cost
 * on a searched phone, what Datapavan cannot tell apart, every package of a shared UID ([packages]), and what ends it.
 * Neither button is chosen beforehand, as the choice for one app's (AppProxyChoiceDialog), whose words they share. A
 * dialog is a window of its own, so its buttons give their tags as resource ids themselves, for the chain shard (review
 * D-rest m9), as the removal of a configuration does (Tunnels.kt).
 */
@Composable
internal fun ToolChoiceDialog(name: String, packages: List<String>, onYes: () -> Unit, onNo: () -> Unit) {
    AlertDialog(
        onDismissRequest = onNo,
        title = { Text(stringResource(R.string.tool_log_title, name)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.tool_log_body, name), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.tool_log_unsure, name), style = MaterialTheme.typography.bodyMedium)
                if (packages.size > 1) {
                    Text(
                        stringResource(R.string.proxy_app_log_together, packages.joinToString(", ") { isolateLtr(it) }),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Text(stringResource(R.string.tool_log_ends), style = MaterialTheme.typography.bodyMedium)
            }
        },
        confirmButton = {
            TextButton(onClick = onYes, modifier = Modifier.semantics { testTagsAsResourceId = true }.testTag("tool-log-yes")) {
                Text(stringResource(R.string.proxy_app_log_yes))
            }
        },
        dismissButton = {
            TextButton(onClick = onNo, modifier = Modifier.semantics { testTagsAsResourceId = true }.testTag("tool-log-no")) {
                Text(stringResource(R.string.proxy_app_log_no))
            }
        },
    )
}
