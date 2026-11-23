package org.visadahyu.datapavan.network.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.network.R

/**
 * Tracker blocking's settings on the network screen (W8, part 3a; ADR 0053): "Block trackers" ([on], off until the user
 * turns it on), "Also block in browsers" ([browsers]), and, only while the user's tool carries the apps ([toolChained]),
 * "Also block your tool's own tracker lookups" ([toolDns]); and the global pause, which names no app, with its end
 * ([pausedUntil], on the phone's clock).
 */
internal data class BlockingSettingsView(
    val on: Boolean = false,
    val browsers: Boolean = false,
    val toolDns: Boolean = false,
    val toolChained: Boolean = false,
    val pausedUntil: Long? = null,
)

/** What the user can change of blocking on the network screen. */
internal class BlockingSettingsActions(
    val onOn: (Boolean) -> Unit = {},
    val onBrowsers: (Boolean) -> Unit = {},
    val onToolDns: (Boolean) -> Unit = {},
    val onPause: () -> Unit = {},
    val onResume: () -> Unit = {},
)

/** The lines of the section, in order, as a pure function the JVM tests hold: what each state of the settings shows. */
internal enum class BlockingPart { SWITCH, NOTE, NOT_COVERED, BROWSERS, BROWSERS_NOTE, TOOL_DNS, TOOL_DNS_NOTE, PAUSED, RESUME, PAUSE, NOTES }

internal fun blockingParts(view: BlockingSettingsView): List<BlockingPart> = buildList {
    add(BlockingPart.SWITCH)
    add(BlockingPart.NOTE)
    add(BlockingPart.NOT_COVERED)
    add(BlockingPart.BROWSERS)
    add(BlockingPart.BROWSERS_NOTE)
    if (view.toolChained) {
        add(BlockingPart.TOOL_DNS)
        add(BlockingPart.TOOL_DNS_NOTE)
    }
    // A pause means something only while blocking is on.
    if (view.on) {
        if (view.pausedUntil != null) {
            add(BlockingPart.PAUSED)
            add(BlockingPart.RESUME)
        } else {
            add(BlockingPart.PAUSE)
            add(BlockingPart.NOTES)
        }
    }
}

/** The section, as [blockingParts] lays it out. */
@Composable
internal fun BlockingSection(view: BlockingSettingsView, actions: BlockingSettingsActions) {
    val context = LocalContext.current
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.blocking_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        for (part in blockingParts(view)) {
            when (part) {
                BlockingPart.SWITCH -> SwitchRow(R.string.blocking_switch, view.on, actions.onOn)
                BlockingPart.NOTE -> Note(R.string.blocking_note)
                BlockingPart.NOT_COVERED -> Note(R.string.blocking_not_covered)
                BlockingPart.BROWSERS -> SwitchRow(R.string.blocking_browsers, view.browsers, actions.onBrowsers)
                BlockingPart.BROWSERS_NOTE -> Note(R.string.blocking_browsers_note)
                BlockingPart.TOOL_DNS -> SwitchRow(R.string.blocking_tool_dns, view.toolDns, actions.onToolDns)
                BlockingPart.TOOL_DNS_NOTE -> Note(R.string.blocking_tool_dns_note)
                BlockingPart.PAUSED -> Text(
                    stringResource(R.string.blocking_paused, whenText(context, checkNotNull(view.pausedUntil))),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                BlockingPart.RESUME -> OutlinedButton(onClick = actions.onResume) { Text(stringResource(R.string.blocking_resume)) }
                BlockingPart.PAUSE -> OutlinedButton(onClick = actions.onPause) { Text(stringResource(R.string.blocking_pause)) }
                BlockingPart.NOTES -> AllowNotes()
            }
        }
    }
}

/** A switch whose row is the control. */
@Composable
private fun SwitchRow(label: Int, on: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = on, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(stringResource(label), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked = on, onCheckedChange = null)
    }
}

@Composable
private fun Note(text: Int) {
    Text(stringResource(text), style = MaterialTheme.typography.bodyMedium)
}
