package org.visadahyu.datapavan.network.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.Snapshot

/**
 * The one switch "Log where apps connect through your tool, WireGuard or a proxy" (`log_switch`; W6's
 * `chain_log_destinations`, reworded in the fix round of W8 part 2a, screens review M4). One setting holds it,
 * `ChainSettings.logDestinations`, which the engine reads with every route, for chained and tunnelled apps, the
 * tool's own servers and apps' own proxies alike. The screen draws it wherever anything is left out for it: in the
 * tool's section while the tool answers, in the WireGuard section while a configuration exists, and else on its own
 * in the log's section, while an app's own proxy has been seen since the engine started, while it is on (so that
 * what the user turned on can be turned off), or when a row of "Now" or the history linked to it.
 */
internal object LogSwitch {
    /** The places the network screen draws it, in the screen's order. */
    enum class Place { CHAIN, TUNNELS, ALONE }

    /**
     * What the network screen knows for it: whether an app's own proxy was seen since the engine started
     * ([proxiesSeen]), whether a row linked to it ([asked], kept across a rotation), and how many links are still
     * to bring it into view ([asks]).
     */
    data class View(val proxiesSeen: Boolean = false, val asked: Boolean = false, val asks: Int = 0)

    /**
     * Where the switch is drawn: in the tool's section while the tool answers ([toolAnswers]), in the WireGuard
     * section while a configuration exists ([tunnels]), and on its own when neither draws it and an app's own proxy
     * was seen ([proxiesSeen]), a row linked to it ([asked]) or it is [on].
     */
    fun places(toolAnswers: Boolean, tunnels: Boolean, proxiesSeen: Boolean, asked: Boolean, on: Boolean): Set<Place> =
        buildSet {
            if (toolAnswers) add(Place.CHAIN)
            if (tunnels) add(Place.TUNNELS)
            if (isEmpty() && (proxiesSeen || asked || on)) add(Place.ALONE)
        }

    /** Where a row's link brings the user: the first place the switch is drawn, if any. */
    fun target(places: Set<Place>): Place? = Place.entries.firstOrNull { it in places }

    /**
     * Whether the engine's counters ([org.visadahyu.datapavan.network.Engine.nativeCounters]) say an app's own proxy
     * was seen since it started: requests declared ([DECLARED]) or proxies inferred ([INFERRED]), both carried across
     * the engine's hand-overs. Empty while no engine runs: none seen. Nothing of it is kept past the engine, so that a
     * phone searched keeps no trace that a proxy was used (ADR 0047).
     */
    fun proxiesSeen(counters: LongArray): Boolean = counters.getOrElse(DECLARED) { 0 } + counters.getOrElse(INFERRED) { 0 } > 0

    /**
     * Whether a proxy was seen, read again from the engine's [counters] while the network part is [running]: once seen,
     * it stays so until the network part stops, so that the moment between two engines of a hand-over, which reads no
     * counter, does not take the switch away.
     */
    fun seen(before: Boolean, running: Boolean, counters: () -> LongArray): Boolean = running && (before || proxiesSeen(counters()))

    /** Whether an app's row in "Now" leaves out where it went for the switch: through the tool, the tool's own servers, or a tunnel. */
    fun hides(app: Snapshot.App): Boolean = app.throughTool || (app.isTool && app.serversHidden) || app.throughTunnel != 0L

    /** The counters' places (`Counters::snapshot` in core/net): the proxy requests declared, and the proxies inferred. */
    const val DECLARED = 61
    const val INFERRED = 63

    /**
     * The flags of a row's link to the switch (`MainActivity.logSwitchIntent`): single-top only, so that the network
     * screen opens above "Now" and Back comes back to where the user was, the same app's row or its history (W8 part
     * 3a, the brief's point 11). `CLEAR_TOP` closed "Now" and everything above the network screen; a new task or a
     * reorder would take the user elsewhere on Back.
     */
    const val LINK_FLAGS = android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP
}

/** The switch's place, brought into view by [requester] where the screen brings it there; as it is for none. */
internal fun Modifier.bringingIntoView(requester: BringIntoViewRequester?): Modifier =
    if (requester == null) this else bringIntoViewRequester(requester)

/** The link under a row that the switch leaves out: it opens the network screen at the switch. */
@Composable
internal fun LogSwitchLink(onClick: () -> Unit) {
    TextButton(onClick = onClick) { Text(stringResource(R.string.log_switch_open)) }
}

/** The switch on its own, with its note, where neither the tool's section nor the WireGuard section draws it. */
@Composable
internal fun LogSwitchAlone(on: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier = Modifier) {
    Column(modifier, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = on, role = Role.Switch, onValueChange = onChange)
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.log_switch), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Switch(checked = on, onCheckedChange = null)
        }
        Text(stringResource(R.string.log_switch_note), style = MaterialTheme.typography.bodyMedium)
    }
}
