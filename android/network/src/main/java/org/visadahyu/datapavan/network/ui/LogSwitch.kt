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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.Snapshot

/**
 * The one switch "Log where apps connect through your tool, WireGuard or a proxy" (`log_switch`; W6's
 * `chain_log_destinations`, reworded in the fix round of W8 part 2a, screens review M4). One setting holds it,
 * `ChainSettings.logDestinations`, which the engine reads with every route, for chained and tunnelled apps, the
 * circumvention tools' own connections (unit D, R10) and apps' own proxies alike. The screen draws it wherever anything is left out for it: in the
 * tool's section while the tool answers, in the WireGuard section while a configuration exists, and else on its own
 * in the log's section, while an app's own proxy has been seen since the engine started, while it is on (so that
 * what the user turned on can be turned off), while the user chose any app or tool to log one by one, whose count its
 * note gives (the proxy record's units C and D, the maintainer's decision of 2026-11-25), or when a row of "Now" or the
 * history linked to it.
 */
internal object LogSwitch {
    /** The places the network screen draws it, in the screen's order. */
    enum class Place { CHAIN, TUNNELS, ALONE }

    /**
     * What the network screen knows for it: whether an app's own proxy was seen since the engine started
     * ([proxiesSeen]), whether a row linked to it ([asked], kept across a rotation), how many links are still
     * to bring it into view ([asks]), and how many apps the user chose to log one by one ([chosen], unit C).
     */
    data class View(val proxiesSeen: Boolean = false, val asked: Boolean = false, val asks: Int = 0, val chosen: Int = 0)

    /**
     * Where the switch is drawn: in the tool's section while the tool answers ([toolAnswers]), in the WireGuard
     * section while a configuration exists ([tunnels]), and on its own when neither draws it and an app's own proxy
     * was seen ([proxiesSeen]), a row linked to it ([asked]), it is [on], or the user chose any app one by one
     * ([chosen]), whose count its note gives.
     */
    fun places(toolAnswers: Boolean, tunnels: Boolean, proxiesSeen: Boolean, asked: Boolean, on: Boolean, chosen: Boolean = false): Set<Place> =
        buildSet {
            if (toolAnswers) add(Place.CHAIN)
            if (tunnels) add(Place.TUNNELS)
            if (isEmpty() && (proxiesSeen || asked || on || chosen)) add(Place.ALONE)
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

    /**
     * Whether an app's row in "Now" leaves out where it went for the switch, and so links to it: through the tool, a
     * tunnel, or a circumvention tool's own connections no longer shown (unit D, R10), chained or not, which the engine
     * marks with [Snapshot.App.serversHidden] on a tool's row alone. The mark stays as long as such bytes are in a window,
     * so for a tool it counts only while the switch is off ([switchOn]) and the user did not choose to log where the tool
     * connects for itself ([toolChosen]): then the switch would change nothing (review D-rest m5).
     */
    fun hides(app: Snapshot.App, switchOn: Boolean = false, toolChosen: Boolean = false): Boolean =
        app.throughTool || app.throughTunnel != 0L || (app.serversHidden && !switchOn && !toolChosen)

    /**
     * Whether blocking's lines of an app's row in "Now" name a blocked connection by its tracker or SDK, never its host
     * (W8, part 3a): an app sent through the tool or a tunnel, and a circumvention tool ([tool]) while the switch is off
     * and the tool is not chosen ([toolHostsHidden]), as its history does (review D-rest m5).
     */
    fun hidesHosts(app: Snapshot.App, tool: Boolean, switchOn: Boolean, toolChosen: Boolean): Boolean =
        app.throughTool || app.throughTunnel != 0L || toolHostsHidden(tool, toolChosen, switchOn)

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

/**
 * The switch's note, the tools' own after it (unit D; review D-rest n9), then, while the user chose any app or tool to log
 * one by one (the proxy record's units C and D), how many: the notes say such an app or tool is logged all the same, and
 * the count says how many there are (the maintainer's decision of 2026-11-25; their list is W9's, behind Advanced's lock).
 */
@Composable
internal fun LogSwitchNote(chosen: Int) {
    Text(stringResource(R.string.log_switch_note_proxies), style = MaterialTheme.typography.bodyMedium)
    Text(stringResource(R.string.log_switch_note_tools), style = MaterialTheme.typography.bodyMedium)
    if (chosen > 0) {
        Text(pluralStringResource(R.plurals.log_switch_note_chosen, chosen, chosen), style = MaterialTheme.typography.bodyMedium)
    }
}

/** The switch on its own, with its note, where neither the tool's section nor the WireGuard section draws it. */
@Composable
internal fun LogSwitchAlone(on: Boolean, onChange: (Boolean) -> Unit, modifier: Modifier = Modifier, chosen: Int = 0) {
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
        LogSwitchNote(chosen)
    }
}
