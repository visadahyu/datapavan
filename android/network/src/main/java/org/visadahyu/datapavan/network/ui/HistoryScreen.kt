package org.visadahyu.datapavan.network.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.paneTitle
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.time.LocalDate
import java.time.ZoneId
import java.util.Date
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.AppNames
import org.visadahyu.datapavan.network.activity.Companies
import org.visadahyu.datapavan.network.activity.History
import org.visadahyu.datapavan.network.activity.TrackerMarks
import org.visadahyu.datapavan.network.log.ConnectionLog
import org.visadahyu.datapavan.network.proxy.ProxyContext

/**
 * What an app's history shows: the app, how long the log keeps its records and how it keeps them shut, the
 * days it keeps (today first), the day shown, and that day's timeline once read.
 */
internal data class HistoryView(
    val app: AppNames.Named,
    val retentionDays: Int,
    val lock: ConnectionLog.Lock,
    /** Whether the phone has a screen lock (a PIN, pattern or password). */
    val screenLock: Boolean,
    val days: List<Long>,
    val index: Int,
    val day: History.Day?,
    val reading: Boolean,
    /** The day could not be opened: a locked phone, or a failure. */
    val closed: Boolean = false,
    /** Whether the app is the user's circumvention tool, whose servers the log keeps only with the switch on. */
    val tool: Boolean = false,
    /**
     * Whether "Log where apps connect ..." leaves this app's destinations out (the tool, a chained app or a tunnelled one,
     * with the switch off): tracker blocking's lines then name a row by its tracker or SDK, never by its host (W8,
     * part 3a; ADR 0053).
     */
    val hideHosts: Boolean = false,
)

/**
 * Each app's history (ADR 0046, decision 2 (d)): its timeline from the connection log, a day at a time, newest
 * first, each segment's time, destination (both names), bytes and state. The log opens only on an unlocked
 * phone (ADR 0037): each of its lock states is said plainly. With retention "none" there is no history, and
 * the screen says how to keep one. Records older than the app now holding the UID belong to an app since
 * removed, and are counted apart. A segment the switch "Log where apps connect ..." left out says why, by its
 * recorded route and proxy ([History.leftOut]), and links to the switch ([onLogSwitch]). Tracker blocking (W8, part 3a)
 * says at the top what it blocked in the app, with the app's undo and each tracker's ([blocking], [blockingActions]),
 * and under each segment whether it was blocked, or why a host it reached is not.
 */
@Composable
internal fun HistoryScreen(
    view: HistoryView,
    appGroup: String?,
    trackers: Map<String, List<TrackerMarks.Match>>,
    companies: Companies?,
    onDay: (Int) -> Unit,
    onClose: () -> Unit,
    /** The WireGuard configurations' names by tunnel number (W7, part 2). */
    tunnelNames: Map<Long, String> = emptyMap(),
    onLogSwitch: () -> Unit = {},
    blocking: BlockingView = BlockingView(),
    blockingActions: BlockingActions = BlockingActions(),
    /** What the service knows of the proxies around the apps (the proxy record's unit B): the PAC proxy's UID and the tools'. */
    proxies: ProxyContext.State = ProxyContext.State(),
) {
    val context = LocalContext.current
    val names = RowNames(blocking.facts, companies, trackers)
    // The phone's own choice of a 12- or 24-hour clock (review c1 of W5's third part, screens, nit 6).
    val time = android.text.format.DateFormat.getTimeFormat(context)
    val date = DateFormat.getDateInstance(DateFormat.MEDIUM)
    // Named for screen readers, which say it as the history opens over "Now" (the accessibility unit, part 2).
    val paneName = stringResource(R.string.history_title, label(view.app, view.app.uid))
    LazyColumn(
        modifier = Modifier.safeDrawingPadding().testTag("history").semantics { paneTitle = paneName },
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onClose) { Text(stringResource(R.string.history_back)) }
                Text(
                    stringResource(R.string.history_title, label(view.app, view.app.uid)),
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.semantics { heading() },
                )
                Text(stringResource(R.string.history_intro), style = MaterialTheme.typography.bodyLarge)
                // Android's PAC proxy connects for other apps, the apps left out included (B5): said once, on its page.
                pacHandlerLine(proxies.pacHandler, view.app.uid)?.let { Text(lineText(it), style = MaterialTheme.typography.bodyMedium) }
                LockFacts(view)
                val day = view.days.getOrNull(view.index)
                if (day != null) {
                    val shown = Date(LocalDate.ofEpochDay(day).atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli())
                    Text(
                        date.format(shown),
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.semantics {
                            heading()
                            liveRegion = LiveRegionMode.Polite
                        },
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (view.index + 1 < view.days.size) {
                            OutlinedButton(onClick = { onDay(view.index + 1) }) { Text(stringResource(R.string.history_earlier)) }
                        }
                        if (view.index > 0) {
                            OutlinedButton(onClick = { onDay(view.index - 1) }) { Text(stringResource(R.string.history_later)) }
                        }
                    }
                }
                when {
                    view.reading -> Text(stringResource(R.string.history_reading), style = MaterialTheme.typography.bodyMedium)
                    view.closed -> Text(stringResource(R.string.history_closed), style = MaterialTheme.typography.bodyMedium)
                    view.day != null && view.day.entries.isEmpty() ->
                        Text(stringResource(R.string.history_empty), style = MaterialTheme.typography.bodyMedium)
                }
                val read = view.day
                if (read != null && read.lookups > 0) {
                    Text(
                        pluralStringResource(R.plurals.history_lookups, read.lookups.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), read.lookups),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (read != null && read.beforeInstall > 0) {
                    Text(
                        pluralStringResource(R.plurals.history_before_install, read.beforeInstall, read.beforeInstall),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                HistoryBlockingLines(
                    context,
                    historyBlocking(blocking, view.app.uid, view.app.packages, read?.entries.orEmpty(), names::name, names::company, view.hideHosts),
                    view.app.packages,
                    blockingActions,
                )
            }
        }
        items(view.day?.entries.orEmpty()) { entry ->
            Card(Modifier.fillMaxWidth().testTag("history-entry")) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        stringResource(R.string.history_time, time.format(Date(entry.start)), time.format(Date(entry.end))),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    val tunnel = if (entry.via == org.visadahyu.datapavan.network.log.LogRecord.VIA_TUNNEL) {
                        tunnelNames[entry.tunnel] ?: stringResource(R.string.tunnel_removed_name)
                    } else {
                        null
                    }
                    val proxy = entry.proxy?.let { proxyFacts(it, entry.ip, entry.port, entry.asn, appGroup, companies) }
                    val bytes = stringResource(R.string.now_destination_bytes, size(context, entry.sent), size(context, entry.received))
                    when (val why = History.leftOut(entry, view.tool)) {
                        // A proxy's flow the engine left out for the switch: its kind, how the network part knows, and
                        // the facts that name nothing (ADR 0052).
                        History.LeftOut.PROXY -> HiddenProxy(
                            proxyRow(checkNotNull(proxy), past = true), bytes, onLogSwitch,
                            marksOf(emptyList(), appGroup, trackers, companies, entry.proxy?.trackers.orEmpty()),
                        )
                        null -> {
                            val hosts = listOf(entry.name, entry.dnsName, entry.address).filter { it.isNotEmpty() }.map { "$it\t${entry.port}" }
                            Place(
                                name = entry.name.ifEmpty { entry.address },
                                dnsName = entry.dnsName,
                                namedBy = entry.namedBy,
                                organisation = "",
                                marks = marksOf(hosts, appGroup, trackers, companies, entry.proxy?.trackers.orEmpty()),
                                bytes = bytes,
                                through = tunnel,
                                proxy = proxy?.let { proxyRow(it, past = true) },
                                onLogSwitch = onLogSwitch,
                            )
                        }
                        // No destination was logged: say why, as "Now" does, never show zeros as one (M3), and never
                        // that it went through the tool where its recorded route says otherwise.
                        else -> {
                            Text(
                                when (why) {
                                    History.LeftOut.TUNNEL -> stringResource(R.string.history_through_tunnel_off, tunnel.orEmpty())
                                    else -> stringResource(leftOutWords(why))
                                },
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Text(bytes, style = MaterialTheme.typography.bodySmall)
                            LogSwitchLink(onLogSwitch)
                        }
                    }
                    entryBlocking(entry, blocking, view.app.uid, names::name, view.hideHosts)?.let { EntryBlockingLines(it) }
                    Text(stringResource(R.string.history_state, stateName(entry.state)), style = MaterialTheme.typography.bodyMedium)
                    if (org.visadahyu.datapavan.network.log.AppState.why(entry.state) != 0) {
                        Text(whyName(org.visadahyu.datapavan.network.log.AppState.why(entry.state)), style = MaterialTheme.typography.bodySmall)
                    }
                    if (entry.continues) Text(stringResource(R.string.history_continues), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/**
 * The words of a segment the switch left out, by why ([History.leftOut]); a tunnel's take its name, and a proxy's
 * are its row's (proxyRow). Only a recorded route through the tool says it went through the tool.
 */
internal fun leftOutWords(why: History.LeftOut): Int = when (why) {
    History.LeftOut.THROUGH_TOOL -> R.string.history_through_tool_off
    History.LeftOut.DIRECT -> R.string.history_direct_off
    History.LeftOut.TUNNEL -> R.string.history_through_tunnel_off
    History.LeftOut.PROXY, History.LeftOut.TOOL_SERVERS, History.LeftOut.NO_ROUTE -> R.string.history_left_out_off
}

/** How long the log keeps its records and how it keeps them shut, as the network screen says it (ADR 0037). */
@Composable
private fun LockFacts(view: HistoryView) {
    if (view.retentionDays == 0) {
        Text(stringResource(R.string.log_not_kept), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.history_keep), style = MaterialTheme.typography.bodyMedium)
        return
    }
    val shut = when {
        view.lock == ConnectionLog.Lock.NO_KEY_YET -> stringResource(R.string.history_nothing_yet)
        view.lock == ConnectionLog.Lock.ANY_TIME -> stringResource(R.string.log_lock_refused)
        // Where the screen lock is set, as Android names the setting (ADR 0054).
        !view.screenLock -> stringResource(R.string.log_no_screen_lock_quoted, quotedLabel("screen_lock"))
        else -> stringResource(R.string.log_locked)
    }
    Text(shut, style = MaterialTheme.typography.bodyMedium)
    if (view.lock != ConnectionLog.Lock.NO_KEY_YET && view.lock != ConnectionLog.Lock.ANY_TIME && !view.screenLock) AndroidLabelsNote("screen_lock")
}
