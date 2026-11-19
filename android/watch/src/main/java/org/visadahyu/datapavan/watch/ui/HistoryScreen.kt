package org.visadahyu.datapavan.watch.ui

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
import androidx.compose.material3.Text
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
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.time.LocalDate
import java.time.ZoneId
import java.util.Date
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.activity.AppNames
import org.visadahyu.datapavan.watch.activity.History
import org.visadahyu.datapavan.watch.log.ConnectionLog

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
)

/**
 * Each app's history (ADR 0046, decision 2 (d)): its timeline from the connection log, a day at a time, newest
 * first, each segment's time, destination (both names), bytes and state. The log opens only on an unlocked
 * phone (ADR 0037): each of its lock states is said plainly. With retention "none" there is no history, and
 * the screen says how to keep one. Records older than the app now holding the UID belong to an app since
 * removed, and are counted apart.
 */
@Composable
internal fun HistoryScreen(view: HistoryView, trackers: Map<String, List<String>>, onDay: (Int) -> Unit, onClose: () -> Unit) {
    val context = LocalContext.current
    val time = DateFormat.getTimeInstance(DateFormat.SHORT)
    val date = DateFormat.getDateInstance(DateFormat.MEDIUM)
    LazyColumn(
        modifier = Modifier.safeDrawingPadding().testTag("history"),
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onClose) { Text(stringResource(R.string.now_title)) }
                Text(
                    stringResource(R.string.history_title, label(view.app, view.app.uid)),
                    style = MaterialTheme.typography.headlineSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.semantics { heading() },
                )
                Text(stringResource(R.string.history_intro), style = MaterialTheme.typography.bodyLarge)
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
            }
        }
        items(view.day?.entries.orEmpty()) { entry ->
            Card(Modifier.fillMaxWidth().testTag("history-entry")) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        stringResource(R.string.history_time, time.format(Date(entry.start)), time.format(Date(entry.end))),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    val hosts = listOf(entry.name, entry.dnsName, entry.address).filter { it.isNotEmpty() }.map { "$it\t${entry.port}" }
                    Place(
                        name = entry.name.ifEmpty { entry.address },
                        dnsName = entry.dnsName,
                        namedBy = entry.namedBy,
                        organisation = "",
                        trackers = hosts.flatMap { trackers[it].orEmpty() }.distinct(),
                        bytes = stringResource(R.string.now_destination_bytes, size(context, entry.sent), size(context, entry.received)),
                    )
                    Text(stringResource(R.string.history_state, stateName(entry.state)), style = MaterialTheme.typography.bodyMedium)
                    if (org.visadahyu.datapavan.watch.log.AppState.why(entry.state) != 0) {
                        Text(whyName(org.visadahyu.datapavan.watch.log.AppState.why(entry.state)), style = MaterialTheme.typography.bodySmall)
                    }
                    if (entry.continues) Text(stringResource(R.string.history_continues), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/** How long the log keeps its records and how it keeps them shut, as Watch's screen says it (ADR 0037). */
@Composable
private fun LockFacts(view: HistoryView) {
    if (view.retentionDays == 0) {
        Text(stringResource(R.string.log_not_kept), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.history_keep), style = MaterialTheme.typography.bodyMedium)
        return
    }
    val shut = when {
        view.lock == ConnectionLog.Lock.NO_KEY_YET -> R.string.history_nothing_yet
        view.lock == ConnectionLog.Lock.ANY_TIME -> R.string.log_lock_refused
        !view.screenLock -> R.string.log_no_screen_lock
        else -> R.string.log_locked
    }
    Text(stringResource(shut), style = MaterialTheme.typography.bodyMedium)
}
