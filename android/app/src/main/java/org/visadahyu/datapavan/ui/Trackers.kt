package org.visadahyu.datapavan.ui

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppTrackers
import org.visadahyu.datapavan.audit.TrackerInfo

/** Under the app summary: the scan's progress while it runs, then how many apps contain trackers. */
@Composable
internal fun TrackerScanStatus(progress: Pair<Int, Int>?, trackers: Map<String, AppTrackers>?) {
    val text = when {
        progress != null -> stringResource(R.string.trackers_scanning, progress.first, progress.second)
        trackers != null -> stringResource(R.string.trackers_summary, trackers.values.count { it.embedded.isNotEmpty() })
        else -> return
    }
    Text(text, style = MaterialTheme.typography.bodyMedium)
}

/**
 * The trackers of one app: those whose code it contains, then those it only refers to, and the
 * source of the signatures, which the ODbL requires wherever the data is used (ADR 0015).
 */
@Composable
internal fun TrackerSection(trackers: AppTrackers?, info: Map<Int, TrackerInfo>) {
    Column {
        SectionTitle(R.string.trackers_heading)
        val body = MaterialTheme.typography.bodyMedium
        when {
            trackers == null -> Text(stringResource(R.string.trackers_pending), style = body)
            trackers.unreadable -> Text(stringResource(R.string.trackers_unreadable), style = body)
            trackers.embedded.isEmpty() -> Text(stringResource(R.string.trackers_none), style = body)
            else -> trackers.embedded.forEach { TrackerLine(info[it], it) }
        }
        if (trackers != null && trackers.referencedOnly.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.trackers_referenced_heading), style = MaterialTheme.typography.titleSmall)
            Text(stringResource(R.string.trackers_referenced_note), style = body)
            trackers.referencedOnly.forEach { TrackerLine(info[it], it) }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            stringResource(R.string.trackers_source),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun TrackerLine(tracker: TrackerInfo?, id: Int) {
    val categories = tracker?.categories.orEmpty().mapNotNull { category(it) }.map { stringResource(it) }
    val name = tracker?.name ?: "#$id"
    Text(
        if (categories.isEmpty()) name else stringResource(R.string.tracker_with_categories, name, categories.joinedForUser()),
        style = MaterialTheme.typography.bodyMedium,
    )
}

/** εxodus categories; an unknown one is left out rather than shown untranslated. */
@StringRes
private fun category(name: String): Int? = when (name) {
    "Advertisement" -> R.string.tracker_category_advertisement
    "Analytics" -> R.string.tracker_category_analytics
    "Crash reporting" -> R.string.tracker_category_crash_reporting
    "Identification" -> R.string.tracker_category_identification
    "Location" -> R.string.tracker_category_location
    "Profiling" -> R.string.tracker_category_profiling
    else -> null
}
