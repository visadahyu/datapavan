package org.visadahyu.datapavan.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppFacts
import org.visadahyu.datapavan.audit.ReviewStatus
import org.visadahyu.datapavan.audit.ReviewStore
import org.visadahyu.datapavan.audit.Rules
import org.visadahyu.datapavan.audit.Sensor
import org.visadahyu.datapavan.audit.WakeWordAssistants

/** Entry card on the overview: how many apps can use a sensor, and a way into the review. */
@Composable
internal fun StrictReviewEntry(apps: List<AppFacts>, onStart: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.strict_title), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.strict_entry_body, reviewCandidates(apps, includeSystem = false).size), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = onStart) { Text(stringResource(R.string.strict_start)) }
        }
    }
}

/**
 * Strict sensor review. Android does not let one app change another app's permissions, so the
 * review guides the user through every app with microphone, camera or location access and
 * remembers what each app had when it was reviewed.
 */
@Composable
internal fun StrictReview(apps: List<AppFacts>, insets: PaddingValues, onBack: () -> Unit) {
    val context = LocalContext.current
    val store = remember { ReviewStore(context) }
    val reviewed = remember { mutableStateMapOf<String, Set<Sensor>>().apply { putAll(store.all()) } }
    var includeSystem by rememberSaveable { mutableStateOf(false) }
    val candidates = reviewCandidates(apps, includeSystem).sortedWith(
        compareBy<AppFacts> { Rules.reviewStatus(it.sensors, reviewed[it.packageName]) == ReviewStatus.REVIEWED }
            .thenBy { (it.label ?: it.packageName).lowercase() },
    )
    val done = candidates.count { Rules.reviewStatus(it.sensors, reviewed[it.packageName]) == ReviewStatus.REVIEWED }
    val assistants = apps.filter { it.enabled && it.packageName in WakeWordAssistants.known }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.strict_title), style = MaterialTheme.typography.headlineSmall)
            Spacer(Modifier.height(8.dp))
            Text(stringResource(R.string.strict_intro), style = MaterialTheme.typography.bodyMedium)
            privacyDashboard(context)?.let { intent ->
                OutlinedButton(onClick = { context.startActivity(intent) }) { Text(stringResource(R.string.strict_dashboard)) }
            }
        }
        items(assistants, key = { "wake:" + it.packageName }) { assistant -> WakeWordCard(assistant) }
        item {
            Text(stringResource(R.string.strict_progress, done, candidates.size), style = MaterialTheme.typography.titleMedium)
            TextButton(onClick = { includeSystem = !includeSystem }) {
                Text(stringResource(if (includeSystem) R.string.strict_hide_system else R.string.strict_show_system))
            }
        }
        items(candidates, key = { it.packageName }) { app ->
            val status = Rules.reviewStatus(app.sensors, reviewed[app.packageName])
            ReviewRow(
                app = app,
                status = status,
                onOpen = { context.startActivity(appDetails(app.packageName)) },
                onToggle = {
                    if (status == ReviewStatus.REVIEWED) {
                        store.clear(app.packageName)
                        reviewed.remove(app.packageName)
                    } else {
                        store.markReviewed(app.packageName, app.sensors)
                        reviewed[app.packageName] = app.sensors
                    }
                },
            )
        }
    }
}

@Composable
private fun ReviewRow(app: AppFacts, status: ReviewStatus, onOpen: () -> Unit, onToggle: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(app.label ?: app.packageName, style = MaterialTheme.typography.titleMedium)
            Text(
                app.sensors.sortedBy { it.ordinal }.map { stringResource(sensorName(it)) }.joinToString(" · "),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(
                    when (status) {
                        ReviewStatus.NOT_REVIEWED -> R.string.strict_status_not_reviewed
                        ReviewStatus.REVIEWED -> R.string.strict_status_reviewed
                        ReviewStatus.CHANGED -> R.string.strict_status_changed
                    },
                ),
                style = MaterialTheme.typography.labelMedium,
                color = if (status == ReviewStatus.CHANGED) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row {
                TextButton(onClick = onOpen) { Text(stringResource(R.string.strict_open_permissions)) }
                TextButton(onClick = onToggle) {
                    Text(stringResource(if (status == ReviewStatus.REVIEWED) R.string.strict_undo else R.string.strict_mark_reviewed))
                }
            }
        }
    }
}

@Composable
private fun WakeWordCard(assistant: AppFacts) {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.wake_title, assistant.label ?: assistant.packageName), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.wake_body), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = { context.startActivity(wakeWordSettings(context, assistant.packageName)) }) {
                Text(stringResource(R.string.wake_open))
            }
        }
    }
}

/** Non-system apps with sensor access; system apps on request, since many of theirs are fixed. */
private fun reviewCandidates(apps: List<AppFacts>, includeSystem: Boolean) =
    apps.filter { it.sensors.isNotEmpty() && (includeSystem || !it.isSystem) }

private fun sensorName(sensor: Sensor) = when (sensor) {
    Sensor.MICROPHONE -> R.string.sensor_microphone
    Sensor.CAMERA -> R.string.sensor_camera
    Sensor.LOCATION -> R.string.sensor_location
}

private fun appDetails(packageName: String) =
    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))

/** The assistant's own wake-word screen when it exists, otherwise its app page. */
private fun wakeWordSettings(context: Context, packageName: String): Intent {
    val action = WakeWordAssistants.known[packageName] ?: return appDetails(packageName)
    val intent = Intent(action).setPackage(packageName)
    return if (intent.resolveActivity(context.packageManager) != null) intent else appDetails(packageName)
}

/** Android 12+ shows each app's recent microphone, camera and location use under Privacy. */
private fun privacyDashboard(context: Context): Intent? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return null
    val intent = Intent(Settings.ACTION_PRIVACY_SETTINGS)
    return intent.takeIf { it.resolveActivity(context.packageManager) != null }
}
