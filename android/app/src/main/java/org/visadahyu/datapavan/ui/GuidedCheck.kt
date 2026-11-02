package org.visadahyu.datapavan.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.icu.text.MeasureFormat
import android.icu.text.NumberFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.runtime.toMutableStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppFacts
import org.visadahyu.datapavan.audit.CheckActivity
import org.visadahyu.datapavan.audit.CheckReading
import org.visadahyu.datapavan.audit.CheckResult
import org.visadahyu.datapavan.audit.Freshness
import org.visadahyu.datapavan.audit.GuidedCheck
import org.visadahyu.datapavan.audit.NetworkUse
import org.visadahyu.datapavan.audit.NotCompared
import org.visadahyu.datapavan.audit.Traffic
import org.visadahyu.datapavan.audit.UsageReader

private enum class Stage { CHOOSE, PREPARING, AWAY, MEASURING, DONE }

/**
 * The guided check of one activity in an app (ADR 0025): a reading of Android's counts, the app
 * opened, a second reading at least 15 seconds after Datapavan's previous query, and the difference.
 * [carriesOthers] marks VPN, proxy and circumvention apps, [sharedUid] an app counted with others.
 * Results stay in memory while the screen is open; nothing is kept.
 */
@Composable
internal fun GuidedCheckScreen(app: AppFacts, carriesOthers: Boolean, sharedUid: Boolean, insets: PaddingValues, onBack: () -> Unit) {
    val context = LocalContext.current
    val reader = remember { UsageReader(context.applicationContext) }
    val name = app.label ?: app.packageName
    val launch = remember(app.packageName) { context.packageManager.getLaunchIntentForPackage(app.packageName) }
    var activity by rememberSaveable { mutableStateOf(CheckActivity.SCROLL) }
    var stage by rememberSaveable { mutableStateOf(Stage.CHOOSE) }
    var first by rememberSaveable(stateSaver = ReadingSaver) { mutableStateOf<CheckReading?>(null) }
    var left by rememberSaveable { mutableStateOf(false) }
    val runs = rememberSaveable(saver = RunsSaver) { mutableStateListOf<CheckResult>() }
    var seconds by remember { mutableIntStateOf(0) }
    var behind by remember { mutableStateOf(false) }

    // Coming back to Datapavan after leaving for the app starts the second reading.
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && stage == Stage.AWAY) left = true
            if (event == Lifecycle.Event.ON_RESUME && stage == Stage.AWAY && left) stage = Stage.MEASURING
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }

    LaunchedEffect(stage) {
        when (stage) {
            Stage.PREPARING -> {
                waitForFreshCount { seconds = it }
                val reading = withContext(Dispatchers.IO) { reader.readCheck(app.uid, GuidedCheck.period(System.currentTimeMillis())) }
                if (reading == null) {
                    stage = Stage.CHOOSE
                    return@LaunchedEffect
                }
                first = reading
                left = false
                stage = Stage.AWAY
                open(context, launch)
            }
            Stage.MEASURING -> {
                val start = first ?: return@LaunchedEffect
                val period = GuidedCheck.period(start.at)
                var result: CheckResult? = null
                for (attempt in 1..GuidedCheck.READS) {
                    waitForFreshCount { seconds = it }
                    val second = withContext(Dispatchers.IO) { reader.readCheck(app.uid, period) } ?: break
                    result = GuidedCheck.result(activity, start, second, vpnActive(context)) { received ->
                        GuidedCheck.notCompared(app, carriesOthers, sharedUid, received, System.getProperty("os.version"))
                    }
                    if (result.freshness != Freshness.BEHIND) break
                    behind = true
                }
                result?.let(runs::add)
                first = null
                behind = false
                stage = if (result == null) Stage.CHOOSE else Stage.DONE
            }
            else -> Unit
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { TextButton(onClick = onBack) { Text(stringResource(R.string.back)) } }
        item { Text(stringResource(R.string.check_title, isolate(name)), style = MaterialTheme.typography.titleLarge) }
        when (stage) {
            Stage.CHOOSE -> item {
                Column {
                    Text(stringResource(R.string.check_intro), style = MaterialTheme.typography.bodyMedium)
                    SectionTitle(R.string.check_choose)
                    Column(Modifier.selectableGroup()) {
                        CheckActivity.entries.forEach { choice ->
                            Row(
                                Modifier.fillMaxWidth()
                                    .selectable(selected = choice == activity, onClick = { activity = choice }, role = Role.RadioButton)
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = choice == activity, onClick = null)
                                Text(stringResource(activityName(choice)), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 8.dp))
                            }
                        }
                    }
                    if (activity.receiveOnly) Note(stringResource(R.string.check_receive_only_hint))
                    if (launch == null) Note(stringResource(R.string.check_no_launch))
                    Button(onClick = { stage = Stage.PREPARING }, modifier = Modifier.padding(top = 8.dp)) { Text(stringResource(R.string.check_start)) }
                }
            }
            Stage.PREPARING -> item {
                Column {
                    Text(stringResource(R.string.check_preparing, isolate(secondsText(seconds))), style = MaterialTheme.typography.bodyMedium)
                    Note(stringResource(R.string.check_gap_note))
                    TextButton(onClick = { stage = Stage.CHOOSE }) { Text(stringResource(R.string.check_cancel)) }
                }
            }
            Stage.AWAY -> item {
                Column {
                    Text(stringResource(R.string.check_away, isolate(name)), style = MaterialTheme.typography.bodyMedium)
                    if (launch != null) OutlinedButton(onClick = { open(context, launch) }) { Text(stringResource(R.string.check_open, isolate(name))) }
                    TextButton(onClick = { stage = Stage.MEASURING }) { Text(stringResource(R.string.check_back_now)) }
                    TextButton(onClick = { first = null; stage = Stage.CHOOSE }) { Text(stringResource(R.string.check_cancel)) }
                }
            }
            Stage.MEASURING -> item {
                Text(
                    stringResource(if (behind) R.string.check_rereading else R.string.check_measuring, isolate(secondsText(seconds))),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            Stage.DONE -> Unit
        }
        itemsIndexed(runs.reversed()) { index, result -> RunCard(runs.size - index, result) }
        if (runs.isNotEmpty()) {
            item { Note(stringResource(R.string.check_limits)) }
            if (stage == Stage.DONE) {
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { stage = Stage.CHOOSE }) { Text(stringResource(R.string.check_again)) }
                        TextButton(onClick = onBack) { Text(stringResource(R.string.check_done)) }
                    }
                }
            }
        }
    }
}

/** One run's facts: the user's numbers first, then the share and the notes. */
@Composable
private fun RunCard(number: Int, result: CheckResult) {
    val use = result.use
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(
                stringResource(R.string.check_run, number, stringResource(activityName(result.activity))),
                style = MaterialTheme.typography.titleSmall,
            )
            Text(stringResource(R.string.check_duration, isolate(durationText(result.millis))), style = MaterialTheme.typography.bodyMedium)
            if (use.total <= 0) {
                Text(stringResource(R.string.check_nothing), style = MaterialTheme.typography.bodyMedium)
            } else {
                CheckLine(R.string.check_mobile, use.mobile)
                CheckLine(R.string.check_wifi, use.wifi)
                val minutes = result.millis / 60_000.0
                if (minutes >= 1) {
                    Text(
                        stringResource(R.string.check_per_minute, size((use.received / minutes).toLong()), size((use.sent / minutes).toLong())),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                if (use.background > 0) {
                    Text(stringResource(R.string.check_background, size(use.background)), style = MaterialTheme.typography.bodyMedium)
                }
                result.sentShare?.let { share ->
                    Text(stringResource(R.string.check_share, isolate(percent(share))), style = MaterialTheme.typography.bodyMedium)
                    Note(stringResource(R.string.check_share_basis))
                }
                if (result.activity.receiveOnly) result.notCompared?.let { Note(stringResource(notComparedText(it))) }
            }
            freshnessText(result.freshness)?.let { Note(stringResource(it)) }
        }
    }
}

@Composable
private fun CheckLine(@StringRes line: Int, traffic: Traffic) {
    if (traffic.total <= 0) return
    Text(stringResource(line, size(traffic.received), size(traffic.sent)), style = MaterialTheme.typography.bodyMedium)
}

/** Waits until Android will bring its counts up to date on the next query, showing the seconds left. */
private suspend fun waitForFreshCount(onSeconds: (Int) -> Unit) {
    while (true) {
        val wait = GuidedCheck.wait(SystemClock.elapsedRealtime(), UsageReader.lastQuery)
        onSeconds(((wait + 999) / 1000).toInt())
        if (wait <= 0) return
        delay(minOf(wait, 250))
    }
}

private fun open(context: Context, launch: android.content.Intent?) {
    if (launch == null) return
    try {
        context.startActivity(launch)
    } catch (_: ActivityNotFoundException) {
        // Disabled or removed since the audit; the user can open it another way.
    }
}

private fun vpnActive(context: Context): Boolean {
    val cm = context.getSystemService(ConnectivityManager::class.java)
    val network = cm.activeNetwork ?: return false
    return cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
}

private fun secondsText(seconds: Int): String =
    MeasureFormat.getInstance(java.util.Locale.getDefault(), MeasureFormat.FormatWidth.SHORT).format(Measure(seconds, MeasureUnit.SECOND))

private fun durationText(millis: Long): String {
    val total = (millis + 500) / 1000
    val format = MeasureFormat.getInstance(java.util.Locale.getDefault(), MeasureFormat.FormatWidth.SHORT)
    return if (total < 60) {
        format.format(Measure(total, MeasureUnit.SECOND))
    } else {
        format.formatMeasures(Measure(total / 60, MeasureUnit.MINUTE), Measure(total % 60, MeasureUnit.SECOND))
    }
}

private fun percent(share: Double): String = NumberFormat.getPercentInstance().apply { maximumFractionDigits = 1 }.format(share)

@StringRes
private fun activityName(activity: CheckActivity) = when (activity) {
    CheckActivity.WATCH -> R.string.check_activity_watch
    CheckActivity.LISTEN -> R.string.check_activity_listen
    CheckActivity.SCROLL -> R.string.check_activity_scroll
    CheckActivity.MAP -> R.string.check_activity_map
    CheckActivity.DOWNLOAD -> R.string.check_activity_download
    CheckActivity.SEND -> R.string.check_activity_send
    CheckActivity.CALL -> R.string.check_activity_call
    CheckActivity.TYPE -> R.string.check_activity_type
    CheckActivity.OPEN -> R.string.check_activity_open
    CheckActivity.OTHER -> R.string.check_activity_other
}

@StringRes
private fun notComparedText(reason: NotCompared) = when (reason) {
    NotCompared.PROXY_OR_VPN -> R.string.check_nc_proxy
    NotCompared.SHARED_UID -> R.string.check_nc_shared
    NotCompared.SYSTEM_COMPONENT -> R.string.check_nc_system
    NotCompared.LITTLE_RECEIVED -> R.string.check_nc_little
    NotCompared.OLD_KERNEL -> R.string.check_nc_kernel
}

@StringRes
private fun freshnessText(freshness: Freshness) = when (freshness) {
    Freshness.UP_TO_DATE -> null
    Freshness.BEHIND -> R.string.check_behind
    Freshness.FIRST_BEHIND -> R.string.check_first_behind
    Freshness.NOT_CHECKED_VPN -> R.string.check_not_checked_vpn
    Freshness.NOT_CHECKED -> R.string.check_not_checked
}

// Readings and results as lists of numbers, so that they survive the activity being recreated
// while the user is in the other app. They are still never written to storage by Datapavan.

private fun Traffic.longs() = listOf(received, sent, backgroundReceived, backgroundSent)
private fun traffic(v: List<Long>, at: Int) = Traffic(v[at], v[at + 1], v[at + 2], v[at + 3])
private fun NetworkUse.longs() = mobile.longs() + wifi.longs()
private fun use(v: List<Long>, at: Int) = NetworkUse(traffic(v, at), traffic(v, at + 4))

private val ReadingSaver: Saver<CheckReading?, Any> = Saver(
    save = { reading -> reading?.let { arrayListOf(it.at) + it.app.longs() + listOf(it.all, it.live ?: -1L) } ?: arrayListOf<Long>() },
    restore = { saved ->
        @Suppress("UNCHECKED_CAST")
        val v = saved as List<Long>
        if (v.isEmpty()) null else CheckReading(v[0], use(v, 1), v[9], v[10].takeIf { it >= 0 })
    },
)

private val RunsSaver: Saver<SnapshotStateList<CheckResult>, Any> = listSaver(
    save = { runs ->
        runs.map { r ->
            arrayListOf(r.activity.ordinal.toLong(), r.millis) + r.use.longs() +
                listOf(r.freshness.ordinal.toLong(), r.notCompared?.ordinal?.toLong() ?: -1L)
        }
    },
    restore = { saved ->
        saved.map { v ->
            CheckResult(
                CheckActivity.entries[v[0].toInt()], v[1], use(v, 2), Freshness.entries[v[10].toInt()],
                v[11].takeIf { it >= 0 }?.let { NotCompared.entries[it.toInt()] },
            )
        }.toMutableStateList()
    },
)
