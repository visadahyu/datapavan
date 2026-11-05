package org.visadahyu.datapavan.ui

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppFacts
import org.visadahyu.datapavan.audit.Dormancy
import org.visadahyu.datapavan.audit.Dormant
import org.visadahyu.datapavan.audit.QuietRole
import org.visadahyu.datapavan.audit.StillHolds
import org.visadahyu.datapavan.audit.Traffic
import org.visadahyu.datapavan.audit.TrafficFacts
import org.visadahyu.datapavan.audit.UsageFacts

/** What usage access gave: still reading, not granted, or the facts (ADR 0022). */
internal sealed interface UsageState {
    data object Reading : UsageState
    data object NoAccess : UsageState
    data class Ready(val facts: UsageFacts) : UsageState
}

/** The overview's part that needs usage access: the request without it, the network and dormant sections with it. */
@Composable
internal fun UsageOverview(usage: UsageState, days: Int, apps: List<AppFacts>, onDays: (Int) -> Unit, onOpen: (String) -> Unit) {
    val context = LocalContext.current
    when (usage) {
        UsageState.Reading -> Unit
        UsageState.NoAccess -> UsageAccessCard()
        is UsageState.Ready -> Column {
            NetworkOverview(usage.facts, days, apps, onDays, onOpen)
            Spacer(Modifier.height(16.dp))
            val dormant = remember(usage.facts, apps) { Dormancy.dormant(apps, usage.facts, context.packageName) }
            DormantSection(dormant, onOpen)
        }
    }
}

/** Says what usage access allows and what Datapavan reads, then opens the system's page for it. */
@Composable
internal fun UsageAccessCard() {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.usage_access_title), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.usage_access_body), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = { openUsageAccess(context) }) { Text(stringResource(R.string.usage_access_button)) }
            if (remember { installedFromFile(context) }) {
                Text(stringResource(R.string.usage_access_restricted), style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = {
                    context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)))
                }) { Text(stringResource(R.string.usage_access_app_info)) }
            }
        }
    }
}

/**
 * Whether Datapavan was installed from a file, for which Android restricts some settings: on the
 * Android 17 emulator the usage access switch was greyed out until "Allow restricted settings" was
 * chosen in the app's info (docs/spikes/2026-10-m4-network-use.md).
 */
private fun installedFromFile(context: Context): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
    val source = try {
        context.packageManager.getInstallSourceInfo(context.packageName).packageSource
    } catch (_: PackageManager.NameNotFoundException) {
        return false
    }
    return source == PackageInstaller.PACKAGE_SOURCE_LOCAL_FILE || source == PackageInstaller.PACKAGE_SOURCE_DOWNLOADED_FILE
}

/** The page for Datapavan itself where the system offers one; otherwise the list of all apps. */
private fun openUsageAccess(context: Context) {
    val own = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.fromParts("package", context.packageName, null))
    try {
        context.startActivity(own)
    } catch (_: ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
    }
}

/** The overview's network section: totals, the apps that used the most, and use under no installed app. */
@Composable
internal fun NetworkOverview(usage: UsageFacts, days: Int, apps: List<AppFacts>, onDays: (Int) -> Unit, onOpen: (String) -> Unit) {
    val byUid = usage.network[days].orEmpty()
    Column {
        SectionTitle(R.string.section_network)
        Text(periodText(usage, days), style = MaterialTheme.typography.bodyMedium)
        Text(
            stringResource(
                R.string.network_totals,
                size(byUid.values.sumOf { it.mobile.total }),
                size(byUid.values.sumOf { it.wifi.total }),
            ),
            style = MaterialTheme.typography.bodyMedium,
        )
        TextButton(onClick = { onDays(if (days == 30) 7 else 30) }) {
            Text(stringResource(if (days == 30) R.string.network_show_7 else R.string.network_show_30))
        }
        // One line per UID, as Android counts it; the system's own UID has its line below.
        val most = apps.groupBy { it.uid }.filterKeys { it !in UsageFacts.OTHER_UIDS }
            .mapNotNull { (uid, members) -> byUid[uid]?.takeIf { it.total > 0 }?.let { members to it } }
            .sortedByDescending { (_, use) -> use.total }.take(TOP_APPS)
        most.forEach { (members, use) ->
            val app = members.first()
            val name = app.label ?: app.packageName
            Text(
                stringResource(
                    R.string.network_app_line,
                    isolate(if (members.size > 1) stringResource(R.string.finding_and_more, name, members.size - 1) else name),
                    size(use.total),
                ),
                style = MaterialTheme.typography.bodyMedium,
                // A row opens the app's page, so it is a full touch target (48 dp), as scripts/a11y-check.py checks.
                modifier = Modifier.fillMaxWidth().clickable { onOpen(app.packageName) }
                    .heightIn(min = 48.dp).wrapContentHeight(Alignment.CenterVertically),
            )
        }
        OTHER.forEach { (uid, label) ->
            byUid[uid]?.takeIf { it.total > 0 }?.let {
                Text(stringResource(label, size(it.total)), style = MaterialTheme.typography.bodyMedium)
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(stringResource(R.string.network_lag), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Apps not opened for 90 days that still hold something (ADR 0022); the remediation plan orders them in M5. */
@Composable
internal fun DormantSection(dormant: List<Dormant>, onOpen: (String) -> Unit) {
    val context = LocalContext.current
    Column {
        SectionTitle(R.string.section_dormant)
        Text(
            pluralStringResource(if (dormant.isEmpty()) R.plurals.dormant_none else R.plurals.dormant_intro, Dormancy.DAYS, Dormancy.DAYS),
            style = MaterialTheme.typography.bodyMedium,
        )
        dormant.forEach { (app, notOpened, holds) ->
            Card(modifier = Modifier.fillMaxWidth().padding(top = 8.dp).clickable { onOpen(app.packageName) }) {
                Column(Modifier.padding(12.dp)) {
                    Text(app.label ?: app.packageName, style = MaterialTheme.typography.titleMedium)
                    Text(
                        pluralStringResource(
                            R.plurals.dormant_line, notOpened.days.toInt(), notOpened.days,
                            holds.sortedBy { it.ordinal }.map { stringResource(holdName(it)) }.joinedForUser(),
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    if (app.worksUnopened) {
                        Text(stringResource(R.string.use_works_unopened), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
        if (dormant.isNotEmpty() && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            TextButton(onClick = { context.startActivity(Intent(Intent.ACTION_MANAGE_UNUSED_APPS)) }) {
                Text(stringResource(R.string.dormant_unused_apps))
            }
        }
    }
}

/**
 * An app page's use section: network use in the period and the last opening, with what Android's
 * counting means for this app, the facts of ADR 0025 and the way into the guided check. [sharedWith]
 * are the other apps of its UID; [proxyNote] is shown on VPN, proxy and circumvention apps.
 */
@Composable
internal fun AppUsageSection(
    app: AppFacts,
    usage: UsageState,
    days: Int,
    sharedWith: List<String>,
    proxyNote: Boolean,
    onDays: (Int) -> Unit,
    onCheck: () -> Unit,
) {
    Column {
        SectionTitle(R.string.section_network)
        when (usage) {
            UsageState.Reading -> Text(stringResource(R.string.usage_reading), style = MaterialTheme.typography.bodyMedium)
            UsageState.NoAccess -> Text(stringResource(R.string.usage_missing), style = MaterialTheme.typography.bodyMedium)
            is UsageState.Ready -> {
                val facts = usage.facts
                val use = facts.network(days, app.uid)
                Text(periodText(facts, days), style = MaterialTheme.typography.bodyMedium)
                if (use == null || use.total == 0L) {
                    Text(stringResource(R.string.network_none), style = MaterialTheme.typography.bodyMedium)
                } else {
                    TrafficLine(R.string.network_mobile, R.string.network_mobile_foreground, use.mobile)
                    TrafficLine(R.string.network_wifi, R.string.network_wifi_foreground, use.wifi)
                }
                TrafficFactLines(app, facts, sharedWith.isNotEmpty())
                TextButton(onClick = { onDays(if (days == 30) 7 else 30) }) {
                    Text(stringResource(if (days == 30) R.string.network_show_7 else R.string.network_show_30))
                }
                TextButton(onClick = onCheck) { Text(stringResource(R.string.check_button)) }
                if (sharedWith.isNotEmpty()) Note(stringResource(R.string.network_shared, sharedWith.map { isolate(it) }.joinedForUser()))
                if (proxyNote) Note(stringResource(R.string.network_proxy))
                Note(stringResource(R.string.network_background_note))
                Spacer(Modifier.height(8.dp))
                val notOpened = Dormancy.notOpened(app, facts)
                val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(notOpened.since))
                Text(
                    if (notOpened.lastUsed != null) {
                        pluralStringResource(R.plurals.use_last, notOpened.days.toInt(), date, notOpened.days)
                    } else {
                        stringResource(R.string.use_none_since, date)
                    },
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (app.worksUnopened) Note(stringResource(R.string.use_works_unopened))
            }
        }
    }
}

/** The facts of ADR 0025 that need no comparison, stated with their limits. */
@Composable
private fun TrafficFactLines(app: AppFacts, facts: UsageFacts, sharedUid: Boolean) {
    TrafficFacts.neverOpened(app, facts, sharedUid)?.let { (installed, use) ->
        val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(installed))
        Text(stringResource(R.string.fact_never_opened, date, size(use.received), size(use.sent)), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 8.dp))
        Note(stringResource(R.string.fact_never_opened_note))
    }
    TrafficFacts.quietRoleSent(app, facts)?.let { sent ->
        val text = when (app.quietRole) {
            QuietRole.KEYBOARD -> R.string.fact_quiet_keyboard
            QuietRole.LIVE_WALLPAPER -> R.string.fact_quiet_wallpaper
            QuietRole.HOME, null -> R.string.fact_quiet_home
        }
        Text(stringResource(text, size(sent)), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 8.dp))
    }
}

@Composable
private fun TrafficLine(@StringRes label: Int, @StringRes foregroundOnly: Int, traffic: Traffic) {
    if (traffic.total == 0L) return
    Text(
        if (traffic.background == 0L) {
            stringResource(foregroundOnly, size(traffic.total), size(traffic.received), size(traffic.sent))
        } else {
            stringResource(label, size(traffic.total), size(traffic.received), size(traffic.sent), size(traffic.background))
        },
        style = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
internal fun Note(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp))
}

@Composable
private fun periodText(usage: UsageFacts, days: Int): String {
    val date = DateFormat.getDateInstance(DateFormat.MEDIUM)
    return pluralStringResource(R.plurals.network_period, days, days, date.format(Date(usage.readAt - days * UsageFacts.DAY)), date.format(Date(usage.readAt)))
}

/** Sizes as Settings' data-usage screen shows them, in the user's language. */
internal fun size(bytes: Long): String = isolate(DataSize.format(bytes))

@StringRes
private fun holdName(hold: StillHolds) = when (hold) {
    StillHolds.SENSITIVE_PERMISSION -> R.string.dormant_sensitive
    StillHolds.SPECIAL_ACCESS -> R.string.dormant_special
    StillHolds.VPN_PERMISSION -> R.string.dormant_vpn
    StillHolds.BACKGROUND_DATA -> R.string.dormant_background
}

private const val TOP_APPS = 10

private val OTHER = listOf(
    UsageFacts.OTHER_UIDS[0] to R.string.network_removed,
    UsageFacts.OTHER_UIDS[1] to R.string.network_tethering,
    UsageFacts.OTHER_UIDS[2] to R.string.network_system,
)
