package org.visadahyu.datapavan.ui

import androidx.activity.compose.BackHandler
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar as MaterialNavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppFacts
import org.visadahyu.datapavan.audit.AppFilter
import org.visadahyu.datapavan.audit.AppQuery
import org.visadahyu.datapavan.audit.AppSort
import org.visadahyu.datapavan.audit.AppTrackers
import org.visadahyu.datapavan.audit.ListedApp
import org.visadahyu.datapavan.audit.Severity
import org.visadahyu.datapavan.audit.TrackerInfo
import org.visadahyu.datapavan.audit.UsageFacts
import org.visadahyu.datapavan.datapack.DataPackRules
import java.time.LocalDate
import java.util.Locale

/** The four destinations of the navigation bar (ADR 0027, point 1). */
enum class Destination(@StringRes val label: Int, @DrawableRes val icon: Int, val tag: String) {
    SUMMARY(R.string.nav_summary, R.drawable.ic_nav_summary, "nav-summary"),
    APPS(R.string.nav_apps, R.drawable.ic_nav_apps, "nav-apps"),
    PHONE(R.string.nav_phone, R.drawable.ic_nav_phone, "nav-phone"),
    NETWORK(R.string.nav_network, R.drawable.ic_nav_network, "nav-network"),
}

@Composable
internal fun NavigationBar(current: Destination, onSelect: (Destination) -> Unit) {
    MaterialNavigationBar {
        Destination.entries.forEach { destination ->
            NavigationBarItem(
                selected = destination == current,
                onClick = { onSelect(destination) },
                icon = { Icon(painterResource(destination.icon), contentDescription = null) },
                label = { Text(stringResource(destination.label)) },
                modifier = Modifier.testTag(destination.tag),
            )
        }
    }
}

/**
 * The destination [tab] with its top bar and its own content. System back returns to the summary,
 * and from there leaves the app.
 */
@Composable
internal fun Destinations(
    tab: Destination,
    audit: AuditResult,
    scanProgress: Pair<Int, Int>?,
    usage: UsageState,
    insets: PaddingValues,
    onTab: (Destination) -> Unit,
    onOpen: (String) -> Unit,
    onReview: () -> Unit,
    onData: () -> Unit,
    onSettings: () -> Unit,
    network: @Composable () -> Unit,
    plan: @Composable () -> Unit,
) {
    BackHandler(enabled = tab != Destination.SUMMARY) { onTab(Destination.SUMMARY) }
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf(AppFilter.WITH_FINDINGS) }
    var sort by rememberSaveable { mutableStateOf(AppSort.URGENCY) }
    val facts = (usage as? UsageState.Ready)?.facts
    val listed = remember(audit) {
        audit.apps.map { (app, findings) -> ListedApp(app, findings, audit.trackers?.get(app.packageName), app.packageName in audit.signatures) }
    }
    val shown = remember(listed, filter, query, sort, facts) { AppQuery.list(listed, filter, query, sort, facts) }
    // Each destination keeps its own place in its list when the user switches (ADR 0027, point 1).
    val scroll = Destination.entries.associateWith { rememberLazyListState() }
    LazyColumn(
        state = scroll.getValue(tab),
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { TopBar(if (tab == Destination.SUMMARY) R.string.app_name else tab.label, onSettings) }
        when (tab) {
            Destination.SUMMARY -> summary(audit, scanProgress, usage, onTab, onReview, onData, plan)
            Destination.APPS -> {
                item {
                    AppsControls(
                        listed, shown.size, facts, audit.trackers, scanProgress, query, filter, sort,
                        onQuery = { query = it }, onFilter = { filter = it }, onSort = { sort = it },
                    )
                }
                items(shown, key = { it.app.packageName }) { item -> AppRow(item.app, item.findings) { onOpen(item.app.packageName) } }
                // Android lists to an app only the apps of its own profile.
                item { Note(stringResource(R.string.other_profiles)) }
            }
            Destination.PHONE -> phone(audit)
            Destination.NETWORK -> item { network() }
        }
    }
}

@Composable
private fun TopBar(@StringRes title: Int, onSettings: () -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 64.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(
            stringResource(title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.weight(1f),
        )
        IconButton(onClick = onSettings, modifier = Modifier.testTag("settings")) {
            Icon(painterResource(R.drawable.ic_settings), contentDescription = stringResource(R.string.settings_title))
        }
    }
}

/** The summary names what to do, never a count of problems (ADR 0026, point 7). */
private fun androidx.compose.foundation.lazy.LazyListScope.summary(
    audit: AuditResult,
    scanProgress: Pair<Int, Int>?,
    usage: UsageState,
    onTab: (Destination) -> Unit,
    onReview: () -> Unit,
    onData: () -> Unit,
    plan: @Composable () -> Unit,
) {
    item { Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyLarge) }
    if (DataPackRules.isStale(audit.dataDate, LocalDate.now())) item { StaleDataCard(audit.dataDate, onData) }
    item { plan() }
    item { StrictReviewEntry(audit.apps.map { it.first }, onStart = onReview) }
    item {
        val phone = if (audit.deviceFindings.any { it.severity != Severity.INFO }) R.string.summary_phone_look else R.string.device_all_clear
        Shortcut(R.string.section_device, stringResource(phone)) { onTab(Destination.PHONE) }
    }
    item {
        val scan = when {
            scanProgress != null -> stringResource(R.string.trackers_scanning, scanProgress.first, scanProgress.second)
            audit.trackers != null -> stringResource(R.string.summary_scan_done)
            else -> stringResource(R.string.audit_loading)
        }
        Shortcut(R.string.section_apps, scan) { onTab(Destination.APPS) }
    }
    item {
        val line = if (usage == UsageState.NoAccess) R.string.summary_network_no_access else R.string.summary_network
        Shortcut(R.string.section_network, stringResource(line)) { onTab(Destination.NETWORK) }
    }
}

@Composable
private fun Shortcut(@StringRes title: Int, line: String, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.titleMedium)
            Text(line, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.phone(audit: AuditResult) {
    if (audit.deviceFindings.isEmpty()) item { Text(stringResource(R.string.device_all_clear), style = MaterialTheme.typography.bodyMedium) }
    items(audit.deviceFindings) { kind ->
        val context = LocalContext.current
        FindingCard(kind, company = null, action = deviceAction(kind)?.let { (label, intent) -> label to { context.startActivity(intent) } })
    }
    item { IntegrityLine(audit.device) }
}

/** The app list's search, filters and order (ADR 0027, point 1); [shown] apps follow below it. */
@Composable
private fun AppsControls(
    listed: List<ListedApp>,
    shown: Int,
    usage: UsageFacts?,
    trackers: Map<String, AppTrackers>?,
    scanProgress: Pair<Int, Int>?,
    query: String,
    filter: AppFilter,
    sort: AppSort,
    onQuery: (String) -> Unit,
    onFilter: (AppFilter) -> Unit,
    onSort: (AppSort) -> Unit,
) {
    var sorting by remember { mutableStateOf(false) }
    val counts = remember(listed, usage) { AppQuery.counts(listed, usage) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = query,
            onValueChange = onQuery,
            label = { Text(stringResource(R.string.apps_search)) },
            leadingIcon = { Icon(painterResource(R.drawable.ic_search), contentDescription = null) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            items(AppFilter.entries) { option ->
                FilterChip(
                    selected = option == filter,
                    onClick = { onFilter(option) },
                    label = { Text(stringResource(R.string.apps_filter_count, stringResource(filterName(option)), counts.getValue(option))) },
                    modifier = Modifier.heightIn(min = 48.dp).testTag("filter-" + option.name.lowercase(Locale.ROOT)),
                )
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                pluralStringResource(R.plurals.apps_shown, listed.size, shown, listed.size),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            Box {
                TextButton(onClick = { sorting = true }) { Text(stringResource(R.string.apps_sort, stringResource(sortName(sort)))) }
                DropdownMenu(expanded = sorting, onDismissRequest = { sorting = false }) {
                    AppSort.entries.forEach { option ->
                        DropdownMenuItem(text = { Text(stringResource(sortName(option))) }, onClick = {
                            onSort(option)
                            sorting = false
                        })
                    }
                }
            }
        }
        TrackerScanStatus(scanProgress, trackers)
        if (shown == 0) Text(stringResource(R.string.apps_none), style = MaterialTheme.typography.bodyMedium)
    }
}

@StringRes
private fun filterName(filter: AppFilter) = when (filter) {
    AppFilter.WITH_FINDINGS -> R.string.filter_with_findings
    AppFilter.TRACKERS -> R.string.filter_trackers
    AppFilter.CONTROL -> R.string.filter_control
    AppFilter.NOT_OPENED -> R.string.filter_not_opened
    AppFilter.PREINSTALLED -> R.string.filter_preinstalled
    AppFilter.VPN_PROXY -> R.string.filter_vpn_proxy
    AppFilter.ALL -> R.string.filter_all
}

@StringRes
private fun sortName(sort: AppSort) = when (sort) {
    AppSort.URGENCY -> R.string.sort_urgency
    AppSort.NAME -> R.string.sort_name
    AppSort.DATA_USE -> R.string.sort_data_use
    AppSort.INSTALLED -> R.string.sort_installed
}

/**
 * The plain-language card at the top of an app's page (ADR 0027, point 2): what the app can reach,
 * the purposes of its trackers, its data in 30 days, and what to do. Facts only, in ADR 0025's words.
 * [onPlan] is there when the plan has a card for the app at some level.
 */
@Composable
internal fun PlainCard(app: AppFacts, trackers: AppTrackers?, trackerInfo: Map<Int, TrackerInfo>, usage: UsageState, onPlan: (() -> Unit)?) {
    val context = LocalContext.current
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer, contentColor = MaterialTheme.colorScheme.onPrimaryContainer),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.plain_title), style = MaterialTheme.typography.titleMedium)
            val reach = app.sensors.sortedBy { it.ordinal }.map { stringResource(sensorName(it)) } +
                app.special.sortedBy { it.ordinal }.map { stringResource(specialName(it)) } +
                listOfNotNull(if (app.vpnAuthorised) stringResource(R.string.dormant_vpn) else null)
            PlainLine(R.string.plain_reach_title, if (reach.isEmpty()) stringResource(R.string.plain_reach_none) else reach.joinedForUser())
            PlainLine(R.string.plain_trackers_title, trackersLine(trackers, trackerInfo))
            PlainLine(R.string.plain_use_title, useLine(app, usage))
            Text(stringResource(R.string.plain_do_title), style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (onPlan != null) OutlinedButton(onClick = onPlan) { Text(stringResource(R.string.plan_open)) }
                OutlinedButton(onClick = { context.startActivity(appSettings(app.packageName)) }) { Text(stringResource(R.string.plain_app_settings)) }
            }
        }
    }
}

@Composable
private fun PlainLine(@StringRes title: Int, value: String) {
    Column {
        Text(stringResource(title), style = MaterialTheme.typography.labelLarge)
        Text(value, style = MaterialTheme.typography.bodyLarge)
    }
}

private val PURPOSES = listOf(
    "Advertisement" to R.string.purpose_advertising,
    "Analytics" to R.string.purpose_analytics,
    "Profiling" to R.string.purpose_profiling,
    "Identification" to R.string.purpose_identification,
    "Location" to R.string.purpose_location,
    "Crash reporting" to R.string.purpose_crash_reports,
)

@Composable
private fun trackersLine(trackers: AppTrackers?, info: Map<Int, TrackerInfo>): String = when {
    trackers == null -> stringResource(R.string.plain_trackers_scanning)
    trackers.unreadable -> stringResource(R.string.plain_trackers_unreadable)
    trackers.embedded.isEmpty() -> stringResource(R.string.plain_trackers_none)
    else -> {
        val categories = trackers.embedded.flatMap { info[it]?.categories.orEmpty() }.toSet()
        val purposes = PURPOSES.filter { (category, _) -> category in categories }.map { (_, name) -> stringResource(name) }
        val count = trackers.embedded.size
        if (purposes.isEmpty()) {
            pluralStringResource(R.plurals.plain_trackers_count, count, count)
        } else {
            pluralStringResource(R.plurals.plain_trackers_some, count, count, purposes.joinedForUser())
        }
    }
}

@Composable
private fun useLine(app: AppFacts, usage: UsageState): String = when (usage) {
    UsageState.Reading -> stringResource(R.string.usage_reading)
    UsageState.NoAccess -> stringResource(R.string.plain_use_no_access)
    is UsageState.Ready -> {
        val use = usage.facts.network(UsageFacts.PERIODS.first(), app.uid)
        if (use == null || use.total == 0L) {
            stringResource(R.string.network_none)
        } else {
            stringResource(R.string.plain_use_line, size(use.received), size(use.sent), size(use.background))
        }
    }
}

/** The privacy summary in the app, from PRIVACY.md. */
@Composable
internal fun privacyParagraphs(): List<String> = listOf(
    stringResource(R.string.privacy_none),
    stringResource(R.string.privacy_no_network),
    stringResource(R.string.privacy_kept),
    stringResource(R.string.privacy_usage),
)

@Composable
internal fun aboutParagraphs(engineVersion: String): List<String> {
    val context = LocalContext.current
    val version = context.packageManager.getPackageInfo(context.packageName, 0).versionName.orEmpty()
    return listOf(
        stringResource(R.string.about_version, isolateLtr(version)),
        stringResource(R.string.engine_version, isolateLtr(engineVersion)),
        stringResource(R.string.about_licence),
        stringResource(R.string.about_source, isolateLtr("github.com/visadahyu/datapavan")),
    )
}
