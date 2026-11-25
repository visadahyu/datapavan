package org.visadahyu.datapavan.network.ui

import android.content.Context
import android.text.format.Formatter
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.AppNames
import org.visadahyu.datapavan.network.activity.Companies
import org.visadahyu.datapavan.network.activity.NowRows
import org.visadahyu.datapavan.network.activity.ProxyFacts
import org.visadahyu.datapavan.network.activity.Snapshot
import org.visadahyu.datapavan.network.activity.TrackerMarks
import org.visadahyu.datapavan.network.log.AppState
import org.visadahyu.datapavan.network.proxy.AndroidProxy
import org.visadahyu.datapavan.network.proxy.ProxyContext

/** A tunnel's configuration by its name, or a plain phrase for one since removed (W7, part 2). */
@Composable
internal fun tunnelName(view: NowView, tunnel: Long): String = view.tunnelNames[tunnel] ?: stringResource(R.string.tunnel_removed_name)

/**
 * What "Now" draws: the engine's snapshot, whether the tunnel runs, the apps' names and company groups, the
 * trackers' matches by host and the companies to tell them by, the one app asked for, the window, and the
 * rows' order, kept by the activity across an app's history and a rotation ([sorts] changes when it sorts).
 */
internal data class NowView(
    val snapshot: Snapshot?,
    val running: Boolean,
    val names: Map<Int?, AppNames.Named>,
    val groups: Map<Int?, String?>,
    val trackers: Map<String, List<TrackerMarks.Match>>,
    val companies: Companies?,
    val only: String?,
    val window: Int,
    val order: NowRows.Order,
    val sorts: Int,
    /** The WireGuard configurations' names by the engine's tunnel numbers, or a phrase for one since removed (W7). */
    val tunnelNames: Map<Long, String> = emptyMap(),
    /** Tracker blocking (W8, part 3a; ADR 0053): what was counted, what the user allowed, and the pause. */
    val blocking: BlockingView = BlockingView(),
    /** The user stopped the counts' updates (the accessibility unit, WCAG 2.2.2). */
    val paused: Boolean = false,
    /**
     * What the service knows of the proxies around the apps (the proxy record's unit B): Android's own settings, the PAC
     * proxy's UID and the circumvention tools' UIDs.
     */
    val proxies: ProxyContext.State = ProxyContext.State(),
    /** The user's choice for one app, "Log where APP connects through a proxy" (the proxy record's unit C, R3). */
    val choices: ProxyChoices = ProxyChoices(),
)

/** The marks of a destination of the app [uid], from its hosts' matches (ADR 0046, decision 2 (d)). */
internal fun marksOf(
    hosts: List<String>,
    appGroup: String?,
    trackers: Map<String, List<TrackerMarks.Match>>,
    companies: Companies?,
    /** The trackers the engine matched on a proxied flow's names before it left them out (ADR 0052), by id. */
    kept: List<Int> = emptyList(),
): List<TrackerMarks.Mark> {
    val matched = hosts.flatMap { trackers[it].orEmpty() }.distinct()
    val engine = org.visadahyu.datapavan.network.NowActivity.trackersOf(kept).filter { e -> matched.none { it.id == e.id } }
    return TrackerMarks.marks(
        matched + engine,
        appGroup,
        { match -> companies?.groupOfWebsite(match.website) },
        { group -> companies?.name(group) ?: group },
    )
}

/** A size as the user reads it, absolute, with its unit, isolated in right-to-left text. */
internal fun size(context: Context, bytes: Long): String = isolate(Formatter.formatFileSize(context, bytes))

/** How long the screen was off, in hours and minutes. */
@Composable
internal fun duration(millis: Long): String {
    val minutes = millis / 60_000
    return when {
        minutes >= 60 -> stringResource(R.string.now_duration_hours, (minutes / 60).toInt(), (minutes % 60).toInt())
        minutes >= 1 -> stringResource(R.string.now_duration_minutes, minutes.toInt())
        else -> stringResource(R.string.now_duration_short)
    }
}

/** An app's name: its label, or what stands for one where no package holds its UID or Android named none. */
@Composable
internal fun label(named: AppNames.Named?, uid: Int?): String = when ((named ?: AppNames.Named(uid, null, emptyList(), null)).kind) {
    AppNames.Kind.UNNAMED -> stringResource(R.string.now_app_unnamed)
    AppNames.Kind.SYSTEM -> stringResource(R.string.now_app_system)
    AppNames.Kind.REMOVED -> stringResource(R.string.now_app_removed)
    AppNames.Kind.NAMED -> isolate(named?.label.orEmpty())
}

/** A state's words, by its [AppState] code; why where there is none is said apart. */
@Composable
internal fun stateName(code: Int): String = stringResource(
    when (AppState.of(code)) {
        AppState.IN_USE -> R.string.now_state_in_use
        AppState.NOTIFICATION -> R.string.now_state_notification
        AppState.BACKGROUND -> R.string.now_state_background
        AppState.NOT_YET -> R.string.now_state_not_yet
        else -> R.string.now_state_none
    },
)

/** Why bytes have no state, by its [AppState] code. */
@Composable
internal fun whyName(code: Int): String = stringResource(
    when (code) {
        AppState.NO_ACCESS -> R.string.now_why_no_access
        AppState.LOCKED -> R.string.now_why_locked
        AppState.LATE -> R.string.now_why_late
        AppState.NO_APP -> R.string.now_why_no_app
        else -> R.string.now_why_not_told
    },
)

/**
 * "Now" (ADR 0046, decision 2 (d)): one row per app that used the network in the chosen window, with its state
 * now, its bytes by state, why some have none, and its destinations as W3 names them; apps in the background
 * first. Rows keep their order while the view is open ([NowRows.Order]). At the end, what this view cannot
 * see (decision 5). A tap on an app opens its history. Each app is named only here, inside the app. A row the
 * switch "Log where apps connect ..." leaves out links to it ([onLogSwitch], LogSwitch). An app tracker blocking
 * covers, or that it blocked, says what was blocked and offers the one-tap undo ([blockingActions]; W8, part 3a).
 */
@Composable
internal fun NowScreen(
    view: NowView,
    history: HistoryView?,
    onWindow: (Int) -> Unit,
    onSort: () -> Unit,
    onAll: () -> Unit,
    onHistory: (Int?, Boolean) -> Unit,
    onDay: (Int) -> Unit,
    onCloseHistory: () -> Unit,
    onAllowAccess: () -> Unit,
    onLogSwitch: () -> Unit = {},
    blockingActions: BlockingActions = BlockingActions(),
    onPause: () -> Unit = {},
    proxyActions: ProxyChoiceActions = ProxyChoiceActions(),
) {
    // Kept here, above the history, so that coming back from it, or a rotation, finds the list where it was
    // (review c1 of W5's third part, screens, M2).
    val listState = rememberLazyListState()
    // The app whose choice "Log where APP connects through a proxy" asks for its confirmation (unit C), kept across a
    // rotation: an SDK Runtime UID's row asks for its app.
    var asking by rememberSaveable { mutableStateOf<Int?>(null) }
    val onChoice = { uid: Int?, choice: Choice ->
        if (uid != null) {
            val app = org.visadahyu.datapavan.network.proxy.ProxyChoice.appOf(uid)
            when (choice) {
                Choice.LOG -> asking = app
                Choice.STOP -> proxyActions.onStop(app)
            }
        }
    }
    // Stable names for the emulator scripts (scripts/talkback-walk.sh, scripts/screenshots.sh --now), as the audit's
    // screens give them.
    Surface(modifier = Modifier.fillMaxSize().semantics { testTagsAsResourceId = true }, color = MaterialTheme.colorScheme.background) {
        if (history != null) {
            BackHandler(onBack = onCloseHistory)
            HistoryScreen(
                history, view.groups[history.app.uid], view.trackers, view.companies, onDay, onCloseHistory, view.tunnelNames, onLogSwitch,
                view.blocking, blockingActions, view.proxies, view.choices, onChoice,
            )
        } else {
            NowList(view, listState, onWindow, onSort, onAll, onHistory, onAllowAccess, onLogSwitch, blockingActions, onPause, onChoice)
        }
    }
    asking?.let { app ->
        val named = view.names[app] ?: history?.app?.takeIf { it.uid == app }
        AppProxyChoiceDialog(
            name = label(named, app),
            packages = named?.packages.orEmpty(),
            sdkRuntime = view.choices.sdkRuntime,
            onYes = {
                asking = null
                proxyActions.onLog(app, named?.packages.orEmpty())
            },
            onNo = { asking = null },
        )
    }
}

@Composable
private fun NowList(
    view: NowView,
    listState: LazyListState,
    onWindow: (Int) -> Unit,
    onSort: () -> Unit,
    onAll: () -> Unit,
    onHistory: (Int?, Boolean) -> Unit,
    onAllowAccess: () -> Unit,
    onLogSwitch: () -> Unit,
    blockingActions: BlockingActions,
    onPause: () -> Unit,
    onChoice: (Int?, Choice) -> Unit,
) {
    val context = LocalContext.current
    val window = view.window
    val snapshot = view.snapshot
    val labels = { uid: Int? -> view.names[uid]?.label ?: "" }
    val apps = snapshot?.apps.orEmpty().filter { app ->
        view.only == null || view.names[app.uid]?.packages?.contains(view.only) == true
    }
    // Read once per recomposition; [NowView.sorts] makes a sort asked for take effect now.
    val keys = remember(snapshot, window, view.sorts, view.only, view.names.size) { view.order.of(apps, window, labels) }
    val byUid = apps.associateBy { it.uid }
    LazyColumn(
        state = listState,
        modifier = Modifier.safeDrawingPadding().testTag("now"),
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(R.string.now_title),
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.semantics { heading() },
                )
                Text(stringResource(R.string.now_intro), style = MaterialTheme.typography.bodyLarge)
                Facts(view, snapshot, onAllowAccess)
                // The counts change every second; the user can stop them, and start them again (WCAG 2.2.2).
                OutlinedButton(onClick = onPause, modifier = Modifier.testTag("now-pause")) {
                    Text(stringResource(if (view.paused) R.string.now_resume else R.string.now_pause))
                }
                // Said once by a screen reader when it appears, so that pausing is confirmed; shown only while the
                // VPN runs, since Datapavan counts nothing while it is off.
                if (view.paused && view.running) {
                    Text(
                        stringResource(R.string.now_paused),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                    )
                }
                if (view.only != null) {
                    Text(stringResource(R.string.now_one_app), style = MaterialTheme.typography.bodyMedium)
                    OutlinedButton(onClick = onAll) { Text(stringResource(R.string.now_all_apps)) }
                }
                WindowChoice(window, onWindow)
                Text(stringResource(R.string.now_sort_note), style = MaterialTheme.typography.bodySmall)
                OutlinedButton(onClick = onSort) { Text(stringResource(R.string.now_sort)) }
                if (keys.none { byUid[it]?.let { app -> NowRows.hasTraffic(app, window) } == true }) {
                    Text(stringResource(R.string.now_empty), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
        items(keys, key = { it ?: Int.MIN_VALUE }) { uid ->
            val app = byUid[uid]
            if (app != null) AppRow(context, app, window, view, onHistory, onLogSwitch, blockingActions, onChoice)
        }
        item { CannotSee() }
    }
}

/** What the latest reading knew, the tunnel's state, and the window while the screen was off. */
@Composable
private fun Facts(view: NowView, snapshot: Snapshot?, onAllowAccess: () -> Unit) {
    val context = LocalContext.current
    if (!view.running) {
        Text(stringResource(R.string.now_network_off), style = MaterialTheme.typography.bodyMedium)
    }
    // The global pause, which names no app (W8, part 3a); its end and the tap that ends it are on the network screen.
    val paused = view.blocking.pausedUntil
    if (view.running && view.blocking.on && paused != null) {
        Text(stringResource(R.string.blocking_paused_now, whenText(context, paused)), style = MaterialTheme.typography.bodyMedium)
    }
    // Android's own proxy setting, while the tunnel runs (the proxy record's unit B, B7): a proxy set for the whole phone
    // over adb or by a device owner shows in none of Android's own Wi-Fi screens, and this is where the user sees it.
    if (view.running) {
        androidProxyLine(view.proxies.android)?.let {
            Text(lineText(it), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("now-android-proxy"))
        }
    }
    when (snapshot?.known) {
        Snapshot.NO_ACCESS -> {
            Text(stringResource(R.string.now_no_access), style = MaterialTheme.typography.bodyMedium)
            // Datapavan's name for the access stays; the phone's own name for its page follows, where the button sends
            // the user (the maintainer, 2026-11-22; ADR 0054).
            Text(stringResource(R.string.now_access_phone_name, quotedLabel("usage_access")), style = MaterialTheme.typography.bodyMedium)
            AndroidLabelsNote("usage_access")
            OutlinedButton(onClick = onAllowAccess) { Text(stringResource(R.string.now_allow_access)) }
        }
        Snapshot.LOCKED -> Text(stringResource(R.string.now_locked), style = MaterialTheme.typography.bodyMedium)
        Snapshot.NOTHING_YET -> if (view.running) {
            Text(stringResource(R.string.now_reading), style = MaterialTheme.typography.bodyMedium)
        }
        else -> Unit
    }
    // The window while the screen was off, once it came on again: the apps that sent in the background then.
    val off = snapshot?.let(NowRows::offLine)
    if (snapshot != null && off != null) {
        val (senders, sent) = off
        val length = duration(snapshot.offUntil - snapshot.offFrom)
        Text(
            if (senders == 0) {
                stringResource(R.string.now_off_none, length)
            } else {
                stringResource(
                    R.string.now_off_window,
                    length,
                    pluralStringResource(R.plurals.now_off_apps, senders, senders),
                    size(context, sent),
                )
            },
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.testTag("now-off"),
        )
    }
}

/** The three windows, as radio rows: the row is the control. */
@Composable
private fun WindowChoice(window: Int, onWindow: (Int) -> Unit) {
    Text(stringResource(R.string.now_window), style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() })
    Column(Modifier.selectableGroup()) {
        for ((value, text) in listOf(
            Snapshot.TEN_MINUTES to R.string.now_window_ten,
            Snapshot.HOUR to R.string.now_window_hour,
            Snapshot.SINCE_SCREEN_ON to R.string.now_window_screen,
        )) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .selectable(selected = value == window, role = Role.RadioButton) { onWindow(value) },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = value == window, onClick = null)
                Text(stringResource(text), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
            }
        }
    }
}

/** One app: its name and packages, its state now, its bytes by state, why some have none, and its destinations. */
@Composable
private fun AppRow(
    context: Context,
    app: Snapshot.App,
    window: Int,
    view: NowView,
    onHistory: (Int?, Boolean) -> Unit,
    onLogSwitch: () -> Unit,
    blockingActions: BlockingActions,
    onChoice: (Int?, Choice) -> Unit,
) {
    val named = view.names[app.uid]
    val historyLabel = stringResource(R.string.now_history)
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClickLabel = historyLabel) { onHistory(app.uid, app.isTool) }
            .testTag("now-app"),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label(named, app.uid), style = MaterialTheme.typography.titleMedium)
            when {
                named == null || named.packages.isEmpty() -> Unit
                named.packages.size == 1 -> Text(isolateLtr(named.packages[0]), style = MaterialTheme.typography.bodySmall)
                else -> Text(
                    stringResource(R.string.now_app_together, named.packages.joinToString(", ") { isolateLtr(it) }),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Text(stringResource(R.string.now_state_now, stateName(app.now)), style = MaterialTheme.typography.bodyMedium)
            if (AppState.why(app.now) != 0) Text(whyName(AppState.why(app.now)), style = MaterialTheme.typography.bodyMedium)
            pacHandlerLine(view.proxies.pacHandler, app.uid)?.let { Text(lineText(it), style = MaterialTheme.typography.bodyMedium) }
            // The user's choice for this app's proxy (unit C): ended here, or without the user in this run.
            val choiceApp = app.uid?.let(org.visadahyu.datapavan.network.proxy.ProxyChoice::appOf)
            AppChoiceLines(appChoiceLines(app.uid, view.names[choiceApp]?.packages ?: named?.packages.orEmpty(), view.choices))
            if (app.isTool) {
                Text(stringResource(R.string.now_is_tool), style = MaterialTheme.typography.bodyMedium)
                // Its servers show only while the switch "Log where apps connect ..." is on (decision 3, 2026-11-19).
                if (app.serversHidden) Text(stringResource(R.string.now_tool_servers_off), style = MaterialTheme.typography.bodyMedium)
            }
            for ((column, text) in listOf(
                AppState.BACKGROUND to R.string.now_bytes_background,
                AppState.NOTIFICATION to R.string.now_bytes_notification,
                AppState.IN_USE to R.string.now_bytes_in_use,
            )) {
                if (NowRows.traffic(app, window, column) > 0) {
                    Text(
                        stringResource(text, size(context, NowRows.sent(app, window, column)), size(context, NowRows.received(app, window, column))),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
            for (reason in NowRows.reasons(app, window)) {
                Text(
                    stringResource(R.string.now_bytes_none, size(context, reason.sent), size(context, reason.received), whyName(reason.why)),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (NowRows.traffic(app, window, AppState.NOT_YET) > 0) {
                Text(
                    stringResource(
                        R.string.now_bytes_not_yet,
                        size(context, NowRows.sent(app, window, AppState.NOT_YET)),
                        size(context, NowRows.received(app, window, AppState.NOT_YET)),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (app.throughTool) Text(stringResource(R.string.now_through_tool_off), style = MaterialTheme.typography.bodyMedium)
            if (app.throughTunnel != 0L) {
                Text(stringResource(R.string.now_through_tunnel_off, tunnelName(view, app.throughTunnel)), style = MaterialTheme.typography.bodyMedium)
            }
            if (LogSwitch.hides(app)) LogSwitchLink(onLogSwitch)
            // Tracker blocking (W8, part 3a): what it blocked in this app, and the one-tap undo. With the switch above off,
            // a chained or tunnelled app's rows are never named by their hosts.
            val names = RowNames(view.blocking.facts, view.companies, view.trackers)
            val packages = named?.packages.orEmpty()
            appBlocking(view.blocking, app.uid, packages, { names.name(it, LogSwitch.hides(app)) }, names::company, LogSwitch.hides(app))
                ?.let { AppBlockingLines(context, it, packages, blockingActions) }
            Destinations(context, app, window, view, onLogSwitch, onChoice)
        }
    }
}

/** An app's destinations with bytes in the window, most bytes first, the first few and then all on request. */
@Composable
private fun Destinations(context: Context, app: Snapshot.App, window: Int, view: NowView, onLogSwitch: () -> Unit, onChoice: (Int?, Choice) -> Unit) {
    val places = app.destinations
        .filter { it.bytes[window * 2] + it.bytes[window * 2 + 1] > 0 }
        .sortedByDescending { it.bytes[window * 2] + it.bytes[window * 2 + 1] }
    var all by rememberSaveable(app.uid) { mutableStateOf(false) }
    val shown = if (all) places else places.take(FIRST_PLACES)
    for (place in shown) {
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        val bytes = stringResource(R.string.now_destination_bytes, size(context, place.bytes[window * 2]), size(context, place.bytes[window * 2 + 1]))
        val proxy = placeProxyFacts(place, view.groups[app.uid], view.companies)
        // A circumvention tool's own flows say so on their proxy rows (B6).
        val toolName = app.uid?.let { view.proxies.tools[it] }
        // What the user's choice for this app can do on this row (unit C): the engine's "local" fact and Android's
        // setting, from the snapshot.
        val choice = view.choices.row(app.uid, place.proxy?.setting == true, place.proxy?.local, tcp = place.protocol == 6)
        val choose = { it: Choice -> onChoice(app.uid, it) }
        if (proxy != null && !proxy.kept) {
            // A proxy's flow the engine left out for the switch: its kind, how the network part knows, and the facts
            // that name nothing (ADR 0052), with the link to the switch.
            val marks = marksOf(emptyList(), view.groups[app.uid], view.trackers, view.companies, place.proxy?.trackers.orEmpty())
            HiddenProxy(proxyRow(proxy, past = false, toolName, choice), bytes, onLogSwitch, marks, choose)
            continue
        }
        val (name, dns) = NowRows.destination(place.name, place.dnsName, place.address.hostAddress.orEmpty())
        Place(
            name = name,
            dnsName = dns,
            namedBy = place.namedBy,
            // A proxied destination's organisation is the proxy's network's, which its lines say; a plain request's
            // server is shown as any destination is.
            organisation = if (proxy == null || proxy.kind == ProxyFacts.Kind.REQUEST) place.organisation else "",
            marks = marksOf(
                org.visadahyu.datapavan.network.NowActivity.hostsOf(place), view.groups[app.uid], view.trackers, view.companies,
                place.proxy?.trackers.orEmpty(),
            ),
            bytes = bytes,
            through = if (place.via == org.visadahyu.datapavan.network.log.LogRecord.VIA_TUNNEL) tunnelName(view, place.tunnel) else null,
            proxy = proxy?.let { proxyRow(it, past = false, toolName, choice) },
            onLogSwitch = onLogSwitch,
            onChoice = choose,
        )
    }
    if (!all && places.size > FIRST_PLACES) {
        val more = places.size - FIRST_PLACES
        TextButton(onClick = { all = true }) { Text(pluralStringResource(R.plurals.now_more_destinations, more, more)) }
    }
}

/** One destination: its name, left to right in any language, where the name came from, and what else is known. */
@Composable
internal fun Place(
    name: String,
    dnsName: String,
    namedBy: Int,
    organisation: String,
    marks: List<TrackerMarks.Mark>,
    bytes: String,
    /** The WireGuard configuration it went through, by its name, if one (W7, part 2). */
    through: String? = null,
    /** What the row says of the proxy it went through, if one (ADR 0052). */
    proxy: ProxyRow? = null,
    /** Opens the network screen at the switch, for a row that the switch leaves something out of. */
    onLogSwitch: () -> Unit = {},
    /** The row's link to the user's choice for its app (unit C), if [proxy] has one. */
    onChoice: (Choice) -> Unit = {},
) {
    Text(isolateLtr(name), style = MaterialTheme.typography.bodyLarge)
    through?.let { Text(stringResource(R.string.now_destination_tunnel, it), style = MaterialTheme.typography.bodySmall) }
    proxy?.let { ProxyLines(it.lines) }
    Text(
        stringResource(
            when (NowRows.namedBy(namedBy)) {
                NowRows.NamedBy.TLS -> R.string.now_named_tls
                NowRows.NamedBy.QUIC -> R.string.now_named_quic
                NowRows.NamedBy.DNS -> R.string.now_named_dns
                NowRows.NamedBy.ORGANISATION -> R.string.now_named_organisation
                NowRows.NamedBy.PROXY -> R.string.now_named_proxy
                NowRows.NamedBy.UNKNOWN -> R.string.now_named_unknown
            },
        ),
        style = MaterialTheme.typography.bodySmall,
    )
    if (dnsName.isNotEmpty()) Text(stringResource(R.string.now_dns_name, isolateLtr(dnsName)), style = MaterialTheme.typography.bodySmall)
    if (organisation.isNotEmpty()) Text(stringResource(R.string.now_organisation, isolate(organisation)), style = MaterialTheme.typography.bodySmall)
    MarkLines(marks)
    Text(bytes, style = MaterialTheme.typography.bodySmall)
    // Last, after the line of where the name came from, which the emulator checks read a place's name before.
    if (proxy?.toSwitch == true) LogSwitchLink(onLogSwitch)
    proxy?.toChoice?.let { choice -> ChoiceLink(choice) { onChoice(choice) } }
}

/** A destination's tracker marks, one line each. */
@Composable
private fun MarkLines(marks: List<TrackerMarks.Mark>) {
    for (mark in marks) {
        val line = when (mark) {
            is TrackerMarks.Mark.Tracker -> stringResource(R.string.now_tracker, isolate(mark.name))
            is TrackerMarks.Mark.Company -> stringResource(R.string.now_tracker_company, isolate(mark.name))
            is TrackerMarks.Mark.SameCompany -> stringResource(R.string.now_same_company, isolate(mark.name))
        }
        Text(line, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * A proxy's flow left out for the switch: its kind, how the network part knows and the facts that name nothing, the
 * trackers' marks the engine kept of it (a tracker's company, never an address or a name), then the link, and the link
 * to the user's choice for its app where the row has one (unit C).
 */
@Composable
internal fun HiddenProxy(
    row: ProxyRow,
    bytes: String,
    onLogSwitch: () -> Unit,
    marks: List<TrackerMarks.Mark> = emptyList(),
    onChoice: (Choice) -> Unit = {},
) {
    row.header?.let { Text(lineText(it), style = MaterialTheme.typography.bodyMedium) }
    ProxyLines(row.lines)
    MarkLines(marks)
    Text(bytes, style = MaterialTheme.typography.bodySmall)
    if (row.toSwitch) LogSwitchLink(onLogSwitch)
    row.toChoice?.let { choice -> ChoiceLink(choice) { onChoice(choice) } }
}

/**
 * The facts of a destination's proxy (ADR 0052), for the app of company group [appGroup], with the owners' tables
 * [companies] where the pack holds them, and in "Now" the engine's mark of a first hop shown there only ([shownOnly]).
 */
internal fun proxyFacts(
    proxy: org.visadahyu.datapavan.network.log.LogRecord.Proxy,
    address: java.net.InetAddress,
    port: Int,
    asn: Long,
    appGroup: String?,
    companies: Companies?,
    shownOnly: Boolean = false,
): ProxyFacts.Facts = ProxyFacts.of(
    proxy, address, port, asn,
    appMaker = appGroup?.let { companies?.name(it) ?: it },
    networkGroup = { companies?.groupOfAsn(it) },
    coverGroup = { companies?.groupOfHost(it) },
    groupName = { companies?.name(it) ?: it },
    shownOnly = shownOnly,
)

/**
 * The facts of a place's proxy in "Now", if it went through one, with the engine's mark of a first hop shown there
 * only, as a pure function the JVM tests hold from the snapshot's destination to its row.
 */
internal fun placeProxyFacts(place: Snapshot.Destination, appGroup: String?, companies: Companies?): ProxyFacts.Facts? =
    place.proxy?.let { proxyFacts(it, place.address, place.port, place.asn, appGroup, companies, place.shownOnly) }

/** A proxy's kind, as the sentences set it in. */
internal fun proxyKind(kind: ProxyFacts.Kind): Int = when (kind) {
    ProxyFacts.Kind.SOCKS5 -> R.string.proxy_kind_socks5
    ProxyFacts.Kind.SOCKS4 -> R.string.proxy_kind_socks4
    // A plain request is never called a proxy: its rows do not set its kind in (proxyRow). The one exception is a plain
    // request to Android's setting, which is called by that setting's name, since Android names it so: left out for the
    // switch, its headers are the setting's, with "HTTP proxy" set in (the proxy record's unit B, R7; ADR 0052).
    ProxyFacts.Kind.HTTP, ProxyFacts.Kind.REQUEST -> R.string.proxy_kind_http
    ProxyFacts.Kind.MTPROTO -> R.string.proxy_kind_mtproto
    ProxyFacts.Kind.WHATSAPP -> R.string.proxy_kind_whatsapp
    ProxyFacts.Kind.SIGNAL -> R.string.proxy_kind_signal
}

/**
 * One line of a proxy's row: its string, the proxy's [kind] set in first where the string takes it, and the other
 * arguments, names and addresses already isolated as the screens set them.
 */
internal data class ProxyLine(val text: Int, val kind: ProxyFacts.Kind? = null, val args: List<String> = emptyList())

/**
 * What a destination's row says of its proxy (ADR 0052; fix round of W8 part 2a, screens review M3): the [header]
 * that stands for the destination where the engine left the flow out for the switch, the [lines], whether the
 * row links to the switch ([toSwitch]), and the link to the user's choice for its app, if any ([toChoice]; unit C).
 */
internal data class ProxyRow(val header: ProxyLine?, val lines: List<ProxyLine>, val toSwitch: Boolean, val toChoice: Choice? = null)

/** A row's link to the user's choice for its app (the proxy record's unit C, R3): to log its proxy, or to stop. */
internal enum class Choice { LOG, STOP }

/**
 * What a proxy row knows of the user's choice for its app (the proxy record's unit C, C8): whether the choice could
 * cover it ([offered], [org.visadahyu.datapavan.network.proxy.ProxyChoice.offered], so never on Android's setting, a
 * local proxy, a tool's row or the PAC handler's), whether its app is chosen ([chosen]), whether the switch of every
 * app is on ([switchOn]), whether the place is a TCP connection's ([tcp]), for the line of a destination asked for
 * before its proxy was logged, which a SOCKS5 relay's datagrams never say, and whether a row not offered is so because
 * its proxy can carry other apps' connections ([shared], [ProxyChoices.row]; review C-rest 2).
 */
internal data class RowChoice(
    val offered: Boolean = false,
    val chosen: Boolean = false,
    val switchOn: Boolean = false,
    val tcp: Boolean = true,
    val shared: Boolean = false,
) {
    /** Whether the row offers to log its app's proxy: it could be covered, and neither the switch nor the choice keeps it. */
    val toLog: Boolean get() = offered && !chosen && !switchOn
}

/**
 * The row of a destination's proxy [facts], in "Now" or, [past], in the history, as a pure function the JVM tests
 * hold. How the network part knows is always said, the switch on or off: "Read from the connection" or "Inferred from
 * where and how it connects". A flow left out for the switch shows its kind, Android's setting in its own words, and
 * the facts that name nothing (on the local network, or else the maker's network it is not in; a password
 * unencrypted). A plain request in a proxy's form is never called a proxy: its line says what it asked for, or with the
 * switch off that this is not shown. The one exception is a plain request to Android's setting, which is called by
 * that setting's name, since Android names it so (the proxy record's unit B, R7): left out, it has the setting's
 * headers, and within its window in "Now" it ends as a first hop does. A record the engine could not tell was a
 * messenger's proxy says so in the kind's own words in place of its proxy line ([ProxyFacts.Facts.unsure]), never that
 * it went through one, nor how that was inferred. Where the network part cannot name the network, the maker's network
 * the address is not in is still said (ADR 0052, decision 6). The row of a circumvention tool's own flow, [tool] its
 * name, says so after the facts (the proxy record's unit B, B6), never "your proxy". A first hop "Now" shows only for
 * its window ends with why: for a declared proxy, that where the app asked it to go is not shown or logged, then that
 * its address is shown only so long; and links to the switch. The history never says so: what it shows was logged.
 *
 * The user's choice for one app ([choice]; the proxy record's unit C, C8, with audit-C 1): a row the choice could cover
 * says so in its window's line and its header past the window, and links to the choice while neither the switch nor the
 * choice keeps it; a row no choice covers (Android's setting, a local proxy, a tool's, the PAC proxy's) says that its
 * proxy can carry other apps' connections, so only the switch logs it; one the choice is not offered on for another
 * reason (another user's, one whose owner Android did not tell, one of Android's own UIDs) says only that the switch
 * logs it (review C-rest 2); a row of a chosen app left out while its proxy was not logged says so. In "Now", a row the
 * choice alone keeps says why it is shown in full, and links to stop; and a row read from the connection, kept with no
 * destination asked for, says that it asked for it before its proxy was logged (review A-rest, note 11). A plain
 * request is never said to be logged for the choice, which would call its server a proxy.
 */
internal fun proxyRow(facts: ProxyFacts.Facts, past: Boolean, tool: String? = null, choice: RowChoice = RowChoice()): ProxyRow {
    val lines = mutableListOf<ProxyLine>()
    val notMaker = ProxyLine(R.string.proxy_not_maker, args = listOf(isolate(facts.maker)))
    // A tool's own connection through a proxy: a fact of the app, which names no address, so it stays with the switch off.
    val toolLine = tool?.let { ProxyLine(R.string.proxy_tool, args = listOf(isolate(it))) }
    val toLog = Choice.LOG.takeIf { choice.toLog }
    // Why a row the choice is not offered on is so: its proxy can carry other apps' connections, or nothing it can say.
    val shared = choice.shared || tool != null || facts.setting || facts.where == ProxyFacts.Where.LOCAL
    if (!facts.kept) {
        // A record the engine could not tell was a messenger's proxy (taken back, or never named for substitution) says
        // so in place of its proxy line, and so says nothing of how it was inferred: only the history has such records.
        val unsure = facts.unsure && past
        val header = ProxyLine(
            when {
                unsure -> R.string.history_proxy_unsure
                facts.setting && past -> R.string.history_proxy_setting_hidden
                facts.setting -> R.string.now_proxy_setting_past
                past -> R.string.history_proxy_hidden
                // Unit C: a proxy no choice for one app covers says so; a chosen app's place left out while its proxy
                // was not logged stays as it was, and says so (audit-C 1).
                !choice.offered -> if (shared) R.string.now_proxy_past_shared else R.string.now_proxy_past_switch
                choice.chosen && !choice.switchOn -> R.string.now_proxy_past_chosen
                else -> R.string.now_proxy_past
            },
            kind = facts.kind,
        )
        if (!unsure) lines += ProxyLine(if (facts.declared) R.string.proxy_how_read else R.string.proxy_how_inferred)
        // "On your local network" names no address, so it stays with the switch off (finding 4 of the brief's audit), in
        // the history and in "Now" past the window alike; as in a kept row, a local address says nothing of a maker.
        when {
            facts.where == ProxyFacts.Where.LOCAL -> lines += ProxyLine(R.string.proxy_local)
            facts.maker.isNotEmpty() -> lines += notMaker
        }
        if (facts.password) lines += ProxyLine(R.string.proxy_password)
        if (!unsure) toolLine?.let { lines += it }
        return ProxyRow(header, lines, toSwitch = true, toChoice = toLog)
    }
    if (facts.kind == ProxyFacts.Kind.REQUEST) {
        if (facts.askedLeftOut) {
            lines += ProxyLine(if (past) R.string.history_proxy_request_hidden else R.string.now_proxy_request_hidden)
            lines += ProxyLine(R.string.proxy_how_read)
        } else {
            lines += ProxyLine(R.string.proxy_request_asked, args = listOf(isolateLtr(facts.asked)))
        }
        if (facts.setting) lines += ProxyLine(R.string.proxy_setting)
        if (facts.password) lines += ProxyLine(R.string.proxy_request_password)
        // Through Android's setting, a tool's plain request goes through a proxy; to any other server it is not said to.
        if (facts.setting) toolLine?.let { lines += it }
        // A plain request to Android's setting is that proxy's first hop (R7): "Now" shows it only for its window, as any
        // own proxy's, and says so. The engine marks no other plain request so; were one marked, it is not called a proxy.
        // No choice for one app covers Android's setting (unit C).
        val shownOnly = facts.shownOnly && facts.setting && !past
        if (shownOnly) lines += ProxyLine(R.string.now_proxy_live_only_shared)
        return ProxyRow(null, lines, toSwitch = facts.askedLeftOut || shownOnly, toChoice = toLog.takeIf { facts.askedLeftOut })
    }
    lines += when {
        !facts.declared -> ProxyLine(R.string.proxy_inferred, facts.kind, listOf(isolateLtr(facts.at)))
        facts.asked.isNotEmpty() -> ProxyLine(R.string.proxy_asked, facts.kind, listOf(isolateLtr(facts.at), isolateLtr(facts.asked)))
        else -> ProxyLine(R.string.proxy_declared, facts.kind, listOf(isolateLtr(facts.at)))
    }
    lines += when {
        facts.where == ProxyFacts.Where.LOCAL -> ProxyLine(R.string.proxy_local)
        facts.where == ProxyFacts.Where.UNKNOWN -> ProxyLine(R.string.proxy_network_unknown)
        facts.maker.isNotEmpty() -> ProxyLine(R.string.proxy_network_not_maker, args = listOf(isolate(facts.organisation), isolate(facts.maker)))
        else -> ProxyLine(R.string.proxy_network, args = listOf(isolate(facts.organisation)))
    }
    if (facts.where == ProxyFacts.Where.UNKNOWN && facts.maker.isNotEmpty()) lines += notMaker
    if (facts.cover.isNotEmpty()) {
        lines += ProxyLine(R.string.proxy_cover, args = listOf(isolateLtr(facts.cover)))
        facts.coverOwner?.let { (name, network) -> lines += ProxyLine(R.string.proxy_cover_owner, args = listOf(isolate(name), isolate(network))) }
    }
    if (facts.setting) lines += ProxyLine(R.string.proxy_setting)
    if (facts.password) lines += ProxyLine(R.string.proxy_password)
    toolLine?.let { lines += it }
    if (past) return ProxyRow(null, lines, toSwitch = false)
    if (facts.shownOnly) {
        if (facts.declared) lines += ProxyLine(R.string.now_proxy_asked_off)
        // "Choose below" only where the link is below: a chosen app's flow opened before the choice, or one the switch
        // was turned on after, has none.
        lines += ProxyLine(
            when {
                choice.toLog -> R.string.now_proxy_live_only
                shared -> R.string.now_proxy_live_only_shared
                else -> R.string.now_proxy_live_only_switch
            },
        )
        return ProxyRow(null, lines, toSwitch = true, toChoice = toLog)
    }
    // Kept with no destination asked for: it opened while its proxy was not logged (note 11). A SOCKS5 relay's datagram
    // asks for nothing of its own on its first read alone, so only a TCP connection's says so.
    if (facts.declared && facts.asked.isEmpty() && choice.tcp) lines += ProxyLine(R.string.now_proxy_asked_earlier)
    // Kept by the user's choice alone, the switch off.
    val chosen = choice.offered && choice.chosen && !choice.switchOn
    if (chosen) lines += ProxyLine(R.string.now_proxy_app_logged)
    return ProxyRow(null, lines, toSwitch = false, toChoice = Choice.STOP.takeIf { chosen })
}

/**
 * The one line "Now" shows of Android's own proxy settings while any is set (the proxy record's unit B, B7; note 24 of
 * the brief's audit), as a pure function the JVM tests hold. The whole phone's comes first, as Android puts it first:
 * apps then follow it, not the network's. Else the network's own, which reaches only the apps that were already running
 * when Datapavan's VPN started and the apps left out (measurements 7.1 and 7.2): its words change again with the unit
 * that gives the VPN the network's proxy (`setHttpProxy`). A PAC file has a sentence of its own, the network's saying
 * that apps started inside the VPN do not use it. It never says who set a proxy, or whether anyone chose it (ADR 0025).
 */
internal fun androidProxyLine(proxy: AndroidProxy): ProxyLine? {
    fun at(server: AndroidProxy.Setting.Server) = listOf(isolateLtr(ProxyFacts.hostPort(server.host, server.port)))
    return when (val global = proxy.global) {
        is AndroidProxy.Setting.Server -> ProxyLine(R.string.now_proxy_global, args = at(global))
        AndroidProxy.Setting.Pac -> ProxyLine(R.string.now_proxy_global_pac)
        null -> when (val network = proxy.network) {
            is AndroidProxy.Setting.Server -> ProxyLine(R.string.now_proxy_network, args = at(network))
            AndroidProxy.Setting.Pac -> ProxyLine(R.string.now_proxy_network_pac)
            null -> null
        }
    }
}

/**
 * The fact on the row of the app of [uid] where it is Android's PAC proxy, whose UID is [handler] (the proxy record's
 * unit B, B5; [org.visadahyu.datapavan.network.proxy.PacHandler]), as a pure function the JVM tests hold: it connects for
 * other apps, the apps left out included, so its connections are never said to be its own. In "Now" and on the app's
 * history alike, by the UID alone: whether a PAC file was set when a record was made is not known, so the line says
 * what the app is, not that a PAC file was in use.
 */
internal fun pacHandlerLine(handler: Int?, uid: Int?): ProxyLine? =
    ProxyLine(R.string.proxy_pac_handler).takeIf { handler != null && uid == handler }

/** A proxy's line as the user reads it: the kind's words set in first, then the other arguments. */
@Composable
internal fun lineText(line: ProxyLine): String {
    val args = listOfNotNull(line.kind?.let { stringResource(proxyKind(it)) }) + line.args
    return stringResource(line.text, *args.toTypedArray())
}

/** The lines of a destination's proxy (ADR 0052), as [proxyRow] chose them. */
@Composable
internal fun ProxyLines(lines: List<ProxyLine>) {
    for (line in lines) Text(lineText(line), style = MaterialTheme.typography.bodySmall)
}

/** "What this view cannot see" (ADR 0046, decision 5), in plain words at the end of "Now". */
@Composable
private fun CannotSee() {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 16.dp)) {
        Text(
            stringResource(R.string.cannot_see_title),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.semantics { heading() },
        )
        for (line in listOf(
            R.string.cannot_see_sender, R.string.cannot_see_content, R.string.cannot_see_device, R.string.cannot_see_together,
            R.string.cannot_see_gaps, R.string.cannot_see_sizes, R.string.cannot_see_notification, R.string.cannot_see_in_use,
            R.string.cannot_see_proxy,
        )) {
            Text("• " + stringResource(line), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** How many destinations an app's row shows before the user asks for all. */
private const val FIRST_PLACES = 5
