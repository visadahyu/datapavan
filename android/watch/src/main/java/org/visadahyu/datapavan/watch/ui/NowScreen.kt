package org.visadahyu.datapavan.watch.ui

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
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.activity.AppNames
import org.visadahyu.datapavan.watch.activity.Companies
import org.visadahyu.datapavan.watch.activity.NowRows
import org.visadahyu.datapavan.watch.activity.ProxyFacts
import org.visadahyu.datapavan.watch.activity.Snapshot
import org.visadahyu.datapavan.watch.activity.TrackerMarks
import org.visadahyu.datapavan.watch.log.AppState

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
)

/** The marks of a destination of the app [uid], from its hosts' matches (ADR 0046, decision 2 (d)). */
internal fun marksOf(hosts: List<String>, appGroup: String?, trackers: Map<String, List<TrackerMarks.Match>>, companies: Companies?): List<TrackerMarks.Mark> =
    TrackerMarks.marks(
        hosts.flatMap { trackers[it].orEmpty() }.distinct(),
        appGroup,
        { match -> companies?.groupOfWebsite(match.website) },
        { group -> companies?.name(group) ?: group },
    )

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
 * see (decision 5). A tap on an app opens its history. Each app is named only here, inside the app.
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
) {
    // Kept here, above the history, so that coming back from it, or a rotation, finds the list where it was
    // (review c1 of W5's third part, screens, M2).
    val listState = rememberLazyListState()
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        if (history != null) {
            BackHandler(onBack = onCloseHistory)
            HistoryScreen(history, view.groups[history.app.uid], view.trackers, view.companies, onDay, onCloseHistory, view.tunnelNames)
        } else {
            NowList(view, listState, onWindow, onSort, onAll, onHistory, onAllowAccess)
        }
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
            if (app != null) AppRow(context, app, window, view, onHistory)
        }
        item { CannotSee() }
    }
}

/** What the latest reading knew, the tunnel's state, and the window while the screen was off. */
@Composable
private fun Facts(view: NowView, snapshot: Snapshot?, onAllowAccess: () -> Unit) {
    val context = LocalContext.current
    if (!view.running) {
        Text(stringResource(R.string.now_watch_off), style = MaterialTheme.typography.bodyMedium)
    }
    when (snapshot?.known) {
        Snapshot.NO_ACCESS -> {
            Text(stringResource(R.string.now_no_access), style = MaterialTheme.typography.bodyMedium)
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
private fun AppRow(context: Context, app: Snapshot.App, window: Int, view: NowView, onHistory: (Int?, Boolean) -> Unit) {
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
            if (app.isTool) {
                Text(stringResource(R.string.now_is_tool), style = MaterialTheme.typography.bodyMedium)
                // Its servers show only while "Log where these apps connect" is on (decision 3, 2026-11-19).
                if (app.serversHidden) Text(stringResource(R.string.now_tool_hidden), style = MaterialTheme.typography.bodyMedium)
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
            if (app.throughTool) Text(stringResource(R.string.now_through_tool), style = MaterialTheme.typography.bodyMedium)
            if (app.throughTunnel != 0L) {
                Text(stringResource(R.string.now_through_tunnel, tunnelName(view, app.throughTunnel)), style = MaterialTheme.typography.bodyMedium)
            }
            Destinations(context, app, window, view)
        }
    }
}

/** An app's destinations with bytes in the window, most bytes first, the first few and then all on request. */
@Composable
private fun Destinations(context: Context, app: Snapshot.App, window: Int, view: NowView) {
    val places = app.destinations
        .filter { it.bytes[window * 2] + it.bytes[window * 2 + 1] > 0 }
        .sortedByDescending { it.bytes[window * 2] + it.bytes[window * 2 + 1] }
    var all by rememberSaveable(app.uid) { mutableStateOf(false) }
    val shown = if (all) places else places.take(FIRST_PLACES)
    for (place in shown) {
        HorizontalDivider(Modifier.padding(vertical = 4.dp))
        val bytes = stringResource(R.string.now_destination_bytes, size(context, place.bytes[window * 2]), size(context, place.bytes[window * 2 + 1]))
        val proxy = place.proxy?.let { proxyFacts(it, place.address, place.port, place.asn, view.groups[app.uid], view.companies) }
        if (proxy != null && !proxy.kept) {
            // An app's own proxy while "Log where these apps connect" is off: its kind, and no destination (ADR 0052).
            Text(stringResource(R.string.now_proxy_hidden, stringResource(proxyKind(proxy.kind))), style = MaterialTheme.typography.bodyMedium)
            ProxyLines(proxy)
            Text(bytes, style = MaterialTheme.typography.bodySmall)
            continue
        }
        val (name, dns) = NowRows.destination(place.name, place.dnsName, place.address.hostAddress.orEmpty())
        Place(
            name = name,
            dnsName = dns,
            namedBy = place.namedBy,
            // A proxied destination's organisation is the proxy's network's, which its lines say.
            organisation = if (proxy == null) place.organisation else "",
            marks = marksOf(org.visadahyu.datapavan.watch.NowActivity.hostsOf(place), view.groups[app.uid], view.trackers, view.companies),
            bytes = bytes,
            through = if (place.via == org.visadahyu.datapavan.watch.log.LogRecord.VIA_TUNNEL) tunnelName(view, place.tunnel) else null,
            proxy = proxy,
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
    /** The app's own proxy it went through, if one (ADR 0052). */
    proxy: ProxyFacts.Facts? = null,
) {
    Text(isolateLtr(name), style = MaterialTheme.typography.bodyLarge)
    through?.let { Text(stringResource(R.string.now_destination_tunnel, it), style = MaterialTheme.typography.bodySmall) }
    proxy?.let { ProxyLines(it) }
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
    for (mark in marks) {
        val line = when (mark) {
            is TrackerMarks.Mark.Tracker -> stringResource(R.string.now_tracker, isolate(mark.name))
            is TrackerMarks.Mark.Company -> stringResource(R.string.now_tracker_company, isolate(mark.name))
            is TrackerMarks.Mark.SameCompany -> stringResource(R.string.now_same_company, isolate(mark.name))
        }
        Text(line, style = MaterialTheme.typography.bodySmall)
    }
    Text(bytes, style = MaterialTheme.typography.bodySmall)
}

/**
 * The facts of a destination's proxy (ADR 0052), for the app of company group [appGroup], with the owners' tables
 * [companies] where the pack holds them.
 */
internal fun proxyFacts(
    proxy: org.visadahyu.datapavan.watch.log.LogRecord.Proxy,
    address: java.net.InetAddress,
    port: Int,
    asn: Long,
    appGroup: String?,
    companies: Companies?,
): ProxyFacts.Facts = ProxyFacts.of(
    proxy, address, port, asn,
    appMaker = appGroup?.let { companies?.name(it) ?: it },
    networkGroup = { companies?.groupOfAsn(it) },
    coverGroup = { companies?.groupOfHost(it) },
    groupName = { companies?.name(it) ?: it },
)

/** A proxy's kind, as the sentences set it in. */
internal fun proxyKind(kind: ProxyFacts.Kind): Int = when (kind) {
    ProxyFacts.Kind.SOCKS5 -> R.string.proxy_kind_socks5
    ProxyFacts.Kind.SOCKS4 -> R.string.proxy_kind_socks4
    ProxyFacts.Kind.HTTP -> R.string.proxy_kind_http
    ProxyFacts.Kind.MTPROTO -> R.string.proxy_kind_mtproto
    ProxyFacts.Kind.WHATSAPP -> R.string.proxy_kind_whatsapp
    ProxyFacts.Kind.SIGNAL -> R.string.proxy_kind_signal
}

/**
 * The lines of a destination's proxy (ADR 0052): its kind, where it is and how Watch knows, then where its address
 * is and that who runs it is not known, and the facts beside it. Only the facts that name nothing while its
 * destination is not kept.
 */
@Composable
internal fun ProxyLines(facts: ProxyFacts.Facts) {
    val kind = stringResource(proxyKind(facts.kind))
    if (facts.kept) {
        Text(
            if (facts.declared && facts.asked.isNotEmpty()) {
                stringResource(R.string.proxy_asked, kind, isolateLtr(facts.at), isolateLtr(facts.asked))
            } else {
                stringResource(R.string.proxy_inferred, kind, isolateLtr(facts.at))
            },
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            when {
                facts.where == ProxyFacts.Where.LOCAL -> stringResource(R.string.proxy_local)
                facts.where == ProxyFacts.Where.UNKNOWN -> stringResource(R.string.proxy_network_unknown)
                facts.maker.isNotEmpty() -> stringResource(R.string.proxy_network_not_maker, isolate(facts.organisation), isolate(facts.maker))
                else -> stringResource(R.string.proxy_network, isolate(facts.organisation))
            },
            style = MaterialTheme.typography.bodySmall,
        )
        if (facts.cover.isNotEmpty()) {
            Text(stringResource(R.string.proxy_cover, isolateLtr(facts.cover)), style = MaterialTheme.typography.bodySmall)
            facts.coverOwner?.let { (name, network) ->
                Text(stringResource(R.string.proxy_cover_owner, isolate(name), isolate(network)), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    if (facts.setting) Text(stringResource(R.string.proxy_setting), style = MaterialTheme.typography.bodySmall)
    if (facts.password) Text(stringResource(R.string.proxy_password), style = MaterialTheme.typography.bodySmall)
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
