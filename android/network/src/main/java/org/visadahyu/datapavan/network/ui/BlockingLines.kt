package org.visadahyu.datapavan.network.ui

import android.content.Context
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import java.text.DateFormat
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.Date
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.activity.Companies
import org.visadahyu.datapavan.network.activity.History
import org.visadahyu.datapavan.network.activity.TrackerMarks
import org.visadahyu.datapavan.network.blocking.BlockingFacts
import org.visadahyu.datapavan.network.blocking.BlockingTable
import org.visadahyu.datapavan.network.blocking.Grades
import org.visadahyu.datapavan.network.blocking.Tallies
import org.visadahyu.datapavan.network.blocking.TrackerCode

/**
 * What "Now" and the history know of tracker blocking (W8, part 3a; ADR 0053): whether it is [on], the [facts] the
 * engine was handed (or a screen's own reading), what the engine counted in memory ([tallies]), the apps and rows the
 * user allowed, by package ([appsAllowed], each with when its hour ends; [entriesAllowed], until blocked again), and
 * the global pause's end. Read again with each second's snapshot and after each tap.
 */
internal data class BlockingView(
    val on: Boolean = false,
    val facts: BlockingFacts? = null,
    val tallies: List<Tallies.Tally> = emptyList(),
    val appsAllowed: Map<String, Long> = emptyMap(),
    val entriesAllowed: Set<Pair<String, String>> = emptySet(),
    val pausedUntil: Long? = null,
)

/** The undo, by an app's packages: the app for an hour, or the hosts of one tracker or company until blocked again. */
internal class BlockingActions(
    val onAllowApp: (List<String>) -> Unit = {},
    val onBlockAppAgain: (List<String>) -> Unit = {},
    val onAllowEntries: (List<String>, List<String>) -> Unit = { _, _ -> },
    val onBlockEntriesAgain: (List<String>, List<String>) -> Unit = { _, _ -> },
)

/**
 * How a blocking line names a row (ADR 0046's decision 4 as ADR 0053 amends it): εxodus names the tracker its SDK is,
 * with its company where the owners' table gives one; several trackers of one company by the company; a row no εxodus
 * tracker joins by its host; and where "Log where apps connect ..." leaves the app's destinations out, by its SDK's
 * coordinate in place of the host, which is never shown then.
 */
internal sealed interface Named {
    data class Tracker(val name: String, val company: String?) : Named
    data class Company(val name: String) : Named
    data class Host(val host: String) : Named
    data class Sdk(val coordinate: String) : Named
}

/**
 * The name of [row]: the εxodus trackers its classes join ([TrackerCode.named]), [companyOf] giving each its company
 * where the owners' table knows it; the host where none joins, or the SDK where [hideHost].
 */
internal fun rowName(
    row: BlockingTable.Row,
    trackers: List<TrackerCode.Tracker>,
    companyOf: (TrackerCode.Tracker) -> String?,
    hideHost: Boolean,
): Named {
    val joined = TrackerCode.named(row.classes, trackers).distinctBy { it.id }
    val companies = joined.map(companyOf).toSet()
    val company = companies.singleOrNull()
    return when {
        joined.size == 1 -> Named.Tracker(joined[0].name, company)
        joined.size > 1 && company != null -> Named.Company(company)
        joined.size > 1 -> Named.Tracker(joined.map { it.name }.distinct().joinToString(", "), null)
        hideHost -> Named.Sdk(row.sdk)
        else -> Named.Host(row.host)
    }
}

/**
 * One allow of an app: the rows it allows together, by their hosts; what it is called ([named]); each row's name and
 * function; what the engine counted for them, lookups apart from connections, since the first; and whether every one of
 * them is allowed in the app now.
 */
internal data class BlockUnit(
    val named: Named,
    val hosts: List<String>,
    val functions: List<Pair<Named, String>>,
    val lookups: Long,
    val connections: Long,
    val since: Long?,
    val allowed: Boolean,
)

/**
 * The allows of the [rows] an app reached that blocking blocks in it: one per row, except that the rows one broad εxodus
 * network signature names as one company's ([company], as [TrackerMarks] groups them) share one allow for the company;
 * where [hideHost], rows that would be told apart by their hosts alone share their name's. Each with what [tallies]
 * counted for its hosts and whether [allowed] holds all of them; most counted first.
 */
internal fun units(
    rows: Collection<BlockingTable.Row>,
    tallies: List<Tallies.Tally>,
    name: (BlockingTable.Row) -> Named,
    company: (BlockingTable.Row) -> String?,
    allowed: Set<String>,
    hideHost: Boolean,
): List<BlockUnit> = rows.distinctBy { it.host }
    .groupBy { row -> company(row)?.let { "company\u0000$it" } ?: if (hideHost) "named\u0000${name(row)}" else "host\u0000${row.host}" }
    .values.map { members ->
        val owner = company(members.first())
        val counted = tallies.filter { tally -> members.any { it.host == tally.host } }
        BlockUnit(
            named = owner?.let { Named.Company(it) } ?: name(members.first()),
            hosts = members.map { it.host },
            functions = members.map { name(it) to it.function },
            lookups = counted.sumOf { it.lookups },
            connections = counted.sumOf { it.connections },
            since = counted.minOfOrNull { it.sinceMs },
            allowed = members.all { it.host in allowed },
        )
    }
    .sortedWith(compareByDescending<BlockUnit> { it.lookups + it.connections }.thenBy { it.named.toString() })

/** What an app's row says of blocking: until when it is allowed (null for not allowed), and its allows with their counts. */
internal data class AppBlocking(val allowedUntil: Long?, val units: List<BlockUnit>)

/**
 * The blocking of the app [uid] of the [packages], for its row in "Now" and the top of its history, or null where it
 * says nothing: blocking off, no table, an app Android named no package for, or one blocking does not cover and that
 * has no count. The rows it reached are those the engine counted for it.
 */
internal fun appBlocking(
    view: BlockingView,
    uid: Int?,
    packages: List<String>,
    name: (BlockingTable.Row) -> Named,
    company: (BlockingTable.Row) -> String?,
    hideHost: Boolean,
): AppBlocking? {
    val facts = view.facts ?: return null
    if (!view.on || uid == null || packages.isEmpty() || facts.table.rows.isEmpty()) return null
    val tallies = view.tallies.filter { it.uid == uid }
    if (uid !in facts.covered && tallies.isEmpty()) return null
    val rows = tallies.mapNotNull { facts.table.row(it.host) }
    val allowed = view.entriesAllowed.filter { it.first in packages }.map { it.second }.toSet()
    return AppBlocking(packages.mapNotNull { view.appsAllowed[it] }.maxOrNull(), units(rows, tallies, name, company, allowed, hideHost))
}

/**
 * Why a row the app reached is not blocked in it, as a string, or null for one blocked: the table keeps it (it also
 * serves the app itself); the app's code keeps a code-dependent row (sign-in or sharing), or the audit has not read its
 * code; or an exception keeps it for the vendor's own app. Never the word the table uses for it (ADR 0025).
 */
internal fun keptFact(row: BlockingTable.Row, decided: Grades.Decided?): Int? = when {
    decided == Grades.Decided.EXCEPTED -> R.string.blocking_kept_own
    decided == Grades.Decided.BLOCK -> null
    row.grade == BlockingTable.Grade.KEEP -> R.string.blocking_kept
    row.grade == BlockingTable.Grade.CODE && decided == Grades.Decided.KEEP -> R.string.blocking_kept_code
    row.grade == BlockingTable.Grade.CODE -> R.string.blocking_kept_unread
    else -> null
}

/** What a segment of the history says of blocking: blocked, by its row's name and function; or why its host is kept. */
internal sealed interface EntryBlocking {
    data class Blocked(val named: Named, val function: String?) : EntryBlocking
    data class Kept(val fact: Int) : EntryBlocking
}

/**
 * The row a segment reached, by its names on label boundaries: none where the log keeps no destination of it
 * ([History.Entry.unlogged]).
 */
internal fun rowOf(entry: History.Entry, table: BlockingTable): BlockingTable.Row? =
    if (entry.unlogged) null else table.find(entry.name) ?: entry.dnsName.takeIf { it.isNotEmpty() }?.let(table::find)

/**
 * What the segment [entry] of the app [uid] says of blocking: a flow blocking refused, by the row its names reach or
 * else the rows of the SDK its record kept, named without the host where the log kept none or [hideHost]; or, with
 * blocking on and the app covered, the fact of a host it reached and that is not blocked in it.
 */
internal fun entryBlocking(
    entry: History.Entry,
    view: BlockingView,
    uid: Int?,
    name: (BlockingTable.Row, Boolean) -> Named,
    hideHost: Boolean,
): EntryBlocking? {
    val facts = view.facts ?: return null
    val hidden = hideHost || entry.unlogged
    val row = rowOf(entry, facts.table)
    if (entry.blocked) {
        if (row != null) return EntryBlocking.Blocked(name(row, hidden), row.function.takeIf { it.isNotEmpty() })
        val ofSdk = facts.table.ofSdk(entry.blockedSdk).firstOrNull()
        return EntryBlocking.Blocked(ofSdk?.let { name(it, true) } ?: Named.Sdk(entry.blockedSdk), null)
    }
    if (!view.on || row == null || uid == null || uid !in facts.covered) return null
    return keptFact(row, facts.decided[uid]?.get(row.host))?.let { EntryBlocking.Kept(it) }
}

/**
 * The top of an app's history: the app's own allow ([AppBlocking]), the allows of every row it reached that blocking
 * blocks in it, from the engine's counts, the day's segments and the log's blocked flows, and the rows it reached that
 * are not blocked in it, each with why.
 */
internal data class HistoryBlocking(val app: AppBlocking?, val units: List<BlockUnit>, val kept: List<Pair<Named, Int>>)

internal fun historyBlocking(
    view: BlockingView,
    uid: Int?,
    packages: List<String>,
    entries: List<History.Entry>,
    name: (BlockingTable.Row, Boolean) -> Named,
    company: (BlockingTable.Row) -> String?,
    hideHost: Boolean,
): HistoryBlocking {
    val app = appBlocking(view, uid, packages, { name(it, hideHost) }, company, hideHost)
    val facts = view.facts
    if (app == null || facts == null) return HistoryBlocking(app, emptyList(), emptyList())
    val tallies = view.tallies.filter { it.uid == uid }
    val logged = entries.mapNotNull { rowOf(it, facts.table) }
    val ofSdks = entries.filter { it.blocked && rowOf(it, facts.table) == null }.flatMap { facts.table.ofSdk(it.blockedSdk) }
    val hidden = hideHost || entries.any { it.blocked && it.unlogged }
    val reached = (tallies.mapNotNull { facts.table.row(it.host) } + logged + ofSdks).distinctBy { it.host }
    val allowed = view.entriesAllowed.filter { it.first in packages }.map { it.second }.toSet()
    val blocked = reached.filter { facts.blocks(uid, it) }
    val kept = reached.filter { !facts.blocks(uid, it) && it in logged }
        .mapNotNull { row -> keptFact(row, facts.decided[uid]?.get(row.host))?.let { name(row, hideHost) to it } }
        .distinct()
    return HistoryBlocking(app, units(blocked, tallies, { name(it, hidden) }, company, allowed, hidden), kept)
}

/** A row's name as the screens set it in a sentence: isolated, names in their own direction, hosts left to right. */
@Composable
internal fun namedText(named: Named): String = when (named) {
    is Named.Tracker -> named.company?.let { stringResource(R.string.blocking_tracker_company, isolate(named.name), isolate(it)) }
        ?: isolate(named.name)
    is Named.Company -> stringResource(R.string.blocking_company, isolate(named.name))
    is Named.Host -> isolateLtr(named.host)
    is Named.Sdk -> isolateLtr(named.coordinate)
}

/** A time as the phone writes it (its 12- or 24-hour clock), with the date where it is not today. */
internal fun whenText(context: Context, millis: Long): String {
    val time = android.text.format.DateFormat.getTimeFormat(context).format(Date(millis))
    val day = Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()).toLocalDate()
    if (day == LocalDate.now()) return isolate(time)
    val date = DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(millis))
    return isolate(context.getString(R.string.blocking_day_time, date, time))
}

/**
 * The functions that name rows for one screen, from [facts], the owners' tables [companies] and the εxodus matches
 * [trackers] of each host at port 443 (the engine's library, as "Now" reads them).
 */
internal class RowNames(
    private val facts: BlockingFacts?,
    private val companies: Companies?,
    private val trackers: Map<String, List<TrackerMarks.Match>>,
) {
    /** A tracker's company, by its website, where the owners' table gives one. */
    private fun companyOf(tracker: TrackerCode.Tracker): String? = companies?.groupOfWebsite(tracker.website)?.let { companies.name(it) }

    fun name(row: BlockingTable.Row, hideHost: Boolean): Named = rowName(row, facts?.trackers.orEmpty(), ::companyOf, hideHost)

    /**
     * The company one broad εxodus network signature names for the row's host, several of its trackers at once, as
     * [TrackerMarks] marks it; null where it names one tracker, or none. The app's own company plays no part (ADR 0053,
     * decision 2): the marks are asked with no app's group.
     */
    fun company(row: BlockingTable.Row): String? {
        val matches = trackers[host(row)].orEmpty()
        if (matches.isEmpty()) return null
        val marks = TrackerMarks.marks(matches, null, { companies?.groupOfWebsite(it.website) }, { companies?.name(it) ?: it })
        return marks.filterIsInstance<TrackerMarks.Mark.Company>().firstOrNull()?.name
    }

    companion object {
        /** The line the engine's library is asked for a row's host: at port 443, as its SDK sends. */
        fun host(row: BlockingTable.Row): String = "${row.host}\t443"
    }
}

/** What blocking counted for one allow, lookups apart from connections. */
@Composable
internal fun UnitCounts(context: Context, unit: BlockUnit) {
    val named = namedText(unit.named)
    val since = unit.since?.let { whenText(context, it) } ?: return
    if (unit.connections > 0) {
        val n = unit.connections.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        Text(pluralStringResource(R.plurals.blocking_connections, n, n, named, since), style = MaterialTheme.typography.bodyMedium)
    }
    if (unit.lookups > 0) {
        val n = unit.lookups.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
        Text(pluralStringResource(R.plurals.blocking_lookups, n, n, named, since), style = MaterialTheme.typography.bodyMedium)
    }
}

/** Beside every allow: what apps may send once allowed, and how soon it works. */
@Composable
internal fun AllowNotes() {
    Text(stringResource(R.string.blocking_late_sends), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(R.string.blocking_seconds), style = MaterialTheme.typography.bodySmall)
}

/**
 * An app's blocking in "Now" or at the top of its history: what was counted, when [counts], and the one tap that allows
 * trackers in it for an hour, or, while allowed, until when and the tap that blocks them again.
 */
@Composable
internal fun AppBlockingLines(context: Context, blocking: AppBlocking, packages: List<String>, actions: BlockingActions, counts: Boolean = true) {
    if (counts) for (unit in blocking.units) UnitCounts(context, unit)
    val until = blocking.allowedUntil
    if (until != null) {
        Text(
            stringResource(R.string.blocking_app_allowed, whenText(context, until)),
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        OutlinedButton(onClick = { actions.onBlockAppAgain(packages) }) { Text(stringResource(R.string.blocking_block_app)) }
    } else {
        OutlinedButton(onClick = { actions.onAllowApp(packages) }) { Text(stringResource(R.string.blocking_allow_app)) }
        AllowNotes()
    }
}

/** The top of an app's history ([historyBlocking]): its allow, each tracker's or company's allow, and the hosts kept. */
@Composable
internal fun HistoryBlockingLines(context: Context, blocking: HistoryBlocking, packages: List<String>, actions: BlockingActions) {
    val app = blocking.app ?: return
    Text(
        stringResource(R.string.blocking_history_title),
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.semantics { heading() },
    )
    AppBlockingLines(context, app, packages, actions, counts = false)
    for (unit in blocking.units) {
        val named = namedText(unit.named)
        Text(named, style = MaterialTheme.typography.titleSmall)
        // A company's allow names each of its trackers above what it does.
        for ((rowNamed, function) in unit.functions.distinct()) {
            if (function.isEmpty()) continue
            if (unit.functions.size > 1) Text(namedText(rowNamed), style = MaterialTheme.typography.bodySmall)
            Text(stringResource(R.string.blocking_function, function.removeSuffix(".")), style = MaterialTheme.typography.bodySmall)
        }
        UnitCounts(context, unit)
        if (unit.allowed) {
            Text(stringResource(R.string.blocking_entry_allowed), style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = { actions.onBlockEntriesAgain(packages, unit.hosts) }) {
                Text(stringResource(R.string.blocking_block_entry, named))
            }
        } else {
            OutlinedButton(onClick = { actions.onAllowEntries(packages, unit.hosts) }) {
                Text(stringResource(R.string.blocking_allow_entry, named))
            }
        }
    }
    if (blocking.units.isNotEmpty()) AllowNotes()
    for ((named, fact) in blocking.kept) {
        Text(namedText(named), style = MaterialTheme.typography.titleSmall)
        Text(stringResource(fact), style = MaterialTheme.typography.bodySmall)
    }
}

/** A segment's blocking, under its destination in the history. */
@Composable
internal fun EntryBlockingLines(line: EntryBlocking) {
    when (line) {
        is EntryBlocking.Blocked -> {
            Text(stringResource(R.string.blocking_blocked, namedText(line.named)), style = MaterialTheme.typography.bodyMedium)
            line.function?.let { Text(stringResource(R.string.blocking_function, it.removeSuffix(".")), style = MaterialTheme.typography.bodySmall) }
        }
        is EntryBlocking.Kept -> Text(stringResource(line.fact), style = MaterialTheme.typography.bodySmall)
    }
}
