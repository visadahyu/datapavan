package org.visadahyu.datapavan.ui

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppCollector
import org.visadahyu.datapavan.audit.Care
import org.visadahyu.datapavan.audit.Change
import org.visadahyu.datapavan.audit.ChangeKind
import org.visadahyu.datapavan.audit.DeviceCollector
import org.visadahyu.datapavan.audit.FloorReason
import org.visadahyu.datapavan.audit.HealthAnswer
import org.visadahyu.datapavan.audit.ItemState
import org.visadahyu.datapavan.audit.Journal
import org.visadahyu.datapavan.audit.JournalCodec
import org.visadahyu.datapavan.audit.JournalEntry
import org.visadahyu.datapavan.audit.JournalSession
import org.visadahyu.datapavan.audit.Outcome
import org.visadahyu.datapavan.audit.Plan
import org.visadahyu.datapavan.audit.PlanInput
import org.visadahyu.datapavan.audit.PlanItem
import org.visadahyu.datapavan.audit.PlanLevel
import org.visadahyu.datapavan.audit.PlanReason
import org.visadahyu.datapavan.audit.PlanResult
import org.visadahyu.datapavan.audit.Screen
import org.visadahyu.datapavan.audit.SpecialAccess
import org.visadahyu.datapavan.audit.sensorOf
import java.text.DateFormat
import java.util.Date

private enum class PlanStage { CHOOSE, CARD, SUMMARY }

/**
 * The plan's entry on the overview (ADR 0026, point 7): the question a few days after a session, a
 * note when a change has come back, and the first action of the next session, never a count.
 */
@Composable
internal fun PlanEntry(
    first: PlanItem?,
    due: JournalSession?,
    cameBack: Boolean,
    hasJournal: Boolean,
    onStart: () -> Unit,
    onJournal: () -> Unit,
    onAnswer: (HealthAnswer) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.plan_title), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            if (due != null) {
                Text(stringResource(R.string.plan_health_question, dateText(due.start)), style = MaterialTheme.typography.bodyMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { onAnswer(HealthAnswer.WORKS) }) { Text(stringResource(R.string.plan_health_works)) }
                    TextButton(onClick = { onAnswer(HealthAnswer.SOMETHING_WRONG) }) { Text(stringResource(R.string.plan_health_wrong)) }
                }
            }
            if (cameBack) Text(stringResource(R.string.plan_came_back), style = MaterialTheme.typography.bodyMedium)
            Text(
                first?.let { stringResource(R.string.plan_entry_first, title(it)) } ?: stringResource(R.string.plan_entry_none),
                style = MaterialTheme.typography.bodyMedium,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onStart) { Text(stringResource(R.string.plan_open)) }
                if (hasJournal) TextButton(onClick = onJournal) { Text(stringResource(R.string.journal_title)) }
            }
        }
    }
}

/**
 * The remediation plan (ADR 0026): the user picks a level, sees the session's cards, and works
 * through them one by one. Each card opens system screens, reads again what the item concerns when
 * the user comes back, and goes into the journal. [state] is what each item concerned when the audit
 * ran, to leave out what the user kept; [onJournal] stores each change of the journal.
 */
@Composable
internal fun PlanScreen(
    input: PlanInput,
    usageMissing: Boolean,
    journal: Journal,
    state: (PlanItem) -> ItemState,
    insets: PaddingValues,
    onJournal: (Journal) -> Unit,
    onBack: () -> Unit,
    onDone: () -> Unit,
) {
    val context = LocalContext.current
    var level by rememberSaveable { mutableStateOf(journal.sessions.lastOrNull()?.level ?: PlanLevel.LIGHT) }
    var stage by rememberSaveable { mutableStateOf(PlanStage.CHOOSE) }
    var sessionStart by rememberSaveable { mutableLongStateOf(0L) }
    var keys by rememberSaveable { mutableStateOf(listOf<String>()) }
    var index by rememberSaveable { mutableIntStateOf(0) }
    var before by rememberSaveable(stateSaver = StateSaver) { mutableStateOf<ItemState?>(null) }
    var after by rememberSaveable(stateSaver = StateSaver) { mutableStateOf<ItemState?>(null) }
    var opened by rememberSaveable { mutableStateOf(listOf<Screen>()) }
    var careAccepted by rememberSaveable { mutableStateOf(false) }
    var more by rememberSaveable { mutableStateOf(false) }
    var left by rememberSaveable { mutableStateOf(false) }
    var reading by remember { mutableStateOf(false) }

    val result = remember(input, level) { Plan.items(input, level) }
    val pending = remember(result, journal) { Plan.pending(result.items, journal.kept(), state) }
    val session = pending.take(Plan.SESSION_CARDS)
    // Every level's items, so that a card is found again by its key.
    val byKey = remember(input) { Plan.items(input, PlanLevel.STRICT).items.associateBy(PlanItem::key) }
    val item = keys.getOrNull(index)?.let(byKey::get)

    // Coming back from a system screen reads again what the card concerns.
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_STOP && opened.isNotEmpty()) left = true
            if (event == Lifecycle.Event.ON_RESUME && left) {
                left = false
                reading = true
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(stage, index, reading) {
        if (stage != PlanStage.CARD) return@LaunchedEffect
        if (item == null) {
            // The item went away, for example after the audit ran again.
            stage = PlanStage.SUMMARY
            return@LaunchedEffect
        }
        if (before == null) before = withContext(Dispatchers.IO) { read(context, item) }
        if (reading) {
            after = withContext(Dispatchers.IO) { read(context, item) }
            reading = false
        }
    }

    fun next(keep: Boolean) {
        val current = item ?: return
        val start = before ?: return
        val end = after ?: start
        val outcome = when {
            Journal.changes(start, end).isNotEmpty() -> Outcome.CHANGED
            keep -> Outcome.KEPT
            opened.isNotEmpty() -> Outcome.NOTHING_CHANGED
            else -> Outcome.SKIPPED
        }
        onJournal(journal.withEntry(JournalEntry(sessionStart, System.currentTimeMillis(), current.reason, current.app?.packageName, opened, start, end, outcome)))
        before = null
        after = null
        opened = emptyList()
        careAccepted = false
        if (index + 1 < keys.size) index++ else stage = PlanStage.SUMMARY
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets).testTag("plan"),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item { TextButton(onClick = if (stage == PlanStage.SUMMARY) onDone else onBack) { Text(stringResource(R.string.back)) } }
        item { Text(stringResource(R.string.plan_title), style = MaterialTheme.typography.headlineSmall) }
        when (stage) {
            PlanStage.CHOOSE -> {
                item { LevelChoice(level, usageMissing) { level = it } }
                item {
                    SectionTitle(R.string.plan_session_title)
                    if (session.isEmpty()) Text(stringResource(R.string.plan_empty), style = MaterialTheme.typography.bodyMedium)
                }
                items(session, key = { it.key }) { Text("· " + title(it), style = MaterialTheme.typography.bodyMedium) }
                item {
                    if (pending.size > session.size) Note(stringResource(R.string.plan_session_more))
                    if (session.isNotEmpty()) {
                        Button(onClick = {
                            sessionStart = System.currentTimeMillis()
                            onJournal(journal.withSession(JournalSession(sessionStart, level)))
                            keys = session.map { it.key }
                            more = pending.size > session.size
                            index = 0
                            stage = PlanStage.CARD
                        }, modifier = Modifier.padding(top = 8.dp)) { Text(stringResource(R.string.plan_start)) }
                    }
                }
                if (result.leftAlone.isNotEmpty()) item { LeftAlone(result) }
            }
            PlanStage.CARD -> if (item != null) {
                item {
                    PlanCard(
                        item, index, keys.size, before, after, reading, careAccepted || item.care == null,
                        onAccept = { careAccepted = true },
                        onOpen = { screen ->
                            opened = (opened + screen).distinct()
                            open(context, screenIntent(context, screen, item.app?.packageName))
                        },
                        onNext = { next(keep = false) },
                        onKeep = { next(keep = true) },
                    )
                }
            }
            PlanStage.SUMMARY -> item { Summary(journal.entriesOf(sessionStart), byKey, more, onDone = onDone) }
        }
    }
}

@Composable
private fun LevelChoice(level: PlanLevel, usageMissing: Boolean, onLevel: (PlanLevel) -> Unit) {
    Column {
        Text(stringResource(R.string.plan_intro), style = MaterialTheme.typography.bodyMedium)
        if (usageMissing) Note(stringResource(R.string.plan_no_usage))
        SectionTitle(R.string.plan_level)
        Column(Modifier.selectableGroup()) {
            PlanLevel.entries.forEach { choice ->
                Row(
                    Modifier.fillMaxWidth()
                        .selectable(selected = choice == level, onClick = { onLevel(choice) }, role = Role.RadioButton)
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = choice == level, onClick = null)
                    Column(Modifier.padding(start = 8.dp)) {
                        Text(stringResource(levelName(choice)), style = MaterialTheme.typography.bodyLarge)
                        Text(stringResource(levelBody(choice)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
private fun PlanCard(
    item: PlanItem,
    index: Int,
    count: Int,
    before: ItemState?,
    after: ItemState?,
    reading: Boolean,
    careDone: Boolean,
    onAccept: () -> Unit,
    onOpen: (Screen) -> Unit,
    onNext: () -> Unit,
    onKeep: () -> Unit,
) {
    val context = LocalContext.current
    val collector = remember { AppCollector(context) }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.plan_card_progress, index + 1, count), style = MaterialTheme.typography.labelMedium)
            Text(title(item), style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(body(item.reason)), style = MaterialTheme.typography.bodyMedium)
            item.app?.let { app ->
                val held = holds(app.grantedDangerous, app.special, app.vpnAuthorised, collector)
                if (held.isNotEmpty()) Text(stringResource(R.string.plan_holds, held.map { isolate(it) }.joinedForUser()), style = MaterialTheme.typography.bodyMedium)
            }
            if (item.also.isNotEmpty()) {
                Note(stringResource(R.string.plan_also, item.also.map { stringResource(shortName(it)) }.joinedForUser()))
            }
            if (item.trackerPurpose) Note(stringResource(R.string.plan_tracker_note))
            Spacer(Modifier.height(8.dp))
            when {
                before == null -> Text(stringResource(R.string.plan_reading), style = MaterialTheme.typography.bodyMedium)
                !careDone -> {
                    Text(stringResource(if (item.care == Care.CONTROL) R.string.plan_care_control else R.string.plan_care_untested), style = MaterialTheme.typography.bodyMedium)
                    OutlinedButton(onClick = onAccept) { Text(stringResource(R.string.plan_care_continue)) }
                }
                else -> {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        item.screens.filter { screenAvailable(it) }.forEach { screen ->
                            OutlinedButton(onClick = { onOpen(screen) }) { Text(stringResource(screenName(screen))) }
                        }
                    }
                    if (item.app != null && Screen.APP_INFO in item.screens) Note(stringResource(R.string.plan_uninstall_note))
                    if (Screen.DEVICE_ADMINS in item.screens) Note(stringResource(R.string.plan_device_admins_note))
                }
            }
            if (reading) Text(stringResource(R.string.plan_reading), style = MaterialTheme.typography.bodyMedium)
            if (before != null && after != null && !reading) {
                val changes = Journal.changes(before, after)
                Text(
                    if (changes.isEmpty()) stringResource(R.string.plan_nothing_yet)
                    else stringResource(R.string.plan_changed, changesText(changes, collector)),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
                Button(onClick = onNext, enabled = before != null && !reading) {
                    Text(stringResource(if (index + 1 < count) R.string.plan_next else R.string.plan_finish))
                }
                TextButton(onClick = onKeep, enabled = before != null && !reading) { Text(stringResource(R.string.plan_keep)) }
            }
        }
    }
}

/** What the session changed, kept and skipped, with the way into the journal. */
@Composable
private fun Summary(entries: List<JournalEntry>, items: Map<String, PlanItem>, more: Boolean, onDone: () -> Unit) {
    val context = LocalContext.current
    val collector = remember { AppCollector(context) }
    Column {
        SectionTitle(R.string.plan_summary_title)
        val changed = entries.filter { it.outcome == Outcome.CHANGED }
        if (changed.isEmpty()) Text(stringResource(R.string.plan_summary_nothing), style = MaterialTheme.typography.bodyMedium)
        changed.forEach { entry ->
            Text(
                stringResource(R.string.plan_summary_line, entryName(entry, items), changesText(entry.changes, collector)),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        val kept = entries.filter { it.outcome == Outcome.KEPT }
        if (kept.isNotEmpty()) Text(stringResource(R.string.plan_summary_kept, kept.map { entryName(it, items) }.joinedForUser()), style = MaterialTheme.typography.bodyMedium)
        val skipped = entries.filter { it.outcome == Outcome.SKIPPED || it.outcome == Outcome.NOTHING_CHANGED }
        if (skipped.isNotEmpty()) Text(stringResource(R.string.plan_summary_skipped, skipped.map { entryName(it, items) }.joinedForUser()), style = MaterialTheme.typography.bodyMedium)
        if (more) Note(stringResource(R.string.plan_session_more))
        Note(stringResource(R.string.plan_summary_journal))
        Button(onClick = onDone, modifier = Modifier.padding(top = 8.dp)) { Text(stringResource(R.string.plan_done)) }
    }
}

@Composable
private fun LeftAlone(result: PlanResult) {
    Column {
        SectionTitle(R.string.plan_left_alone_title)
        Text(stringResource(R.string.plan_left_alone_body), style = MaterialTheme.typography.bodyMedium)
        result.leftAlone.forEach { (app, reason) ->
            Text(stringResource(R.string.plan_left_alone_line, isolate(app.label ?: app.packageName), stringResource(floorName(reason))), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * The journal (ADR 0026, point 8): every session's cards, newest first, with what changed, what has
 * come back since, and the screens that undo it. [current] is what each entry concerns now.
 */
@Composable
internal fun JournalScreen(journal: Journal, labels: Map<String, String>, current: (JournalEntry) -> ItemState, insets: PaddingValues, onBack: () -> Unit, onDelete: () -> Unit) {
    val context = LocalContext.current
    val collector = remember { AppCollector(context) }
    var confirming by rememberSaveable { mutableStateOf(false) }
    val latest = journal.entries.groupBy { it.key }.mapValues { (_, list) -> list.maxBy { it.at } }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.journal_title), style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.journal_intro), style = MaterialTheme.typography.bodyMedium)
            if (journal.entries.isEmpty()) Text(stringResource(R.string.journal_empty), style = MaterialTheme.typography.bodyMedium)
        }
        journal.sessions.sortedByDescending { it.start }.forEach { session ->
            val entries = journal.entriesOf(session.start)
            if (entries.isEmpty()) return@forEach
            item(key = "session:${session.start}") {
                SectionTitle(R.string.journal_session)
                Text(stringResource(R.string.journal_session_line, dateText(session.start), stringResource(levelName(session.level))), style = MaterialTheme.typography.bodySmall)
            }
            items(entries, key = { "entry:${it.session}:${it.key}" }) { entry ->
                val name = entry.packageName?.let { labels[it] ?: it } ?: stringResource(R.string.journal_phone)
                JournalCard(entry, isolate(name), latest[entry.key] == entry, current(entry), collector)
            }
        }
        if (journal.entries.isNotEmpty() || journal.sessions.isNotEmpty()) {
            item {
                if (!confirming) {
                    TextButton(onClick = { confirming = true }) { Text(stringResource(R.string.journal_delete)) }
                } else {
                    Text(stringResource(R.string.journal_delete_confirm), style = MaterialTheme.typography.bodyMedium)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { confirming = false; onDelete() }) { Text(stringResource(R.string.journal_delete_yes)) }
                        TextButton(onClick = { confirming = false }) { Text(stringResource(R.string.journal_cancel)) }
                    }
                }
            }
        }
    }
}

@Composable
private fun JournalCard(entry: JournalEntry, name: String, latest: Boolean, current: ItemState, collector: AppCollector) {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(name, style = MaterialTheme.typography.titleSmall)
            Text(stringResource(shortName(entry.reason)), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val changes = entry.changes
            Text(
                when (entry.outcome) {
                    Outcome.CHANGED -> stringResource(R.string.plan_changed, changesText(changes, collector))
                    Outcome.NOTHING_CHANGED -> stringResource(R.string.journal_nothing_changed)
                    Outcome.KEPT -> stringResource(R.string.journal_kept)
                    Outcome.SKIPPED -> stringResource(R.string.journal_skipped)
                },
                style = MaterialTheme.typography.bodyMedium,
            )
            // Only the latest entry of an item says what came back, so that older ones do not contradict it.
            if (latest && entry.outcome == Outcome.CHANGED) {
                val back = changes.filter { Journal.cameBack(it, entry.after, current) }
                if (back.isNotEmpty()) Note(stringResource(R.string.journal_came_back, changesText(back, collector)))
                val undoable = changes.filter { it.kind != ChangeKind.UNINSTALLED && it !in back }
                if (undoable.isNotEmpty()) {
                    Note(stringResource(R.string.journal_undo, undoable.map { undoText(it, collector) }.distinct().joinedForUser()))
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        entry.opened.filter { screenAvailable(it) }.forEach { screen ->
                            TextButton(onClick = { open(context, screenIntent(context, screen, entry.packageName)) }) { Text(stringResource(screenName(screen))) }
                        }
                    }
                }
                if (changes.any { it.kind == ChangeKind.UNINSTALLED } && !current.installed) Note(stringResource(R.string.journal_uninstalled))
            }
        }
    }
}

/** Reads again what [item] concerns, off the main thread. */
private fun read(context: Context, item: PlanItem): ItemState =
    item.app?.let { AppCollector(context).state(it.packageName) } ?: DeviceCollector(context).planState()

@Composable
private fun entryName(entry: JournalEntry, items: Map<String, PlanItem>): String =
    entry.packageName?.let { isolate(items[entry.key]?.app?.label ?: it) } ?: stringResource(R.string.journal_phone)

@Composable
private fun title(item: PlanItem): String {
    val name = isolate(item.app?.let { it.label ?: it.packageName }.orEmpty())
    return when (item.reason) {
        PlanReason.WIRELESS_DEBUGGING -> stringResource(R.string.plan_wireless_title)
        PlanReason.CERTIFICATE_AUTHORITY -> stringResource(R.string.plan_authority_title)
        PlanReason.USB_DEBUGGING -> stringResource(R.string.plan_usb_title)
        PlanReason.CONTROL_ACCESS -> stringResource(R.string.plan_control_title, name)
        PlanReason.DOUBTFUL_COPY -> stringResource(R.string.plan_copy_title, name)
        PlanReason.INSTALLS_APPS -> stringResource(R.string.plan_installs_title, name)
        PlanReason.TRAFFIC_SHARING -> stringResource(R.string.plan_sharing_title, name)
        PlanReason.NOT_OPENED_SENSITIVE, PlanReason.NOT_OPENED_OTHER -> {
            val days = item.notOpenedDays ?: 0
            pluralStringResource(R.plurals.plan_not_opened_title, days.toInt(), name, days)
        }
        PlanReason.PREINSTALLED -> stringResource(R.string.plan_preinstalled_title, name)
    }
}

@StringRes
private fun body(reason: PlanReason) = when (reason) {
    PlanReason.WIRELESS_DEBUGGING -> R.string.plan_wireless_body
    PlanReason.CERTIFICATE_AUTHORITY -> R.string.plan_authority_body
    PlanReason.USB_DEBUGGING -> R.string.plan_usb_body
    PlanReason.CONTROL_ACCESS -> R.string.plan_control_body
    PlanReason.DOUBTFUL_COPY -> R.string.plan_copy_body
    PlanReason.INSTALLS_APPS -> R.string.plan_installs_body
    PlanReason.TRAFFIC_SHARING -> R.string.plan_sharing_body
    PlanReason.NOT_OPENED_SENSITIVE -> R.string.plan_not_opened_sensitive_body
    PlanReason.NOT_OPENED_OTHER -> R.string.plan_not_opened_other_body
    PlanReason.PREINSTALLED -> R.string.plan_preinstalled_body
}

@StringRes
private fun shortName(reason: PlanReason) = when (reason) {
    PlanReason.WIRELESS_DEBUGGING -> R.string.plan_short_wireless
    PlanReason.CERTIFICATE_AUTHORITY -> R.string.plan_short_authority
    PlanReason.USB_DEBUGGING -> R.string.plan_short_usb
    PlanReason.CONTROL_ACCESS -> R.string.plan_short_control
    PlanReason.DOUBTFUL_COPY -> R.string.plan_short_copy
    PlanReason.INSTALLS_APPS -> R.string.plan_short_installs
    PlanReason.TRAFFIC_SHARING -> R.string.plan_short_sharing
    PlanReason.NOT_OPENED_SENSITIVE, PlanReason.NOT_OPENED_OTHER -> R.string.plan_short_not_opened
    PlanReason.PREINSTALLED -> R.string.plan_short_preinstalled
}

@StringRes
private fun levelName(level: PlanLevel) = when (level) {
    PlanLevel.LIGHT -> R.string.plan_level_light
    PlanLevel.MEDIUM -> R.string.plan_level_medium
    PlanLevel.STRICT -> R.string.plan_level_strict
}

@StringRes
private fun levelBody(level: PlanLevel) = when (level) {
    PlanLevel.LIGHT -> R.string.plan_level_light_body
    PlanLevel.MEDIUM -> R.string.plan_level_medium_body
    PlanLevel.STRICT -> R.string.plan_level_strict_body
}

@StringRes
private fun screenName(screen: Screen) = when (screen) {
    Screen.APP_INFO -> R.string.screen_app_info
    Screen.UNUSED_APP_SETTING -> R.string.screen_unused
    Screen.ACCESSIBILITY -> R.string.screen_accessibility
    Screen.NOTIFICATION_LISTENER -> R.string.screen_notification_listener
    Screen.DEVICE_ADMINS -> R.string.screen_device_admins
    Screen.INSTALL_UNKNOWN_APPS -> R.string.screen_install_unknown
    Screen.OVERLAY -> R.string.screen_overlay
    Screen.USAGE_ACCESS -> R.string.screen_usage_access
    Screen.ALL_FILES -> R.string.screen_all_files
    Screen.BATTERY -> R.string.screen_battery
    Screen.VPN -> R.string.screen_vpn
    Screen.DEVELOPER_OPTIONS -> R.string.screen_developer
    Screen.SECURITY -> R.string.screen_security
}

@StringRes
private fun floorName(reason: FloorReason) = when (reason) {
    FloorReason.HOME -> R.string.floor_home
    FloorReason.PHONE -> R.string.floor_phone
    FloorReason.SMS -> R.string.floor_sms
    FloorReason.BROWSER -> R.string.floor_browser
    FloorReason.KEYBOARD -> R.string.floor_keyboard
    FloorReason.SCREEN_READER -> R.string.floor_screen_reader
    FloorReason.DEVICE_OWNER -> R.string.floor_device_owner
    FloorReason.PREINSTALLED_ADMIN -> R.string.floor_preinstalled_admin
    FloorReason.INSTALLER -> R.string.floor_installer
    FloorReason.PERMISSION_CONTROLLER -> R.string.floor_permissions
    FloorReason.DATAPAVAN -> R.string.floor_datapavan
    FloorReason.CORE -> R.string.floor_core
    FloorReason.TELEPHONY -> R.string.floor_telephony
    FloorReason.EMERGENCY -> R.string.floor_emergency
    FloorReason.UPDATES -> R.string.floor_updates
    FloorReason.SETUP -> R.string.floor_setup
    FloorReason.TIME_ZONE -> R.string.floor_time_zone
    FloorReason.CONNECTIVITY -> R.string.floor_connectivity
    FloorReason.DEVICE_LOCK -> R.string.floor_device_lock
}

/**
 * What an app holds, in the user's language: sensors by their short names, other permissions by
 * Android's labels, then special access and VPN permission.
 */
@Composable
private fun holds(permissions: List<String>, special: Set<SpecialAccess>, vpn: Boolean, collector: AppCollector): List<String> {
    val sensors = permissions.mapNotNull(::sensorOf).distinct().sortedBy { it.ordinal }.map { stringResource(sensorName(it)) }
    return sensors + permissions.filter { sensorOf(it) == null }.map { collector.permissionLabel(it) }.distinct() +
        special.sortedBy { it.ordinal }.map { stringResource(specialName(it)) } +
        listOfNotNull(if (vpn) stringResource(R.string.dormant_vpn) else null)
}

/** A permission's name: a sensor's short name, or Android's label. */
@Composable
private fun permissionName(permission: String, collector: AppCollector): String =
    sensorOf(permission)?.let { stringResource(sensorName(it)) } ?: isolate(collector.permissionLabel(permission))

/** The changes as the user reads them; precise and approximate location both read as location. */
@Composable
private fun changesText(changes: List<Change>, collector: AppCollector): String =
    changes.map { changeText(it, collector) }.distinct().joinedForUser()

@Composable
private fun changeText(change: Change, collector: AppCollector): String = when (change.kind) {
    ChangeKind.UNINSTALLED -> stringResource(R.string.change_uninstalled)
    ChangeKind.DISABLED -> stringResource(R.string.change_disabled)
    ChangeKind.PERMISSION_REMOVED -> stringResource(R.string.change_permission, permissionName(change.detail.orEmpty(), collector))
    ChangeKind.SPECIAL_REMOVED -> stringResource(R.string.change_special, specialNamed(change.detail))
    ChangeKind.VPN_REMOVED -> stringResource(R.string.change_vpn)
    ChangeKind.USB_DEBUGGING_OFF -> stringResource(R.string.change_usb)
    ChangeKind.WIRELESS_DEBUGGING_OFF -> stringResource(R.string.change_wireless)
    ChangeKind.AUTHORITY_REMOVED -> stringResource(R.string.change_authority)
}

/** What to turn back on to undo [change]. */
@Composable
private fun undoText(change: Change, collector: AppCollector): String = when (change.kind) {
    ChangeKind.UNINSTALLED -> ""
    ChangeKind.DISABLED -> stringResource(R.string.undo_enable)
    ChangeKind.PERMISSION_REMOVED -> permissionName(change.detail.orEmpty(), collector)
    ChangeKind.SPECIAL_REMOVED -> specialNamed(change.detail)
    ChangeKind.VPN_REMOVED -> stringResource(R.string.dormant_vpn)
    ChangeKind.USB_DEBUGGING_OFF -> stringResource(R.string.plan_short_usb)
    ChangeKind.WIRELESS_DEBUGGING_OFF -> stringResource(R.string.plan_short_wireless)
    ChangeKind.AUTHORITY_REMOVED -> stringResource(R.string.undo_authority)
}

@Composable
private fun specialNamed(name: String?): String =
    SpecialAccess.entries.firstOrNull { it.name == name }?.let { stringResource(specialName(it)) } ?: name.orEmpty()

@Composable
private fun dateText(millis: Long): String = isolate(DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(millis)))

private fun screenAvailable(screen: Screen): Boolean = when (screen) {
    Screen.UNUSED_APP_SETTING, Screen.ALL_FILES -> Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
    else -> true
}

/**
 * The system screen for [screen], for the app [packageName] where Android offers a page per app. A
 * notification listener's own page needs its component, which the secure setting names.
 */
private fun screenIntent(context: Context, screen: Screen, packageName: String?): Intent {
    val pkg = packageName?.let { Uri.fromParts("package", it, null) }
    val appInfo = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkg)
    val r = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R
    val intent = when (screen) {
        Screen.APP_INFO -> appInfo
        Screen.UNUSED_APP_SETTING -> if (r) Intent(Intent.ACTION_AUTO_REVOKE_PERMISSIONS, pkg) else appInfo
        Screen.ACCESSIBILITY -> Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
        Screen.NOTIFICATION_LISTENER -> {
            val listener = listenerOf(context, packageName)
            if (r && listener != null) {
                Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
                    .putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, listener.flattenToString())
            } else {
                Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            }
        }
        Screen.DEVICE_ADMINS, Screen.SECURITY -> Intent(Settings.ACTION_SECURITY_SETTINGS)
        Screen.INSTALL_UNKNOWN_APPS -> Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, pkg)
        Screen.OVERLAY -> Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, pkg)
        Screen.USAGE_ACCESS -> Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, pkg)
        Screen.ALL_FILES -> if (r) Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkg) else appInfo
        Screen.BATTERY -> Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        Screen.VPN -> Intent(Settings.ACTION_VPN_SETTINGS)
        Screen.DEVELOPER_OPTIONS -> Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
    }
    if (intent.resolveActivity(context.packageManager) != null) return intent
    // Some makers leave out a screen: the app's page, or Settings itself, still leads there.
    return if (pkg != null) appInfo else Intent(Settings.ACTION_SETTINGS)
}

private fun listenerOf(context: Context, packageName: String?): ComponentName? {
    if (packageName == null) return null
    val setting = try {
        Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
    } catch (_: SecurityException) {
        null
    }
    return setting.orEmpty().split(':').mapNotNull(ComponentName::unflattenFromString).firstOrNull { it.packageName == packageName }
}

private fun open(context: Context, intent: Intent) {
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_SETTINGS))
    }
}

/** An [ItemState] saved as the journal's own text, so that a card survives recreation. */
private val StateSaver = Saver<ItemState?, String>(
    save = { it?.let(JournalCodec::encodeState) ?: "" },
    restore = { if (it.isEmpty()) null else JournalCodec.decodeState(it) },
)
