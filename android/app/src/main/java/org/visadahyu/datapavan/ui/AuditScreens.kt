package org.visadahyu.datapavan.ui

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AppCollector
import org.visadahyu.datapavan.audit.AppFacts
import org.visadahyu.datapavan.audit.AppSigners
import org.visadahyu.datapavan.audit.AppTrackers
import org.visadahyu.datapavan.audit.AttestationTrust
import org.visadahyu.datapavan.audit.Capability
import org.visadahyu.datapavan.audit.DeviceCollector
import org.visadahyu.datapavan.audit.DeviceFacts
import org.visadahyu.datapavan.audit.FindingKind
import org.visadahyu.datapavan.audit.FloorReason
import org.visadahyu.datapavan.audit.HealthAnswer
import org.visadahyu.datapavan.audit.InstallSource
import org.visadahyu.datapavan.audit.ItemState
import org.visadahyu.datapavan.audit.Journal
import org.visadahyu.datapavan.audit.JournalEntry
import org.visadahyu.datapavan.audit.JournalStore
import org.visadahyu.datapavan.audit.KeyFacts
import org.visadahyu.datapavan.audit.KnownCollectors
import org.visadahyu.datapavan.audit.Outcome
import org.visadahyu.datapavan.audit.OwnerNotes
import org.visadahyu.datapavan.audit.Owners
import org.visadahyu.datapavan.audit.Plan
import org.visadahyu.datapavan.audit.PlanInput
import org.visadahyu.datapavan.audit.PlanItem
import org.visadahyu.datapavan.audit.PlanLevel
import org.visadahyu.datapavan.audit.Rules
import org.visadahyu.datapavan.audit.SafetyFloor
import org.visadahyu.datapavan.audit.Sdk
import org.visadahyu.datapavan.audit.SdkList
import org.visadahyu.datapavan.audit.ServiceNeeds
import org.visadahyu.datapavan.audit.ServiceState
import org.visadahyu.datapavan.audit.Severity
import org.visadahyu.datapavan.audit.SignatureVerdict
import org.visadahyu.datapavan.audit.SpecialAccess
import org.visadahyu.datapavan.audit.SystemKeys
import org.visadahyu.datapavan.audit.TrackerInfo
import org.visadahyu.datapavan.audit.TrackerScanner
import org.visadahyu.datapavan.audit.UsageFacts
import org.visadahyu.datapavan.audit.UsageReader
import org.visadahyu.datapavan.datapack.DataPackRules
import org.visadahyu.datapavan.datapack.DataPackStore
import java.text.DateFormat
import java.time.LocalDate
import java.util.Calendar
import java.util.Date
import java.util.Locale

internal typealias AppEntry = Pair<AppFacts, List<FindingKind>>

/** One complete audit of the phone. [trackers] is null until the tracker scan has finished. */
internal class AuditResult(
    val device: DeviceFacts,
    val deviceFindings: List<FindingKind>,
    val apps: List<AppEntry>,
    /** The date of the data pack in use. */
    val dataDate: String,
    /** Each app's signature judged against the list of official certificates (ADR 0018), by package. */
    val signatures: Map<String, SignatureVerdict>,
    val trackers: Map<String, AppTrackers>? = null,
    val trackerInfo: Map<Int, TrackerInfo> = emptyMap(),
    /** SDKs from `data/sdks` whose code each app contains (ADR 0019), by package. */
    val sdks: Map<String, List<Sdk>> = emptyMap(),
    /** Capabilities from `data/sdk-needs` that cannot work now, by package (ADR 0021). */
    val unavailable: Map<String, List<Capability>> = emptyMap(),
    /** The services those capabilities need, read when the scan finished, and when. */
    val services: ServiceStates? = null,
    /** Who runs the services of each app's SDKs, by package, where there is something to say (ADR 0020). */
    val owners: Map<String, OwnerNotes> = emptyMap(),
    /** What the phone's system key says about each app, by package (ADR 0023). */
    val keys: Map<String, KeyFacts> = emptyMap(),
    /** Why the remediation plan's safety floor leaves an app alone, by package (ADR 0026). */
    val floor: Map<String, FloorReason> = emptyMap(),
) {
    /**
     * The same audit with the scan's findings added. The scan matched εxodus trackers and the SDKs of
     * [sdkList] in one pass; they are told apart by id, and only SDK code the app contains counts.
     */
    fun withTrackers(
        found: Map<String, AppTrackers>, info: Map<Int, TrackerInfo>, sdkList: SdkList, needs: ServiceNeeds, services: ServiceStates, owners: Owners,
    ): AuditResult {
        val exodus = found.mapValues { (_, t) ->
            t.copy(embedded = t.embedded.filter { it < SdkList.FIRST_ID }, referencedOnly = t.referencedOnly.filter { it < SdkList.FIRST_ID })
        }
        val sdks = found.mapValues { (_, t) -> t.embedded.mapNotNull(sdkList::byId) }.filterValues { it.isNotEmpty() }
        val unavailable = found.mapValues { (_, t) ->
            t.embedded.mapNotNull(needs::byId).filter { needs.unavailable(it, services.states) }
        }.filterValues { it.isNotEmpty() }
        val notes = apps.mapNotNull { (app, _) ->
            val operators = found[app.packageName]?.embedded.orEmpty().mapNotNull(owners::byId)
            owners.notes(owners.publisher(app.packageName, app.signing), operators, dataDate)
                .takeIf { it.sameGroup.isNotEmpty() || it.shutDown.isNotEmpty() }?.let { app.packageName to it }
        }.toMap()
        val judged = apps.map { (app, _) ->
            val categories = sdks[app.packageName].orEmpty().map { it.category }.toSet()
            app to Rules.forApp(app, exodus[app.packageName], signatures[app.packageName], categories, keys[app.packageName])
        }.sortedWith(Rules.byUrgency)
        return AuditResult(device, deviceFindings, judged, dataDate, signatures, exodus, info, sdks, unavailable, services, notes, keys, floor)
    }
}

/** The state of each system service (ADR 0021), as read at [checkedAt], with the services' names. */
internal class ServiceStates(val states: Map<String, ServiceState>, val names: Map<String, String>, val checkedAt: Long)

/**
 * Device and app checks run in parallel; the hardware key attestation alone can take a moment.
 * Only the apps with findings get their labels here, so the overview appears quickly.
 */
private suspend fun runAudit(context: Context): AuditResult = coroutineScope {
    val device = async(Dispatchers.IO) { DeviceCollector(context).collect() }
    val collector = AppCollector(context)
    val data = DataPackStore.get(context)
    val signers = AppSigners.parse(data.text(AppSigners.APPS_PATH).orEmpty(), data.text(AppSigners.SIGNERS_PATH).orEmpty())
    val fresh = !DataPackRules.isStale(data.active.date, LocalDate.now())
    val collected = collector.collect()
    // A debug build is this app's own test build: its debug key says nothing about a fake, and the
    // self-check calls it a test build (ADR 0024). A release build is judged like any other app.
    val testBuild = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
    val signatures = collected
        .filterNot { testBuild && it.packageName == context.packageName }
        .mapNotNull { app -> signers.judge(app.packageName, app.signing, fresh)?.let { app.packageName to it } }
        .toMap()
    // The key that signs the package `android` is the phone's system key (ADR 0023).
    val systemKeys = SystemKeys.parse(data.text(SystemKeys.PATH).orEmpty())
    val platform = collected.firstOrNull { it.packageName == PLATFORM_PACKAGE }?.signing
    val keys = collected.associate { it.packageName to systemKeys.facts(it, platform, Build.MANUFACTURER.orEmpty()) }
    val judged = collected.map { it to Rules.forApp(it, signature = signatures[it.packageName], keys = keys[it.packageName]) }
    val labelled = collector.withLabels(judged.filter { (_, f) -> f.isNotEmpty() }.map { it.first }).associateBy { it.packageName }
    val apps = judged.map { (app, findings) -> (labelled[app.packageName] ?: app) to findings }.sortedWith(Rules.byUrgency)
    val now = Calendar.getInstance().let { it.get(Calendar.YEAR) * 100 + it.get(Calendar.MONTH) + 1 }
    // The safety floor: what the phone itself shows it needs, then the deny-list by function (ADR 0026).
    val denyList = SafetyFloor.parse(data.text(SafetyFloor.PATH).orEmpty())
    val computed = collector.protectedApps(collected)
    val floor = collected.mapNotNull { app ->
        (computed[app.packageName] ?: denyList.reason(app.packageName, Build.MANUFACTURER.orEmpty()))?.let { app.packageName to it }
    }.toMap()
    AuditResult(
        device.await(), Rules.forDevice(device.await(), now, systemKeys.untrusted(platform)), apps, data.active.date, signatures, keys = keys, floor = floor,
    )
}

private const val PLATFORM_PACKAGE = "android"

/** The remediation plan's input from one audit and, when granted, usage access (ADR 0026). */
private fun planInput(audit: AuditResult, usage: UsageState, ownPackage: String) = PlanInput(
    audit.deviceFindings, audit.apps, (usage as? UsageState.Ready)?.facts, audit.trackers, audit.trackerInfo, audit.floor, ownPackage,
)

/** What a plan item, or a journal entry, concerned when the audit ran. */
private fun AuditResult.stateOf(packageName: String?): ItemState =
    if (packageName == null) ItemState.of(device) else ItemState.of(apps.firstOrNull { it.first.packageName == packageName }?.first)

private fun AuditResult.stateOf(item: PlanItem): ItemState = stateOf(item.app?.packageName)

private fun AuditResult.stateOf(entry: JournalEntry): ItemState = stateOf(entry.packageName)

/** Whether something the user changed through the plan has come back, judged on each item's latest entry. */
private fun AuditResult.cameBack(journal: Journal): Boolean =
    journal.entries.groupBy { it.key }.values.map { list -> list.maxBy { it.at } }.filter { it.outcome == Outcome.CHANGED }
        .any { entry -> entry.changes.any { Journal.cameBack(it, entry.after, stateOf(entry)) } }

/** Second pass: the labels of all remaining apps, for the full list. */
private suspend fun AuditResult.withAllLabels(context: Context): AuditResult {
    val missing = apps.filter { it.first.label == null }.map { it.first }
    val labelled = AppCollector(context).withLabels(missing).associateBy { it.packageName }
    val all = apps.map { (app, findings) -> (labelled[app.packageName] ?: app) to findings }.sortedWith(Rules.byUrgency)
    return AuditResult(device, deviceFindings, all, dataDate, signatures, trackers, trackerInfo, sdks, unavailable, services, owners, keys, floor)
}

/**
 * Root of the v0.1 UI (ADR 0027): four destinations in a navigation bar, each app's page, the plan,
 * the reviews and checks, and the settings with their pages. [theme] and [onTheme] are the settings'
 * appearance, which the activity applies.
 */
@Composable
internal fun DatapavanApp(
    engineVersion: String,
    usageUntil: Long? = null,
    usageDays: Int? = null,
    theme: ThemeMode = ThemeMode.SYSTEM,
    onTheme: (ThemeMode) -> Unit = {},
    launch: LaunchTarget? = null,
    onLaunched: () -> Unit = {},
) {
    val context = LocalContext.current.applicationContext
    // The scan reports progress from background threads; a StateFlow carries it safely to the UI.
    val scanProgressFlow = remember { MutableStateFlow<Pair<Int, Int>?>(null) }
    val scanProgress by scanProgressFlow.collectAsState()
    // Raised after a data pack is imported, which runs the audit again with the new data.
    var dataVersion by remember { mutableIntStateOf(0) }
    val result by produceState<AuditResult?>(initialValue = null, dataVersion) {
        val first = withContext(Dispatchers.Default) { runAudit(context) }
        value = first
        val labelled = withContext(Dispatchers.Default) { first.withAllLabels(context) }
        value = labelled
        val scanner = TrackerScanner(context)
        scanProgressFlow.value = 0 to labelled.apps.size
        val found = withContext(Dispatchers.Default) {
            scanner.scan(labelled.apps.map { it.first }) { done, total -> scanProgressFlow.value = done to total }
        }
        // Read right after the scan, so that each label says when its service was checked.
        val states = withContext(Dispatchers.Default) {
            ServiceStates(scanner.needs.read(context), scanner.needs.services.mapValues { it.value.name }, System.currentTimeMillis())
        }
        value = labelled.withTrackers(found, scanner.trackers, scanner.sdkList, scanner.needs, states, scanner.owners)
        scanProgressFlow.value = null
    }
    // The app being checked (ADR 0025); while a check runs, nothing else may query Android's counts.
    var checking by rememberSaveable { mutableStateOf<String?>(null) }
    // Usage access is granted in Settings, so it is read again whenever the user comes back (ADR 0022).
    var usageVersion by remember { mutableIntStateOf(0) }
    LifecycleResumeEffect(Unit) {
        if (checking == null) usageVersion++
        onPauseOrDispose { }
    }
    val usage by produceState<UsageState>(initialValue = UsageState.Reading, usageVersion) {
        val periods = (listOfNotNull(usageDays) + UsageFacts.PERIODS).distinct()
        value = withContext(Dispatchers.IO) { UsageReader(context).read(usageUntil ?: System.currentTimeMillis(), periods) }
            ?.let(UsageState::Ready) ?: UsageState.NoAccess
    }
    var days by rememberSaveable { mutableIntStateOf(usageDays ?: UsageFacts.PERIODS.first()) }
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    var reviewing by rememberSaveable { mutableStateOf(false) }
    var tab by rememberSaveable { mutableStateOf(Destination.SUMMARY) }
    var settingsOpen by rememberSaveable { mutableStateOf(false) }
    var settingsPage by rememberSaveable { mutableStateOf<SettingsPage?>(null) }
    var planning by rememberSaveable { mutableStateOf(false) }
    var journaling by rememberSaveable { mutableStateOf(false) }
    // The remediation plan's journal (ADR 0026), small enough to read and write in one go.
    val journalStore = remember { JournalStore(context) }
    var journal by remember { mutableStateOf(journalStore.load()) }
    val saveJournal: (Journal) -> Unit = {
        journal = it
        journalStore.save(it)
    }
    // A launcher shortcut opens its screen in place of whatever was open; back then leads to the
    // summary, as from the plan's own entry. The plan shows once the audit has loaded.
    LaunchedEffect(launch) {
        val target = launch ?: return@LaunchedEffect
        if (checking != null) usageVersion++
        checking = null
        selected = null
        reviewing = false
        journaling = false
        settingsOpen = false
        settingsPage = null
        planning = target == LaunchTarget.PLAN
        tab = when (target) {
            LaunchTarget.PLAN -> Destination.SUMMARY
            LaunchTarget.APPS -> Destination.APPS
            LaunchTarget.NETWORK -> Destination.NETWORK
        }
        onLaunched()
    }
    val audit = result
    val entry = audit?.apps?.firstOrNull { it.first.packageName == selected }
    val checked = audit?.apps?.firstOrNull { it.first.packageName == checking }?.first
    val topLevel = audit != null && checked == null && entry == null && !reviewing && !planning && !journaling && !settingsOpen && settingsPage == null

    Scaffold(
        // Stable names for the emulator scripts, which cannot read labels in every language.
        modifier = Modifier.fillMaxSize().semantics { testTagsAsResourceId = true },
        bottomBar = { if (topLevel) NavigationBar(tab) { tab = it } },
    ) { insets ->
        when {
            audit == null -> Loading(insets)
            checked != null -> {
                val close: () -> Unit = {
                    checking = null
                    usageVersion++
                }
                BackHandler(onBack = close)
                GuidedCheckScreen(
                    checked,
                    carriesOthers = checked.packageName in audit.signatures,
                    sharedUid = audit.apps.any { it.first.uid == checked.uid && it.first.packageName != checked.packageName },
                    insets = insets,
                    onBack = close,
                )
            }
            entry != null -> {
                BackHandler { selected = null }
                val app = entry.first
                val sharedWith = audit.apps.map { it.first }.filter { it.uid == app.uid && it.packageName != app.packageName }
                    .map { it.label ?: it.packageName }
                val inPlan = Plan.items(planInput(audit, usage, context.packageName), PlanLevel.STRICT).items.any { it.app?.packageName == app.packageName }
                AppDetail(
                    entry, audit.trackers?.get(app.packageName), audit.trackerInfo, audit.signatures[app.packageName],
                    audit.sdks[app.packageName].orEmpty(), audit.unavailable[app.packageName].orEmpty(),
                    audit.services, audit.owners[app.packageName], audit.keys[app.packageName],
                    installerLabel = audit.apps.firstOrNull { it.first.packageName == app.installer }?.first?.label,
                    insets = insets, onBack = { selected = null },
                    plain = {
                        PlainCard(app, audit.trackers?.get(app.packageName), audit.trackerInfo, usage, onPlan = if (inPlan) ({ planning = true }) else null)
                    },
                    usage = {
                        AppUsageSection(
                            app, usage, days, sharedWith, app.isVpnApp || app.packageName in audit.signatures,
                            onDays = { days = it }, onCheck = { checking = app.packageName },
                        )
                    },
                )
            }
            reviewing -> {
                BackHandler { reviewing = false }
                StrictReview(audit.apps.map { it.first }, insets, onBack = { reviewing = false })
            }
            planning -> {
                // Done runs the audit again, so that the overview shows what changed.
                val done: () -> Unit = {
                    planning = false
                    dataVersion++
                }
                BackHandler { planning = false }
                PlanScreen(
                    planInput(audit, usage, context.packageName), usage == UsageState.NoAccess, journal, audit::stateOf, insets,
                    onJournal = saveJournal, onBack = { planning = false }, onDone = done,
                )
            }
            journaling -> {
                BackHandler { journaling = false }
                JournalScreen(
                    journal, audit.apps.associate { (app, _) -> app.packageName to (app.label ?: app.packageName) }, audit::stateOf, insets,
                    onBack = { journaling = false },
                    onDelete = {
                        journalStore.delete()
                        journal = Journal()
                    },
                )
            }
            settingsPage != null -> {
                val back: () -> Unit = { settingsPage = null }
                BackHandler(onBack = back)
                when (settingsPage) {
                    SettingsPage.DATA_SOURCES -> DataSources(insets, onBack = back, onImported = { dataVersion++ })
                    SettingsPage.OWN_COPY -> {
                        val own = audit.apps.firstOrNull { it.first.packageName == context.packageName }?.first
                        OwnCopyScreen(own?.signing, audit.signatures[context.packageName], insets, onBack = back)
                    }
                    SettingsPage.PRIVACY -> TextPage(R.string.privacy_title, privacyParagraphs(), insets, back)
                    SettingsPage.LICENCES -> LicencesScreen(insets, back)
                    SettingsPage.ABOUT, null -> TextPage(R.string.about_title, aboutParagraphs(engineVersion), insets, back)
                }
            }
            settingsOpen -> {
                BackHandler { settingsOpen = false }
                SettingsScreen(theme, insets, onTheme, onPage = { settingsPage = it }, onBack = { settingsOpen = false })
            }
            else -> Destinations(
                tab, audit, scanProgress, usage, insets,
                onTab = { tab = it }, onOpen = { selected = it }, onReview = { reviewing = true },
                onData = { settingsPage = SettingsPage.DATA_SOURCES }, onSettings = { settingsOpen = true },
                network = { UsageOverview(usage, days, audit.apps.map { it.first }, onDays = { days = it }, onOpen = { selected = it }) },
                plan = {
                    val input = planInput(audit, usage, context.packageName)
                    val level = journal.sessions.lastOrNull()?.level ?: PlanLevel.LIGHT
                    val first = remember(input, journal) { Plan.session(Plan.items(input, level).items, journal.kept(), audit::stateOf).firstOrNull() }
                    PlanEntry(
                        first, journal.healthCheckDue(System.currentTimeMillis()), audit.cameBack(journal), journal.entries.isNotEmpty(),
                        onStart = { planning = true },
                        onJournal = { journaling = true },
                        onAnswer = { answer ->
                            val due = journal.healthCheckDue(System.currentTimeMillis()) ?: return@PlanEntry
                            saveJournal(journal.answered(due.start, answer))
                            if (answer == HealthAnswer.SOMETHING_WRONG) journaling = true
                        },
                    )
                },
            )
        }
    }
}

@Composable
private fun Loading(insets: PaddingValues) {
    Column(
        modifier = Modifier.fillMaxSize().padding(insets).padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.audit_loading), style = MaterialTheme.typography.bodyLarge)
    }
}

/** Where an app came from, in one line (audit/Stores.kt); names and package names are isolated. */
@Composable
private fun installLine(source: InstallSource): String = when (source) {
    InstallSource.Preinstalled -> stringResource(R.string.detail_system_app)
    is InstallSource.PreinstalledWith -> stringResource(R.string.detail_system_app_source, isolateLtr(source.source))
    is InstallSource.FromStore -> stringResource(R.string.detail_installed_from, isolateLtr(source.store))
    is InstallSource.ByApp -> source.label?.let { stringResource(R.string.detail_installed_by_app, isolate(it), isolateLtr(source.packageName)) }
        ?: stringResource(R.string.detail_installer, isolateLtr(source.packageName))
    InstallSource.Unknown -> stringResource(R.string.detail_installer_unknown)
}

/** The items of a list joined as the user's language writes them, for example with "،" in Persian. */
@Composable
internal fun List<String>.joinedForUser(): String = joinToString(stringResource(R.string.list_separator))

@Composable
internal fun SectionTitle(@StringRes title: Int) {
    Text(stringResource(title), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(vertical = 4.dp))
}

@Composable
internal fun IntegrityLine(device: DeviceFacts) {
    val integrity = device.integrity
    val text = when {
        integrity == null -> stringResource(R.string.device_integrity_unavailable)
        integrity.deviceLocked == true && integrity.verifiedBoot == 0 && integrity.securityLevel > 0 &&
            integrity.trust == AttestationTrust.GOOGLE_ROOT -> stringResource(R.string.device_integrity_ok)
        else -> null
    }
    val patch = integrity?.osPatchLevel?.let { String.format(Locale.ROOT, "%04d-%02d", it / 100, it % 100) }
    Column(Modifier.padding(vertical = 4.dp)) {
        text?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
        patch?.let { Text(stringResource(R.string.device_patch, isolateLtr(it)), style = MaterialTheme.typography.bodyMedium) }
    }
}

@Composable
internal fun AppRow(app: AppFacts, findings: List<FindingKind>, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag("app-row").clickable(onClick = onClick)) {
        Column(Modifier.padding(12.dp)) {
            Text(app.label ?: app.packageName, style = MaterialTheme.typography.titleMedium)
            Text(isolateLtr(app.packageName), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            findings.firstOrNull()?.let { first ->
                Spacer(Modifier.height(6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SeverityDot(first.severity)
                    Spacer(Modifier.size(8.dp))
                    val more = findings.size - 1
                    Text(
                        if (more > 0) stringResource(R.string.finding_and_more, stringResource(title(first)), more) else stringResource(title(first)),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

/**
 * One app's page (ADR 0027, point 2): the plain-language card, then sections that open and close, the
 * findings open. [plain] is the card, [usage] the network section with the guided check.
 */
@Composable
private fun AppDetail(entry: AppEntry, trackers: AppTrackers?, trackerInfo: Map<Int, TrackerInfo>, signature: SignatureVerdict?,
    sdks: List<Sdk>, unavailable: List<Capability>, services: ServiceStates?, owners: OwnerNotes?, keys: KeyFacts?, installerLabel: String?,
    insets: PaddingValues, onBack: () -> Unit, plain: @Composable () -> Unit, usage: @Composable () -> Unit) {
    val (app, findings) = entry
    val context = LocalContext.current
    val collector = remember { AppCollector(context) }
    val date = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }
    var open by rememberSaveable { mutableStateOf(listOf(DetailGroup.FINDINGS.name)) }
    val toggle: (DetailGroup) -> Unit = { group -> open = if (group.name in open) open - group.name else open + group.name }
    val showKeys = keys != null && (keys.systemKey || keys.runsAsSystem || keys.untrusted != null)

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(app.label ?: app.packageName, style = MaterialTheme.typography.headlineSmall)
            Text(isolateLtr(app.packageName), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
            Text(installLine(InstallSource.of(app.isSystem, app.installer, installerLabel)), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(if (app.enabled) R.string.detail_state_enabled else R.string.detail_state_disabled), style = MaterialTheme.typography.bodyMedium)
            Text(
                stringResource(R.string.detail_dates, date.format(Date(app.firstInstall)), date.format(Date(app.lastUpdate))),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        item { plain() }
        item { GroupHeader(DetailGroup.FINDINGS, DetailGroup.FINDINGS.name in open, toggle) }
        if (DetailGroup.FINDINGS.name in open) {
            if (findings.isEmpty()) item { Text(stringResource(R.string.detail_no_findings), style = MaterialTheme.typography.bodyMedium) }
            items(findings) { kind -> FindingCard(kind, company = KnownCollectors.companyOf(app.packageName), action = null) }
            if (FindingKind.PREINSTALLED_COLLECTOR in findings) item { DisableGuide(app.packageName) }
        }
        item { GroupHeader(DetailGroup.ACCESS, DetailGroup.ACCESS.name in open, toggle) }
        if (DetailGroup.ACCESS.name in open) {
            item {
                SectionTitle(R.string.detail_special)
                Text(
                    app.special.sortedBy { it.ordinal }.map { stringResource(specialName(it)) }.ifEmpty { listOf(stringResource(R.string.detail_none)) }.joinToString("\n"),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(8.dp))
                SectionTitle(R.string.detail_permissions)
                Text(
                    app.grantedDangerous.map { collector.permissionLabel(it) }.distinct().ifEmpty { listOf(stringResource(R.string.detail_none)) }.joinToString("\n"),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(16.dp))
                OutlinedButton(onClick = { context.startActivity(appSettings(app.packageName)) }) { Text(stringResource(R.string.open_app_settings)) }
            }
        }
        item { GroupHeader(DetailGroup.TRACKERS, DetailGroup.TRACKERS.name in open, toggle) }
        if (DetailGroup.TRACKERS.name in open) {
            if (sdks.isNotEmpty()) item { SdkSection(sdks, accessibilityOn = SpecialAccess.ACCESSIBILITY in app.special) }
            item { TrackerSection(trackers, trackerInfo) }
            if (owners != null) item { OwnerSection(owners) }
            if (unavailable.isNotEmpty() && services != null) {
                item { ServiceNeedsSection(unavailable, services.states, services.names, services.checkedAt) }
            }
        }
        item { GroupHeader(DetailGroup.NETWORK, DetailGroup.NETWORK.name in open, toggle) }
        if (DetailGroup.NETWORK.name in open) item { usage() }
        if (signature != null || showKeys) {
            item { GroupHeader(DetailGroup.SIGNATURE, DetailGroup.SIGNATURE.name in open, toggle) }
            if (DetailGroup.SIGNATURE.name in open) {
                if (signature != null) item { SignatureSection(signature) }
                if (showKeys && keys != null) item { SystemKeySection(keys, Build.MANUFACTURER.orEmpty()) }
            }
        }
    }
}

/** The sections of an app's page. */
private enum class DetailGroup(@StringRes val title: Int) {
    FINDINGS(R.string.detail_findings),
    ACCESS(R.string.detail_group_access),
    TRACKERS(R.string.detail_group_trackers),
    NETWORK(R.string.detail_group_network),
    SIGNATURE(R.string.detail_group_signature),
}

/** A section's header, which opens and closes it; screen readers hear its state. */
@Composable
private fun GroupHeader(group: DetailGroup, open: Boolean, onToggle: (DetailGroup) -> Unit) {
    val state = stringResource(if (open) R.string.section_open else R.string.section_closed)
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
            .clickable(role = Role.Button) { onToggle(group) }
            .semantics { stateDescription = state }
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(stringResource(group.title), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
        Icon(painterResource(if (open) R.drawable.ic_expand_less else R.drawable.ic_expand_more), contentDescription = null)
    }
}

internal fun appSettings(packageName: String) =
    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null))

@Composable
internal fun FindingCard(kind: FindingKind, company: String?, action: Pair<Int, () -> Unit>?) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityDot(kind.severity)
                Spacer(Modifier.size(8.dp))
                Text(stringResource(title(kind)), style = MaterialTheme.typography.titleSmall)
            }
            Spacer(Modifier.height(4.dp))
            Text(stringResource(body(kind), company.orEmpty()), style = MaterialTheme.typography.bodyMedium)
            action?.let { (label, onClick) -> TextButton(onClick = onClick) { Text(stringResource(label)) } }
        }
    }
}

/**
 * How to turn off a preinstalled data collector. Disabling is enough when the maker allows it;
 * otherwise a computer can remove the app for the current user, which a factory reset or the
 * restore command undoes.
 */
@Composable
private fun DisableGuide(packageName: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.guide_title), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.guide_steps), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            SelectionContainer {
                Column {
                    Text(stringResource(R.string.guide_remove), style = MaterialTheme.typography.labelMedium)
                    Text(isolateLtr("adb shell pm uninstall -k --user 0 $packageName"), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(4.dp))
                    Text(stringResource(R.string.guide_restore), style = MaterialTheme.typography.labelMedium)
                    Text(isolateLtr("adb shell cmd package install-existing $packageName"), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

/** Colour is never the only signal: the severity is also spoken and written next to the dot. */
@Composable
private fun SeverityDot(severity: Severity) {
    val color = when (severity) {
        Severity.HIGH -> MaterialTheme.colorScheme.error
        Severity.MEDIUM -> MaterialTheme.colorScheme.tertiary
        Severity.LOW -> MaterialTheme.colorScheme.primary
        Severity.INFO -> MaterialTheme.colorScheme.outline
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(10.dp).background(color, CircleShape))
        Spacer(Modifier.size(6.dp))
        Text(stringResource(severityName(severity)), style = MaterialTheme.typography.labelMedium, color = if (severity == Severity.INFO) Color.Unspecified else color)
    }
}

internal fun deviceAction(kind: FindingKind): Pair<Int, Intent>? = when (kind) {
    FindingKind.USB_DEBUGGING, FindingKind.WIRELESS_DEBUGGING -> R.string.action_developer_settings to Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
    FindingKind.USER_CERTIFICATE_AUTHORITY -> R.string.action_security_settings to Intent(Settings.ACTION_SECURITY_SETTINGS)
    else -> null
}

@StringRes
private fun severityName(severity: Severity) = when (severity) {
    Severity.HIGH -> R.string.severity_high
    Severity.MEDIUM -> R.string.severity_medium
    Severity.LOW -> R.string.severity_low
    Severity.INFO -> R.string.severity_info
}

@StringRes
internal fun specialName(access: SpecialAccess) = when (access) {
    SpecialAccess.ACCESSIBILITY -> R.string.special_accessibility
    SpecialAccess.NOTIFICATION_LISTENER -> R.string.special_notification_listener
    SpecialAccess.DEVICE_ADMIN -> R.string.special_device_admin
    SpecialAccess.OVERLAY -> R.string.special_overlay
    SpecialAccess.USAGE_ACCESS -> R.string.special_usage_access
    SpecialAccess.INSTALL_UNKNOWN_APPS -> R.string.special_install_unknown_apps
    SpecialAccess.ALL_FILES -> R.string.special_all_files
    SpecialAccess.BATTERY_EXEMPT -> R.string.special_battery_exempt
}

@StringRes
private fun title(kind: FindingKind) = when (kind) {
    FindingKind.VPN_WITH_REMOTE_CONTROL -> R.string.finding_vpn_remote_control_title
    FindingKind.REMOTE_CONTROL -> R.string.finding_remote_control_title
    FindingKind.PREINSTALLED_COLLECTOR -> R.string.finding_preinstalled_collector_title
    FindingKind.INSTALLS_APPS -> R.string.finding_installs_apps_title
    FindingKind.SENSORS -> R.string.finding_sensors_title
    FindingKind.TRACKERS -> R.string.finding_trackers_title
    FindingKind.UNKNOWN_SOURCE -> R.string.finding_unknown_source_title
    FindingKind.MODIFIED_APP -> R.string.finding_modified_app_title
    FindingKind.TRAFFIC_SHARING -> R.string.finding_traffic_sharing_title
    FindingKind.REMOTE_SUPPORT -> R.string.finding_remote_support_title
    FindingKind.SCREEN_RECORDING -> R.string.finding_screen_recording_title
    FindingKind.SIGNER_UNKNOWN -> R.string.finding_signer_unknown_title
    FindingKind.USER_CERTIFICATE_AUTHORITY -> R.string.finding_user_ca_title
    FindingKind.WIRELESS_DEBUGGING -> R.string.finding_wireless_debugging_title
    FindingKind.BOOTLOADER_UNLOCKED -> R.string.finding_bootloader_unlocked_title
    FindingKind.BOOT_NOT_VERIFIED -> R.string.finding_boot_not_verified_title
    FindingKind.USB_DEBUGGING -> R.string.finding_usb_debugging_title
    FindingKind.OLD_SECURITY_PATCH -> R.string.finding_old_patch_title
    FindingKind.INTEGRITY_SOFTWARE_ONLY -> R.string.finding_software_only_title
    FindingKind.ATTESTATION_REVOKED -> R.string.finding_attestation_revoked_title
    FindingKind.ATTESTATION_UNCONFIRMED -> R.string.finding_attestation_unconfirmed_title
    FindingKind.VPN_ACTIVE -> R.string.finding_vpn_active_title
    FindingKind.UNTRUSTED_SYSTEM_KEY -> R.string.finding_untrusted_system_key_title
    FindingKind.LEAKED_KEY_FROM_STORE -> R.string.finding_leaked_key_from_store_title
    FindingKind.SYSTEM_KEY_PUBLIC -> R.string.finding_system_key_public_title
    FindingKind.SYSTEM_KEY_LEAKED -> R.string.finding_system_key_leaked_title
    FindingKind.SYSTEM_KEY_DEVELOPMENT -> R.string.finding_system_key_development_title
}

@StringRes
private fun body(kind: FindingKind) = when (kind) {
    FindingKind.VPN_WITH_REMOTE_CONTROL -> R.string.finding_vpn_remote_control_body
    FindingKind.REMOTE_CONTROL -> R.string.finding_remote_control_body
    FindingKind.PREINSTALLED_COLLECTOR -> R.string.finding_preinstalled_collector_body
    FindingKind.INSTALLS_APPS -> R.string.finding_installs_apps_body
    FindingKind.SENSORS -> R.string.finding_sensors_body
    FindingKind.TRACKERS -> R.string.finding_trackers_body
    FindingKind.UNKNOWN_SOURCE -> R.string.finding_unknown_source_body
    FindingKind.MODIFIED_APP -> R.string.finding_modified_app_body
    FindingKind.TRAFFIC_SHARING -> R.string.finding_traffic_sharing_body
    FindingKind.REMOTE_SUPPORT -> R.string.finding_remote_support_body
    FindingKind.SCREEN_RECORDING -> R.string.finding_screen_recording_body
    FindingKind.SIGNER_UNKNOWN -> R.string.finding_signer_unknown_body
    FindingKind.USER_CERTIFICATE_AUTHORITY -> R.string.finding_user_ca_body
    FindingKind.WIRELESS_DEBUGGING -> R.string.finding_wireless_debugging_body
    FindingKind.BOOTLOADER_UNLOCKED -> R.string.finding_bootloader_unlocked_body
    FindingKind.BOOT_NOT_VERIFIED -> R.string.finding_boot_not_verified_body
    FindingKind.USB_DEBUGGING -> R.string.finding_usb_debugging_body
    FindingKind.OLD_SECURITY_PATCH -> R.string.finding_old_patch_body
    FindingKind.INTEGRITY_SOFTWARE_ONLY -> R.string.finding_software_only_body
    FindingKind.ATTESTATION_REVOKED -> R.string.finding_attestation_revoked_body
    FindingKind.ATTESTATION_UNCONFIRMED -> R.string.finding_attestation_unconfirmed_body
    FindingKind.VPN_ACTIVE -> R.string.finding_vpn_active_body
    FindingKind.UNTRUSTED_SYSTEM_KEY -> R.string.finding_untrusted_system_key_body
    FindingKind.LEAKED_KEY_FROM_STORE -> R.string.finding_leaked_key_from_store_body
    FindingKind.SYSTEM_KEY_PUBLIC -> R.string.finding_system_key_public_body
    FindingKind.SYSTEM_KEY_LEAKED -> R.string.finding_system_key_leaked_body
    FindingKind.SYSTEM_KEY_DEVELOPMENT -> R.string.finding_system_key_development_body
}
