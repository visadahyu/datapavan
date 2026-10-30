package org.visadahyu.datapavan.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
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
import org.visadahyu.datapavan.audit.DeviceCollector
import org.visadahyu.datapavan.audit.DeviceFacts
import org.visadahyu.datapavan.audit.FindingKind
import org.visadahyu.datapavan.audit.KnownCollectors
import org.visadahyu.datapavan.audit.Rules
import org.visadahyu.datapavan.audit.Severity
import org.visadahyu.datapavan.audit.SignatureVerdict
import org.visadahyu.datapavan.audit.SpecialAccess
import org.visadahyu.datapavan.audit.TrackerInfo
import org.visadahyu.datapavan.audit.TrackerScanner
import org.visadahyu.datapavan.datapack.DataPackRules
import org.visadahyu.datapavan.datapack.DataPackStore
import java.text.DateFormat
import java.time.LocalDate
import java.util.Calendar
import java.util.Date
import java.util.Locale

private typealias AppEntry = Pair<AppFacts, List<FindingKind>>

/** One complete audit of the phone. [trackers] is null until the tracker scan has finished. */
private class AuditResult(
    val device: DeviceFacts,
    val deviceFindings: List<FindingKind>,
    val apps: List<AppEntry>,
    /** The date of the data pack in use. */
    val dataDate: String,
    /** Each app's signature judged against the list of official certificates (ADR 0018), by package. */
    val signatures: Map<String, SignatureVerdict>,
    val trackers: Map<String, AppTrackers>? = null,
    val trackerInfo: Map<Int, TrackerInfo> = emptyMap(),
) {
    /** The same audit with the tracker scan's findings added. */
    fun withTrackers(found: Map<String, AppTrackers>, info: Map<Int, TrackerInfo>): AuditResult {
        val judged = apps.map { (app, _) -> app to Rules.forApp(app, found[app.packageName], signatures[app.packageName]) }
            .sortedWith(Rules.byUrgency)
        return AuditResult(device, deviceFindings, judged, dataDate, signatures, found, info)
    }
}

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
    val signatures = collected.mapNotNull { app -> signers.judge(app.packageName, app.signing, fresh)?.let { app.packageName to it } }.toMap()
    val judged = collected.map { it to Rules.forApp(it, signature = signatures[it.packageName]) }
    val labelled = collector.withLabels(judged.filter { (_, f) -> f.isNotEmpty() }.map { it.first }).associateBy { it.packageName }
    val apps = judged.map { (app, findings) -> (labelled[app.packageName] ?: app) to findings }.sortedWith(Rules.byUrgency)
    val now = Calendar.getInstance().let { it.get(Calendar.YEAR) * 100 + it.get(Calendar.MONTH) + 1 }
    AuditResult(device.await(), Rules.forDevice(device.await(), now), apps, data.active.date, signatures)
}

/** Second pass: the labels of all remaining apps, for the full list. */
private suspend fun AuditResult.withAllLabels(context: Context): AuditResult {
    val missing = apps.filter { it.first.label == null }.map { it.first }
    val labelled = AppCollector(context).withLabels(missing).associateBy { it.packageName }
    val all = apps.map { (app, findings) -> (labelled[app.packageName] ?: app) to findings }.sortedWith(Rules.byUrgency)
    return AuditResult(device, deviceFindings, all, dataDate, signatures, trackers, trackerInfo)
}

/** Root of the v0.1 audit UI: an overview of the phone and its apps, and a detail page per app. */
@Composable
internal fun DatapavanApp(engineVersion: String) {
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
        value = labelled.withTrackers(found, scanner.trackers)
        scanProgressFlow.value = null
    }
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    var reviewing by rememberSaveable { mutableStateOf(false) }
    var showingData by rememberSaveable { mutableStateOf(false) }

    Scaffold(modifier = Modifier.fillMaxSize()) { insets ->
        val audit = result
        val entry = audit?.apps?.firstOrNull { it.first.packageName == selected }
        when {
            audit == null -> Loading(insets)
            entry != null -> {
                BackHandler { selected = null }
                AppDetail(
                    entry, audit.trackers?.get(entry.first.packageName), audit.trackerInfo, audit.signatures[entry.first.packageName],
                    insets, onBack = { selected = null },
                )
            }
            reviewing -> {
                BackHandler { reviewing = false }
                StrictReview(audit.apps.map { it.first }, insets, onBack = { reviewing = false })
            }
            showingData -> {
                BackHandler { showingData = false }
                DataSources(insets, onBack = { showingData = false }, onImported = { dataVersion++ })
            }
            else -> Overview(
                audit, engineVersion, scanProgress, insets,
                onOpen = { selected = it }, onReview = { reviewing = true }, onData = { showingData = true },
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

@Composable
private fun Overview(audit: AuditResult, engineVersion: String, scanProgress: Pair<Int, Int>?, insets: PaddingValues,
    onOpen: (String) -> Unit, onReview: () -> Unit, onData: () -> Unit) {
    var showAll by rememberSaveable { mutableStateOf(false) }
    val flagged = audit.apps.filter { (_, findings) -> findings.any { it.severity != Severity.INFO } }
    val shown = if (showAll) audit.apps else flagged
    val context = LocalContext.current

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
            Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyLarge)
            if (DataPackRules.isStale(audit.dataDate, LocalDate.now())) {
                Spacer(Modifier.height(8.dp))
                StaleDataCard(audit.dataDate, onData)
            }
            Spacer(Modifier.height(16.dp))
            SectionTitle(R.string.section_device)
        }
        if (audit.deviceFindings.isEmpty()) {
            item { Text(stringResource(R.string.device_all_clear), style = MaterialTheme.typography.bodyMedium) }
        }
        items(audit.deviceFindings) { kind ->
            FindingCard(kind, company = null, action = deviceAction(kind)?.let { (label, intent) -> label to { context.startActivity(intent) } })
        }
        item { IntegrityLine(audit.device) }
        item { StrictReviewEntry(audit.apps.map { it.first }, onStart = onReview) }
        item {
            Spacer(Modifier.height(16.dp))
            SectionTitle(R.string.section_apps)
            Text(
                stringResource(R.string.apps_summary, audit.apps.size, flagged.size),
                style = MaterialTheme.typography.bodyMedium,
            )
            TrackerScanStatus(scanProgress, audit.trackers)
            TextButton(onClick = { showAll = !showAll }) {
                Text(stringResource(if (showAll) R.string.show_flagged_apps else R.string.show_all_apps))
            }
        }
        items(shown, key = { it.first.packageName }) { (app, findings) -> AppRow(app, findings) { onOpen(app.packageName) } }
        item {
            Spacer(Modifier.height(24.dp))
            TextButton(onClick = onData) { Text(stringResource(R.string.data_sources_title)) }
            Text(
                stringResource(R.string.engine_version, isolateLtr(engineVersion)),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
internal fun SectionTitle(@StringRes title: Int) {
    Text(stringResource(title), style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(vertical = 4.dp))
}

@Composable
private fun IntegrityLine(device: DeviceFacts) {
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
private fun AppRow(app: AppFacts, findings: List<FindingKind>, onClick: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)) {
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

@Composable
private fun AppDetail(entry: AppEntry, trackers: AppTrackers?, trackerInfo: Map<Int, TrackerInfo>, signature: SignatureVerdict?,
    insets: PaddingValues, onBack: () -> Unit) {
    val (app, findings) = entry
    val context = LocalContext.current
    val collector = remember { AppCollector(context) }
    val date = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }

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
            Text(stringResource(if (app.isSystem) R.string.detail_system_app else R.string.detail_user_app), style = MaterialTheme.typography.bodyMedium)
            Text(stringResource(if (app.enabled) R.string.detail_state_enabled else R.string.detail_state_disabled), style = MaterialTheme.typography.bodyMedium)
            Text(
                app.installer?.let { stringResource(R.string.detail_installer, isolateLtr(it)) } ?: stringResource(R.string.detail_installer_unknown),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(R.string.detail_dates, date.format(Date(app.firstInstall)), date.format(Date(app.lastUpdate))),
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(8.dp))
            SectionTitle(R.string.detail_findings)
            if (findings.isEmpty()) Text(stringResource(R.string.detail_no_findings), style = MaterialTheme.typography.bodyMedium)
        }
        items(findings) { kind -> FindingCard(kind, company = KnownCollectors.companyOf(app.packageName), action = null) }
        if (FindingKind.PREINSTALLED_COLLECTOR in findings) item { DisableGuide(app.packageName) }
        if (signature != null) item { SignatureSection(signature) }
        item { TrackerSection(trackers, trackerInfo) }
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
            OutlinedButton(onClick = {
                context.startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", app.packageName, null)))
            }) { Text(stringResource(R.string.open_app_settings)) }
        }
    }
}

@Composable
private fun FindingCard(kind: FindingKind, company: String?, action: Pair<Int, () -> Unit>?) {
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

private fun deviceAction(kind: FindingKind): Pair<Int, Intent>? = when (kind) {
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
private fun specialName(access: SpecialAccess) = when (access) {
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
}
