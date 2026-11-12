package org.visadahyu.datapavan.watch.ui

import android.text.BidiFormatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.audit.SignatureVerdict
import org.visadahyu.datapavan.watch.PrivateDns
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.chain.ToolSearch
import java.util.Locale

/** An app the user may send through the tool: its package name and the name the user knows. */
internal data class AppChoice(val packageName: String, val label: String)

/** The user's chain as the screen shows it (W6). */
internal data class ChainView(
    /** What Watch found of the user's tool; null while it looks. */
    val search: ToolSearch?,
    val on: Boolean,
    val allApps: Boolean,
    val apps: Set<String>,
    val logDestinations: Boolean,
    /** The user name and password Watch offers for the tool's proxy, when the tool takes one. */
    val user: String?,
    val password: String?,
    /** The apps the user can choose from, loaded once the user asks to choose. */
    val choices: List<AppChoice>,
    /** What the found tool's signing key says about this copy (ADR 0018), when anything can be said. */
    val key: SignatureVerdict? = null,
    /** The name of the tool the chain last went through, for its switch while that tool does not answer. */
    val chainedName: String? = null,
)

/** What the user can change in the chain. */
internal class ChainActions(
    val onSearch: () -> Unit,
    val onOn: (Boolean) -> Unit,
    val onAllApps: (Boolean) -> Unit,
    val onApp: (String, Boolean) -> Unit,
    val onLogDestinations: (Boolean) -> Unit,
    val onCopyPassword: () -> Unit,
    val onPrivateDnsSettings: () -> Unit,
)

/**
 * Watch beside the user's circumvention tool (W6, docs/VPN.md): which tool it found, the switch that
 * sends apps through it, which apps, the password that keeps other apps off its proxy, and whether
 * chained destinations are logged. A tool's name keeps its own direction inside a right-to-left sentence.
 */
@Composable
internal fun ChainSection(view: ChainView, privateDns: PrivateDns?, actions: ChainActions) {
    val bidi = BidiFormatter.getInstance()
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.chain_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        when (val search = view.search) {
            null -> Text(stringResource(R.string.chain_searching), style = MaterialTheme.typography.bodyMedium)
            ToolSearch.NoneInstalled -> {
                Text(stringResource(R.string.chain_none), style = MaterialTheme.typography.bodyMedium)
                OutlinedButton(onClick = actions.onSearch) { Text(stringResource(R.string.chain_search_again)) }
            }
            is ToolSearch.NotAnswering -> {
                val names = search.installed.joinToString(", ") { bidi.unicodeWrap(it.name) }
                Text(
                    stringResource(if (view.on) R.string.chain_waiting else R.string.chain_not_answering, names),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (view.on) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onBackground,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                OutlinedButton(onClick = actions.onSearch) { Text(stringResource(R.string.chain_search_again)) }
            }
            is ToolSearch.Answering -> Answering(search, view, privateDns, actions)
        }
        // A chain that is on stays one tap from off, whatever the search says now: while the tool does
        // not answer, the apps sent through it wait, and the user must be able to let them go directly
        // (CI, 2026-11-12: without this switch, only turning Watch off could end the wait).
        if (view.on && view.search !is ToolSearch.Answering) {
            val tool = bidi.unicodeWrap(view.chainedName ?: "")
            LabelledSwitch(stringResource(R.string.chain_switch, tool), checked = true, onChange = actions.onOn)
        }
    }
}

@Composable
private fun Answering(search: ToolSearch.Answering, view: ChainView, privateDns: PrivateDns?, actions: ChainActions) {
    val tool = BidiFormatter.getInstance().unicodeWrap(search.found.tool.name)
    Text(stringResource(R.string.chain_found, tool, search.found.port), style = MaterialTheme.typography.bodyMedium)
    view.key?.let { KeyVerdict(it) }
    LabelledSwitch(stringResource(R.string.chain_switch, tool), view.on, actions.onOn)
    if (search.found.tool.udp == false) {
        Text(stringResource(R.string.chain_no_udp, tool), style = MaterialTheme.typography.bodyMedium)
    }
    if (privateDns is PrivateDns.Strict) {
        // What leaves past the tool, to whom, and what the network sees; then where to change it.
        Text(
            stringResource(R.string.chain_private_dns, BidiFormatter.getInstance().unicodeWrap(privateDns.host), tool),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
        Text(stringResource(R.string.chain_private_dns_where), style = MaterialTheme.typography.bodyMedium)
        OutlinedButton(onClick = actions.onPrivateDnsSettings) { Text(stringResource(R.string.chain_private_dns_open)) }
    }
    Column(Modifier.selectableGroup()) {
        for ((all, label) in listOf(true to R.string.chain_all_apps, false to R.string.chain_some_apps)) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .selectable(selected = view.allApps == all, role = Role.RadioButton) { actions.onAllApps(all) }
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = view.allApps == all, onClick = null)
                Text(stringResource(label), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
            }
        }
    }
    if (!view.allApps) {
        for (app in view.choices) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .toggleable(value = app.packageName in view.apps, role = Role.Checkbox) { actions.onApp(app.packageName, it) }
                    .padding(start = 16.dp, top = 2.dp, bottom = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(checked = app.packageName in view.apps, onCheckedChange = null)
                Text(app.label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.padding(start = 12.dp))
            }
        }
    }
    if (view.user != null && view.password != null) {
        Text(stringResource(R.string.chain_password, tool), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.chain_user, view.user), style = MaterialTheme.typography.bodyLarge)
        Text(stringResource(R.string.chain_password_value, view.password), style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = actions.onCopyPassword) { Text(stringResource(R.string.chain_copy)) }
    }
    LabelledSwitch(stringResource(R.string.chain_log_destinations), view.logDestinations, actions.onLogDestinations)
    Text(stringResource(R.string.chain_log_destinations_note), style = MaterialTheme.typography.bodyMedium)
}

/**
 * What the tool's signing key says about this copy, in the audit app's words (ADR 0018): a modified
 * copy carries everything the chained apps send, so it is said plainly, with its fingerprint.
 */
@Composable
private fun KeyVerdict(verdict: SignatureVerdict) {
    val body = MaterialTheme.typography.bodyMedium
    val app = BidiFormatter.getInstance().unicodeWrap(verdict.app)
    when (verdict) {
        is SignatureVerdict.Genuine -> {
            val text = when (verdict.controller) {
                "google" -> R.string.signature_genuine_google
                "fdroid" -> R.string.signature_genuine_fdroid
                else -> R.string.signature_genuine_developer
            }
            Text(stringResource(text, app), style = body)
            if (verdict.pastKeyOnly) Text(stringResource(R.string.signature_past_key), style = body)
        }
        is SignatureVerdict.UnknownKey -> {
            Text(stringResource(R.string.signature_unknown, app), style = body)
            Fingerprint(verdict.fingerprint)
        }
        is SignatureVerdict.Modified -> {
            val text = if (verdict.debugKey) R.string.signature_modified_debug else R.string.signature_modified
            Text(stringResource(text, app), style = body, color = MaterialTheme.colorScheme.error)
            Fingerprint(verdict.fingerprint)
        }
        // Watch looks for the table's package names only, so a build under another name is never the tool.
        is SignatureVerdict.Disguised -> Unit
    }
}

/** A SHA-256 fingerprint as developers usually print it: colon-separated uppercase pairs. */
@Composable
private fun Fingerprint(hex: String) {
    SelectionContainer {
        Text(
            hex.split(' ').joinToString("\n") { digest -> digest.uppercase(Locale.ROOT).chunked(2).joinToString(":") },
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

/** A switch whose whole row is the control, with its label. */
@Composable
private fun LabelledSwitch(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = null)
    }
}
