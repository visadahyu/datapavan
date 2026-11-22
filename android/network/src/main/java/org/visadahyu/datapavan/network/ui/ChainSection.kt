package org.visadahyu.datapavan.network.ui

import android.text.BidiFormatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.relocation.BringIntoViewRequester
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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
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
import org.visadahyu.datapavan.network.PrivateDns
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.chain.ToolSearch
import org.visadahyu.datapavan.network.guides.GuideLink
import org.visadahyu.datapavan.network.guides.Page
import java.util.Locale

/** An app the user may send through the tool: its package name and the name the user knows. */
internal data class AppChoice(val packageName: String, val label: String)

/** The user's chain as the screen shows it (W6). */
internal data class ChainView(
    /** What the network part found of the user's tool; null while it looks. */
    val search: ToolSearch?,
    val on: Boolean,
    val allApps: Boolean,
    val apps: Set<String>,
    val logDestinations: Boolean,
    /** Whether the user chose to send the apps' UDP through the tool too (ADR 0041, decision 5). */
    val udp: Boolean,
    /** The user name and password the network part offers for the tool's proxy, when the tool takes one. */
    val user: String?,
    val password: String?,
    /** The apps the user can choose from, loaded once the user asks to choose. */
    val choices: List<AppChoice>,
    /** What the found tool's signing key says about this copy (ADR 0018), when anything can be said. */
    val key: SignatureVerdict? = null,
    /** The name of the tool the chain last went through, for its switch while that tool does not answer. */
    val chainedName: String? = null,
    /** A guide per tool of the table installed here (W8, part 3b), in the guides' order. */
    val guides: List<GuideLink> = emptyList(),
)

/** What the user can change in the chain. */
internal class ChainActions(
    val onSearch: () -> Unit,
    val onOn: (Boolean) -> Unit,
    val onAllApps: (Boolean) -> Unit,
    val onApp: (String, Boolean) -> Unit,
    val onLogDestinations: (Boolean) -> Unit,
    val onUdp: (Boolean) -> Unit,
    val onCopyPassword: () -> Unit,
    val onPrivateDnsSettings: () -> Unit,
    /** Opens an installed tool's guide (W8, part 3b). */
    val onGuide: (GuideLink) -> Unit = {},
)

/**
 * The network part beside the user's circumvention tool (W6, docs/VPN.md): which tool it found, the switch that
 * sends apps through it, which apps, what its proxy lets other apps on the phone do and the password
 * that keeps them off it (ADR 0041, decision 5), whether UDP goes through it too, and the switch that logs where
 * chained apps connect, with the rest it covers (LogSwitch). A tool's name keeps its own direction inside a
 * right-to-left sentence.
 */
@Composable
internal fun ChainSection(
    view: ChainView,
    privateDns: PrivateDns?,
    actions: ChainActions,
    tunnelled: Map<String, String> = emptyMap(),
    waiting: Set<String> = emptySet(),
    /** Brings the switch "Log where apps connect ..." into view, where the screen does so here for a row's link. */
    logSwitch: BringIntoViewRequester? = null,
) {
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
            is ToolSearch.Answering -> Answering(search, view, privateDns, actions, tunnelled, waiting, logSwitch)
        }
        // A chain that is on stays one tap from off, whatever the search says now: while the tool does
        // not answer, the apps sent through it wait, and the user must be able to let them go directly
        // (CI, 2026-11-12: without this switch, only turning the network part off could end the wait).
        if (view.on && view.search !is ToolSearch.Answering) {
            val tool = bidi.unicodeWrap(view.chainedName ?: "")
            LabelledSwitch(stringResource(R.string.chain_switch, tool), checked = true, onChange = actions.onOn)
        }
        GuideLinks(view.guides, actions.onGuide)
    }
}

/**
 * The guide of each tool of the table installed here (W8, part 3b), whatever the search found: Android hides a VPN's
 * owner from other apps, so the network part cannot tell which tool runs as the VPN, and links them all
 * ([chainGuideLinks]).
 */
@Composable
private fun GuideLinks(guides: List<GuideLink>, onGuide: (GuideLink) -> Unit) {
    val links = chainGuideLinks(guides)
    if (links.isEmpty()) return
    Text(stringResource(R.string.chain_guides_title), style = MaterialTheme.typography.bodyMedium)
    val bidi = BidiFormatter.getInstance()
    for ((link, label) in links) {
        TextButton(onClick = { onGuide(link) }) { Text(stringResource(label, bidi.unicodeWrap(link.name))) }
    }
}

/**
 * Each installed tool's link and the words of its button: steps for proxy mode, or what the tool and the network part
 * can do.
 */
internal fun chainGuideLinks(guides: List<GuideLink>): List<Pair<GuideLink, Int>> =
    guides.distinctBy { it.guide }.map { it to if (it.page == Page.PROXY) R.string.chain_guide_proxy else R.string.chain_guide_other }

@Composable
private fun Answering(
    search: ToolSearch.Answering,
    view: ChainView,
    privateDns: PrivateDns?,
    actions: ChainActions,
    tunnelled: Map<String, String>,
    waiting: Set<String>,
    logSwitch: BringIntoViewRequester?,
) {
    val tool = BidiFormatter.getInstance().unicodeWrap(search.found.tool.name)
    Text(stringResource(R.string.chain_found, tool, search.found.port), style = MaterialTheme.typography.bodyMedium)
    view.key?.let { KeyVerdict(it) }
    LabelledSwitch(stringResource(R.string.chain_switch, tool), view.on, actions.onOn)
    ProxyDoor(search, tool)
    if (search.found.tool.udp == false) {
        Text(stringResource(R.string.chain_no_udp, tool), style = MaterialTheme.typography.bodyMedium)
    } else {
        LabelledSwitch(stringResource(R.string.chain_udp, tool), view.udp, actions.onUdp)
        Text(stringResource(R.string.chain_udp_note, tool), style = MaterialTheme.typography.bodyMedium)
    }
    if (privateDns is PrivateDns.Strict) {
        // What leaves past the tool, to whom, and what the network sees; then where to change it.
        // The setting and its choices as Android names them on this phone (ADR 0054).
        Text(
            stringResource(
                R.string.chain_private_dns_quoted, BidiFormatter.getInstance().unicodeWrap(privateDns.host), tool,
                quotedLabel("private_dns"), quotedLabel("private_dns_automatic"), quotedLabel("private_dns_off"),
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
        Text(stringResource(R.string.chain_private_dns_where_quoted, quotedLabel("private_dns")), style = MaterialTheme.typography.bodyMedium)
        AndroidLabelsNote("private_dns", "private_dns_automatic", "private_dns_off")
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
    // An app sent through a WireGuard configuration goes through it, whatever the chain says (the maintainer's
    // answer 3 of 2026-11-19): the chain's choice says so, and its way is changed under "Each app's way".
    if (view.allApps && tunnelled.isNotEmpty()) {
        Text(pluralStringResource(R.plurals.chain_tunnelled_apps, tunnelled.size, tunnelled.size), style = MaterialTheme.typography.bodyMedium)
    }
    if (!view.allApps) {
        for (app in view.choices) {
            val tunnel = tunnelled[app.packageName]
            val waits = app.packageName in waiting
            val free = tunnel == null && !waits
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .toggleable(value = app.packageName in view.apps && free, enabled = free, role = Role.Checkbox) {
                        actions.onApp(app.packageName, it)
                    }
                    .padding(start = 16.dp, top = 2.dp, bottom = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(checked = app.packageName in view.apps && free, onCheckedChange = null, enabled = free)
                Column(Modifier.padding(start = 12.dp)) {
                    Text(app.label, style = MaterialTheme.typography.bodyLarge)
                    tunnel?.let { Text(stringResource(R.string.chain_app_tunnel, it), style = MaterialTheme.typography.bodyMedium) }
                    if (waits) Text(stringResource(R.string.chain_app_waiting), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
    if (view.user != null && view.password != null) {
        Text(stringResource(R.string.chain_password, tool), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.chain_password_where, tool), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.chain_user, view.user), style = MaterialTheme.typography.bodyLarge)
        Text(stringResource(R.string.chain_password_value, view.password), style = MaterialTheme.typography.bodyLarge)
        OutlinedButton(onClick = actions.onCopyPassword) { Text(stringResource(R.string.chain_copy)) }
    }
    // The one switch (LogSwitch), here while the tool answers.
    Column(Modifier.bringingIntoView(logSwitch), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        LabelledSwitch(stringResource(R.string.log_switch), view.logDestinations, actions.onLogDestinations)
        Text(stringResource(R.string.log_switch_note), style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * What the tool's proxy lets other apps on the phone do (ADR 0041, decision 5), from the network part's greeting: one
 * that asks no password can be used by any of them, which is said plainly, with whether the tool can take one;
 * one that asks a password keeps them out, though any app can still find it. The network part chains either way.
 */
@Composable
private fun ProxyDoor(search: ToolSearch.Answering, tool: String) {
    val body = MaterialTheme.typography.bodyMedium
    if (search.found.needsPassword) {
        Text(stringResource(R.string.chain_proxy_closed, tool), style = body)
        return
    }
    Text(stringResource(R.string.chain_proxy_open, tool), style = body, color = MaterialTheme.colorScheme.error)
    if (search.found.tool.auth == "none") Text(stringResource(R.string.chain_proxy_no_password, tool), style = body)
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
        // The network part looks for the table's package names only, so a build under another name is never the tool.
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
