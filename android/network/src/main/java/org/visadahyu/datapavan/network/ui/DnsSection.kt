package org.visadahyu.datapavan.network.ui

import android.content.ActivityNotFoundException
import android.content.Intent
import android.text.BidiFormatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import java.util.Locale
import org.visadahyu.datapavan.network.PrivateDns
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.dns.DnsCatalogue
import org.visadahyu.datapavan.network.dns.DnsSettings
import org.visadahyu.datapavan.network.dns.DnsStatus

/** What the network screen shows of the names of apps that go directly (W8, part 1). */
internal data class DnsView(
    val running: Boolean,
    val status: DnsStatus?,
    val choice: DnsSettings.Choice,
    val strict: Boolean,
    /** "Only this resolver" (W8's fix round, review R-M1). */
    val only: Boolean,
    val notify: Boolean,
    /** Android refused the network part's notifications when the user turned "Notify me" on (review R-M3). */
    val notifyRefused: Boolean,
    /** The pairs the user set, `relay>target` by commas; empty for the defaults. */
    val pairs: String,
    val catalogue: DnsCatalogue?,
    /** The last check of the user's own resolver, while the screen shows it. */
    val probe: Probe?,
) {
    /** The check of the user's own resolver before the network part saves it (review R-M1). */
    sealed interface Probe {
        data object Asking : Probe

        data class Answered(val ms: Long) : Probe

        data class Failed(val tampered: Boolean) : Probe
    }
}

/** What the user can change there. */
internal class DnsActions(
    val onChoice: (DnsSettings.Choice) -> Unit,
    /** The user's own resolver: tested first, saved only if it answers (review R-M1). */
    val onCustom: (DnsSettings.Choice.Custom) -> Unit,
    val onStrict: (Boolean) -> Unit,
    val onOnly: (Boolean) -> Unit,
    val onNotify: (Boolean) -> Unit,
    val onPairs: (String) -> Unit,
)

/**
 * The names of apps that go directly (W8, part 1, ADR 0042, and its fix round): which way they go now, the fallback
 * while it lasts, when Android's strict Private DNS takes them past the network part (that note alone then), the user's
 * choice of resolver with each service's card and what happens if it fails, "only this resolver", the strict setting
 * with what it costs and what it cannot cover, the network's own domains, the ODoH pairs, and the fallback's
 * notification. Nothing of the names themselves is shown or kept.
 */
@Composable
internal fun DnsSection(view: DnsView, privateDns: PrivateDns?, actions: DnsActions) {
    val bidi = BidiFormatter.getInstance()
    val catalogue = view.catalogue
    // Opened to type a resolver of the user's own: that row is the one selected meanwhile (review R-m6).
    var typing by rememberSaveable { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.dns_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (privateDns is PrivateDns.Strict) {
            // Android sends every name past the network part: this note alone, not what the network part would do
            // (review R-m5).
            Text(
                stringResource(
                    R.string.dns_private_dns_strict_quoted, bidi.unicodeWrap(privateDns.host),
                    quotedLabel("private_dns"), quotedLabel("private_dns_off"), quotedLabel("private_dns_automatic"),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            AndroidLabelsNote("private_dns", "private_dns_off", "private_dns_automatic")
            Text(stringResource(R.string.private_dns_still_named), style = MaterialTheme.typography.bodyMedium)
        } else if (view.running) {
            Now(view, catalogue)
        }
        Text(stringResource(R.string.dns_choice), style = MaterialTheme.typography.bodyMedium)
        Column(Modifier.selectableGroup()) {
            Choice(
                selected = view.choice == DnsSettings.Choice.Odoh && !typing,
                label = stringResource(R.string.dns_odoh),
                detail = stringResource(R.string.dns_odoh_detail),
            ) {
                typing = false
                actions.onChoice(DnsSettings.Choice.Odoh)
            }
            // One row per service, its two protocols inside (review n3).
            for ((_, presets) in catalogue?.presets.orEmpty().groupBy { it.group }) {
                Service(presets, view.choice.takeIf { !typing }, actions) { typing = false }
            }
            Custom(view, typing, actions) { typing = it }
        }
        if (view.choice != DnsSettings.Choice.Odoh) {
            Toggle(stringResource(R.string.dns_only), view.only, actions.onOnly)
            Text(stringResource(R.string.dns_only_cost), style = MaterialTheme.typography.bodyMedium)
        }
        Toggle(stringResource(R.string.dns_strict), view.strict, actions.onStrict)
        Text(stringResource(R.string.dns_strict_cost), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.dns_local_names), style = MaterialTheme.typography.bodyMedium)
        val search = view.status?.search.orEmpty()
        if (view.running && search.isNotEmpty()) {
            Text(
                stringResource(R.string.dns_search, search.joinToString(", ") { bidi.unicodeWrap(it) }),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        // Android's own name for its always-on switch (ADR 0054).
        Text(stringResource(R.string.dns_strict_limits_quoted, quotedLabel("always_on_vpn")), style = MaterialTheme.typography.bodyMedium)
        AndroidLabelsNote("always_on_vpn")
        Toggle(stringResource(R.string.dns_notify), view.notify, actions.onNotify)
        if (view.notifyRefused) {
            Text(
                stringResource(R.string.dns_notify_refused),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        if (catalogue != null && view.choice == DnsSettings.Choice.Odoh) Pairs(view, catalogue, actions)
        Text(stringResource(R.string.dns_not_kept), style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * Where direct apps' names go now: a first sentence that a screen reader reads out when it changes, and the details
 * apart, so that a hedge between the two pairs is not read out each time (review R-m6).
 */
@Composable
private fun Now(view: DnsView, catalogue: DnsCatalogue?) {
    val status = view.status
    val way = status?.way.orEmpty().split(' ')
    val chose = view.choice != DnsSettings.Choice.Odoh
    // The pair's words, for a way through one; the operator's, for a way to one.
    val pair = stringResource(R.string.dns_now_pair, party(catalogue?.relays, way.getOrNull(1)), party(catalogue?.targets, way.getOrNull(2)))
    val operator = if (way[0] == "preset") {
        catalogue?.presets?.firstOrNull { it.id == way.getOrNull(1) }?.operator ?: way.getOrNull(1).orEmpty()
    } else {
        catalogue?.targets?.get(way.getOrNull(1).orEmpty())?.operator ?: way.getOrNull(1).orEmpty()
    }
    val to = stringResource(R.string.dns_now_to, BidiFormatter.getInstance().unicodeWrap(operator))
    val (headline, detail) = when {
        status == null -> stringResource(R.string.dns_now_unknown) to null
        status.fallbackSeconds != null -> stringResource(R.string.dns_now_fallback) to null
        status.failingSeconds != null && chose && view.only -> stringResource(R.string.dns_now_failing_only) to null
        status.failingSeconds != null -> stringResource(R.string.dns_now_failing) to null
        way[0] == "choice" -> stringResource(R.string.dns_now_choice) to null
        // The user's resolver failed: say so first, by what failed (review R-M1).
        way[0] == "odoh" && chose -> stringResource(R.string.dns_now_choice_down) to (stringResource(R.string.dns_now_odoh) + " " + pair)
        way[0] == "odoh" -> stringResource(R.string.dns_now_odoh) to pair
        way[0] == "odoh-tool" -> stringResource(R.string.dns_now_odoh_tool) to pair
        way[0] == "doh-target" || way[0] == "preset" ->
            stringResource(if (chose) R.string.dns_now_choice_down else R.string.dns_now_down_odoh) to to
        !chose -> stringResource(R.string.dns_now_none_odoh) to null
        else -> stringResource(R.string.dns_now_unknown) to null
    }
    val alarm = status?.fallbackSeconds != null || status?.failingSeconds != null
    Text(
        headline,
        style = MaterialTheme.typography.bodyMedium,
        color = if (alarm) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onBackground,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
    if (detail != null) Text(detail, style = MaterialTheme.typography.bodyMedium)
}

/** Countries' two-letter codes, by commas, as the phone's language names them (review R-M2). */
internal fun countries(codes: String): String =
    codes.split(',').map { it.trim() }.filter { it.isNotEmpty() }.joinToString(", ") { code ->
        Locale.Builder().setRegion(code).build().displayCountry.ifEmpty { code }
    }

/** A relay or a target by its operator and countries, or its id where the catalogue does not hold it. */
@Composable
private fun party(parties: Map<String, DnsCatalogue.Party>?, id: String?): String {
    val bidi = BidiFormatter.getInstance()
    val p = parties?.get(id.orEmpty()) ?: return bidi.unicodeWrap(id.orEmpty())
    return stringResource(R.string.dns_party, bidi.unicodeWrap(p.operator), countries(p.jurisdictions))
}

@Composable
private fun Toggle(label: String, on: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = on, role = Role.Switch, onValueChange = onChange)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
        Switch(checked = on, onCheckedChange = null)
    }
}

@Composable
private fun Choice(selected: Boolean, label: String, detail: String, onSelect: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected = selected, onClick = null)
        Column(Modifier.padding(start = 12.dp)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            Text(detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/**
 * One service of the presets (review n3): its operator and a translated name of the service, its card in the
 * screen's words (review R-M2), what happens if it fails (review R-M1) and its privacy policy (review n1); once
 * chosen, its two protocols. [choice] is null while the user types a resolver of their own.
 */
@Composable
private fun Service(presets: List<DnsCatalogue.Preset>, choice: DnsSettings.Choice?, actions: DnsActions, onPick: () -> Unit) {
    val first = presets.firstOrNull() ?: return
    val bidi = BidiFormatter.getInstance()
    val chosen = presets.firstOrNull { choice == DnsSettings.Choice.Preset(it.id) }
    val service = when (first.service) {
        "blocking" -> stringResource(R.string.dns_service_blocking)
        "standard" -> stringResource(R.string.dns_service_standard)
        else -> stringResource(R.string.dns_service_unfiltered)
    }
    val logs = when (first.logs) {
        "totals" -> R.string.dns_logs_totals
        "names-day" -> R.string.dns_logs_names_day
        "day" -> R.string.dns_logs_day
        "months" -> R.string.dns_logs_months
        else -> R.string.dns_logs_none
    }
    val blocks = when (first.blocks) {
        "harm" -> R.string.dns_blocks_harm
        "court" -> R.string.dns_blocks_court
        else -> R.string.dns_blocks_none
    }
    val audited = if (first.audited == "firm") R.string.dns_audited_firm else R.string.dns_audited_no
    Choice(
        selected = chosen != null,
        label = stringResource(R.string.dns_preset, bidi.unicodeWrap(first.operator), service),
        detail = stringResource(R.string.dns_preset_card, countries(first.country), stringResource(logs), stringResource(blocks), stringResource(audited)) +
            " " + stringResource(R.string.dns_choice_fails),
    ) {
        onPick()
        actions.onChoice(DnsSettings.Choice.Preset((presets.firstOrNull { !it.dot } ?: first).id))
    }
    if (first.policy.isNotEmpty()) {
        val context = LocalContext.current
        val named = stringResource(R.string.dns_policy_named, bidi.unicodeWrap(first.operator))
        TextButton(onClick = {
            try {
                context.startActivity(Intent(Intent.ACTION_VIEW, first.policy.toUri()))
            } catch (_: ActivityNotFoundException) {
                // No browser: the policy's address is in the data pack's table.
            }
        },
            // A screen reader moving from button to button hears whose policy it is (WCAG 2.4.4), its visible words
            // first (2.5.3).
            modifier = Modifier.padding(start = 36.dp).semantics {
                contentDescription = named
            },
        ) { Text(stringResource(R.string.dns_policy), modifier = Modifier.clearAndSetSemantics {}) }
    }
    if (chosen != null && presets.size > 1) {
        Column(Modifier.padding(start = 36.dp).selectableGroup()) {
            for (preset in presets.sortedBy { it.dot }) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(selected = preset == chosen, role = Role.RadioButton) { actions.onChoice(DnsSettings.Choice.Preset(preset.id)) }
                        .padding(vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = preset == chosen, onClick = null)
                    Text(
                        stringResource(if (preset.dot) R.string.dns_protocol_dot else R.string.dns_protocol_doh),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(start = 12.dp),
                    )
                }
            }
        }
    }
}

/**
 * The user's own DoH or DoT resolver: a URL or a host, and its addresses, since the network part never looks a
 * resolver's name up. Tested with one query before it is saved, and the result shown (review R-M1). The fields are left
 * to right, with a URL's keyboard; a refusal is tied to its field and read out (review R-m6).
 */
@Composable
private fun Custom(view: DnsView, typing: Boolean, actions: DnsActions, onTyping: (Boolean) -> Unit) {
    val current = view.choice as? DnsSettings.Choice.Custom
    var at by rememberSaveable { mutableStateOf(current?.at.orEmpty()) }
    var addresses by rememberSaveable { mutableStateOf(current?.addresses?.joinToString(", ").orEmpty()) }
    var refused by rememberSaveable { mutableStateOf(false) }
    Choice(
        selected = typing || current != null,
        label = stringResource(R.string.dns_custom),
        detail = stringResource(R.string.dns_custom_detail) + " " + stringResource(R.string.dns_choice_fails),
    ) { onTyping(true) }
    if (!typing && current == null) return
    val refusal = stringResource(R.string.dns_custom_refused)
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        OutlinedTextField(
            value = at,
            onValueChange = {
                at = it
                refused = false
            },
            label = { Text(stringResource(R.string.dns_custom_at)) },
            singleLine = true,
            isError = refused,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.semantics { if (refused) error(refusal) },
        )
        OutlinedTextField(
            value = addresses,
            onValueChange = {
                addresses = it
                refused = false
            },
            label = { Text(stringResource(R.string.dns_custom_addresses)) },
            singleLine = true,
            isError = refused,
            supportingText = if (refused) ({ Text(refusal) }) else null,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.semantics { if (refused) error(refusal) },
        )
    }
    OutlinedButton(
        enabled = view.probe != DnsView.Probe.Asking,
        onClick = {
            val made = DnsSettings.Choice.custom(at, addresses) as? DnsSettings.Choice.Custom
            refused = made == null
            made?.let(actions.onCustom)
        },
    ) { Text(stringResource(R.string.dns_custom_use)) }
    val result = when (val probe = view.probe) {
        null -> null
        DnsView.Probe.Asking -> stringResource(R.string.dns_custom_testing)
        is DnsView.Probe.Answered -> stringResource(R.string.dns_custom_answered, probe.ms)
        is DnsView.Probe.Failed -> stringResource(if (probe.tampered) R.string.dns_custom_tampered else R.string.dns_custom_failed)
    }
    if (refused || result != null) {
        Text(
            if (refused) refusal else result.orEmpty(),
            color = if (refused || view.probe is DnsView.Probe.Failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onBackground,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive },
        )
    }
}

/** The ODoH pairs in use, and the user's change of them among the pairs the rule allows. */
@Composable
private fun Pairs(view: DnsView, catalogue: DnsCatalogue, actions: DnsActions) {
    val bidi = BidiFormatter.getInstance()
    val chosen = view.pairs.split(',').mapNotNull { it.trim().split('>').takeIf { p -> p.size == 2 }?.let { p -> p[0] to p[1] } }
        .filter { it in catalogue.allowed }
        .ifEmpty { catalogue.defaults }
    var open by rememberSaveable { mutableStateOf(false) }
    Text(stringResource(R.string.dns_pairs), style = MaterialTheme.typography.bodyMedium)

    // Relay first, then target, in words a right-to-left sentence keeps in order (review R-m6).
    @Composable
    fun name(pair: Pair<String, String>): String {
        val relay = catalogue.relays[pair.first]
        val target = catalogue.targets[pair.second]
        return stringResource(
            R.string.dns_pair,
            stringResource(R.string.dns_party, bidi.unicodeWrap(relay?.operator ?: pair.first), countries(relay?.jurisdictions.orEmpty())),
            stringResource(R.string.dns_party, bidi.unicodeWrap(target?.operator ?: pair.second), countries(target?.jurisdictions.orEmpty())),
        )
    }
    if (!open) {
        for (pair in chosen) Text(name(pair), style = MaterialTheme.typography.bodyMedium)
        OutlinedButton(onClick = { open = true }) { Text(stringResource(R.string.dns_pairs_change)) }
        return
    }
    for (pair in catalogue.allowed) {
        val on = pair in chosen
        Row(
            modifier = Modifier
                .fillMaxWidth()
                // The last pair stays: Oblivious DoH needs one.
                .toggleable(value = on, role = Role.Checkbox, enabled = !(on && chosen.size == 1)) {
                    val next = if (it) chosen + pair else chosen - pair
                    actions.onPairs(if (next == catalogue.defaults) "" else next.joinToString(",") { p -> "${p.first}>${p.second}" })
                }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = on, onCheckedChange = null)
            Text(name(pair), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(start = 12.dp))
        }
    }
    OutlinedButton(onClick = {
        actions.onPairs("")
        open = false
    }) { Text(stringResource(R.string.dns_pairs_default)) }
    OutlinedButton(onClick = { open = false }) { Text(stringResource(R.string.dns_pairs_done)) }
}
