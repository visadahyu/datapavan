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
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.watch.PrivateDns
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.dns.DnsCatalogue
import org.visadahyu.datapavan.watch.dns.DnsSettings
import org.visadahyu.datapavan.watch.dns.DnsStatus

/** What Watch's screen shows of the names of apps that go directly (W8, part 1). */
internal data class DnsView(
    val running: Boolean,
    val status: DnsStatus?,
    val choice: DnsSettings.Choice,
    val strict: Boolean,
    val notify: Boolean,
    /** The user's pairs, `relay>target` by commas; empty for the defaults. */
    val pairs: String,
    val catalogue: DnsCatalogue?,
)

/** What the user can change there. */
internal class DnsActions(
    val onChoice: (DnsSettings.Choice) -> Unit,
    val onStrict: (Boolean) -> Unit,
    val onNotify: (Boolean) -> Unit,
    val onPairs: (String) -> Unit,
)

/**
 * The names of apps that go directly (W8, part 1, ADR 0042): which way they go now, the fallback while it lasts,
 * when Android's strict Private DNS takes them past Watch, the user's choice of resolver with each preset's card,
 * the strict setting with what it costs and what it cannot cover, the ODoH pairs, and the fallback's notification.
 * Nothing of the names themselves is shown or kept.
 */
@Composable
internal fun DnsSection(view: DnsView, privateDns: PrivateDns?, actions: DnsActions) {
    val bidi = BidiFormatter.getInstance()
    val catalogue = view.catalogue
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.dns_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        if (view.running) {
            val status = view.status
            val now = nowText(status, catalogue, view.choice)
            Text(
                now,
                style = MaterialTheme.typography.bodyMedium,
                color = if (status?.fallbackSeconds != null || status?.failingSeconds != null) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onBackground
                },
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        if (privateDns is PrivateDns.Strict) {
            Text(stringResource(R.string.dns_private_dns_strict, bidi.unicodeWrap(privateDns.host)), style = MaterialTheme.typography.bodyMedium)
        }
        Text(stringResource(R.string.dns_choice), style = MaterialTheme.typography.bodyMedium)
        Column(Modifier.selectableGroup()) {
            Choice(
                selected = view.choice == DnsSettings.Choice.Odoh,
                label = stringResource(R.string.dns_odoh),
                detail = stringResource(R.string.dns_odoh_detail),
            ) { actions.onChoice(DnsSettings.Choice.Odoh) }
            for (preset in catalogue?.presets.orEmpty()) {
                Choice(
                    selected = view.choice == DnsSettings.Choice.Preset(preset.id),
                    label = stringResource(
                        R.string.dns_preset,
                        bidi.unicodeWrap(preset.name),
                        if (preset.dot) "DoT" else "DoH",
                    ),
                    detail = stringResource(
                        R.string.dns_preset_card,
                        bidi.unicodeWrap(preset.operator),
                        preset.country,
                        bidi.unicodeWrap(preset.logging),
                        bidi.unicodeWrap(preset.audit.ifEmpty { stringResource(R.string.dns_preset_no_audit) }),
                        bidi.unicodeWrap(preset.filtering),
                    ),
                ) { actions.onChoice(DnsSettings.Choice.Preset(preset.id)) }
            }
            Custom(view.choice, actions)
        }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = view.strict, role = Role.Switch) { actions.onStrict(it) }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.dns_strict), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Switch(checked = view.strict, onCheckedChange = null)
        }
        Text(stringResource(R.string.dns_strict_cost), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.dns_local_names), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.dns_strict_limits), style = MaterialTheme.typography.bodyMedium)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .toggleable(value = view.notify, role = Role.Switch) { actions.onNotify(it) }
                .padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(stringResource(R.string.dns_notify), style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            Switch(checked = view.notify, onCheckedChange = null)
        }
        if (catalogue != null && view.choice == DnsSettings.Choice.Odoh) Pairs(view, catalogue, actions)
        Text(stringResource(R.string.dns_not_kept), style = MaterialTheme.typography.bodyMedium)
    }
}

/** The sentence that says where direct apps' names go now. */
@Composable
private fun nowText(status: DnsStatus?, catalogue: DnsCatalogue?, choice: DnsSettings.Choice): String {
    val bidi = BidiFormatter.getInstance()
    val way = status?.way.orEmpty().split(' ')
    val relay = party(catalogue?.relays, way.getOrNull(1))
    val target = party(catalogue?.targets, way.getOrNull(2))
    return when {
        status == null -> stringResource(R.string.dns_now_unknown)
        status.fallbackSeconds != null -> stringResource(R.string.dns_now_fallback)
        status.failingSeconds != null -> stringResource(R.string.dns_now_failing)
        way[0] == "odoh" -> stringResource(R.string.dns_now_odoh, relay, target)
        way[0] == "odoh-tool" -> stringResource(R.string.dns_now_odoh_tool, relay, target)
        way[0] == "choice" -> stringResource(R.string.dns_now_choice)
        way[0] == "doh-target" -> stringResource(R.string.dns_now_down, party(catalogue?.targets, way.getOrNull(1)))
        way[0] == "preset" -> {
            val preset = catalogue?.presets?.firstOrNull { it.id == way.getOrNull(1) }
            stringResource(R.string.dns_now_down, bidi.unicodeWrap(preset?.name ?: way.getOrNull(1).orEmpty()))
        }
        choice == DnsSettings.Choice.Odoh -> stringResource(R.string.dns_now_none_odoh)
        else -> stringResource(R.string.dns_now_unknown)
    }
}

/** A relay or a target by its operator and countries, or its id where the catalogue does not hold it. */
@Composable
private fun party(parties: Map<String, DnsCatalogue.Party>?, id: String?): String {
    val bidi = BidiFormatter.getInstance()
    val p = parties?.get(id.orEmpty()) ?: return bidi.unicodeWrap(id.orEmpty())
    return stringResource(R.string.dns_party, bidi.unicodeWrap(p.operator), p.jurisdictions)
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

/** The user's own DoH or DoT resolver: a URL or a host, and its addresses, since Watch never looks a resolver's name up. */
@Composable
private fun Custom(choice: DnsSettings.Choice, actions: DnsActions) {
    val current = choice as? DnsSettings.Choice.Custom
    var open by rememberSaveable { mutableStateOf(current != null) }
    var at by rememberSaveable { mutableStateOf(current?.at.orEmpty()) }
    var addresses by rememberSaveable { mutableStateOf(current?.addresses?.joinToString(", ").orEmpty()) }
    var refused by rememberSaveable { mutableStateOf(false) }
    Choice(selected = current != null, label = stringResource(R.string.dns_custom), detail = stringResource(R.string.dns_custom_detail)) {
        open = true
    }
    if (!open) return
    OutlinedTextField(value = at, onValueChange = { at = it }, label = { Text(stringResource(R.string.dns_custom_at)) }, singleLine = true)
    OutlinedTextField(value = addresses, onValueChange = { addresses = it }, label = { Text(stringResource(R.string.dns_custom_addresses)) }, singleLine = true)
    OutlinedButton(onClick = {
        val made = DnsSettings.Choice.custom(at, addresses)
        refused = made == null
        made?.let(actions.onChoice)
    }) { Text(stringResource(R.string.dns_custom_use)) }
    if (refused) Text(stringResource(R.string.dns_custom_refused), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
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
    fun name(pair: Pair<String, String>): String {
        val relay = catalogue.relays[pair.first]
        val target = catalogue.targets[pair.second]
        return "${bidi.unicodeWrap(relay?.operator ?: pair.first)} (${relay?.jurisdictions.orEmpty()}) → ${bidi.unicodeWrap(target?.operator ?: pair.second)} (${target?.jurisdictions.orEmpty()})"
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
