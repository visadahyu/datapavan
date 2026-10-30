package org.visadahyu.datapavan.ui

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.Capability
import org.visadahyu.datapavan.audit.ServiceState
import java.text.DateFormat
import java.util.Date

/**
 * Capabilities of this app's SDKs that need a system service the phone lacks right now (ADR 0021).
 * Each line names the capability, never the SDK or the app, says that it holds for this profile and
 * the time of the check, and that the rest of the app's code can still run. Capabilities whose key
 * this version of the app does not know are left out, so new data never produces an unworded label.
 */
@Composable
internal fun ServiceNeedsSection(unavailable: List<Capability>, states: Map<String, ServiceState>, names: Map<String, String>, checkedAt: Long) {
    val time = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(checkedAt))
    val lines = unavailable.flatMap { capability ->
        val name = capabilityName(capability.key) ?: return@flatMap emptyList()
        capability.services.filter { states[it] == ServiceState.ABSENT }.map { name to it }
    }
    if (lines.isEmpty()) return
    Column {
        SectionTitle(R.string.needs_heading)
        lines.forEach { (name, service) ->
            Spacer(Modifier.height(4.dp))
            val serviceName = serviceName(service)?.let { stringResource(it) } ?: names[service] ?: service
            Text(stringResource(R.string.needs_line, stringResource(name), serviceName, time), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@StringRes
private fun capabilityName(key: String): Int? = when (key) {
    "google-ad-id" -> R.string.need_google_ad_id
    "fcm-push" -> R.string.need_fcm_push
    "play-install-referrer" -> R.string.need_play_install_referrer
    "play-integrity-app-check" -> R.string.need_play_integrity_app_check
    "hms-push" -> R.string.need_hms_push
    "hms-account" -> R.string.need_hms_account
    "hms-oaid" -> R.string.need_hms_oaid
    else -> null
}

@StringRes
private fun serviceName(id: String): Int? = when (id) {
    "google-play-services" -> R.string.service_google_play_services
    "google-play-store" -> R.string.service_google_play_store
    "hms-core" -> R.string.service_hms_core
    else -> null
}
