package org.visadahyu.datapavan.ui

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.KeyFacts
import org.visadahyu.datapavan.audit.KeyKind
import org.visadahyu.datapavan.audit.Origin

/**
 * What the phone's system key says about an app (ADR 0023), as separate facts: signed with the
 * system key, running as the system user, where it came from, and why its key cannot be trusted.
 * The maker is named as the phone reports it; nothing here calls an app safe, needed or unneeded.
 */
@Composable
internal fun SystemKeySection(facts: KeyFacts, manufacturer: String) {
    Column {
        SectionTitle(R.string.system_key_heading)
        if (facts.systemKey) {
            Text(stringResource(R.string.system_key_platform, isolate(manufacturer)), style = MaterialTheme.typography.bodyMedium)
        }
        if (facts.runsAsSystem) Text(stringResource(R.string.system_key_runs_as_system), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(originText(facts.origin)), style = MaterialTheme.typography.bodyMedium)
        facts.untrusted?.let { Text(stringResource(kindText(it)), style = MaterialTheme.typography.bodyMedium) }
    }
}

@StringRes
private fun originText(origin: Origin) = when (origin) {
    Origin.SYSTEM_IMAGE -> R.string.origin_system_image
    Origin.UPDATED_SYSTEM_APP -> R.string.origin_updated_system_app
    Origin.INSTALLED_LATER -> R.string.origin_installed_later
}

@StringRes
private fun kindText(kind: KeyKind) = when (kind) {
    KeyKind.AOSP_TEST -> R.string.key_kind_aosp_test
    KeyKind.GOOGLE_DEV -> R.string.key_kind_google_dev
    KeyKind.LEAKED -> R.string.key_kind_leaked
}
