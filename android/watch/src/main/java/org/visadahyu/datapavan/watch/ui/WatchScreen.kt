package org.visadahyu.datapavan.watch.ui

import android.text.BidiFormatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.watch.PrivateDns
import org.visadahyu.datapavan.watch.R

/**
 * Watch's one screen: what it is for, whether it is on, the switch, and while it is on, what Private
 * DNS hides from it (W3).
 */
@Composable
internal fun WatchScreen(
    running: Boolean,
    privateDns: PrivateDns?,
    refused: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            Text(stringResource(R.string.tagline), style = MaterialTheme.typography.bodyLarge)
            Text(
                stringResource(if (running) R.string.status_on else R.string.status_off),
                style = MaterialTheme.typography.titleMedium,
                // Read out when it changes, also when the change came from outside (another VPN).
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
            if (running) {
                OutlinedButton(onClick = onStop) { Text(stringResource(R.string.turn_off)) }
            } else {
                Button(onClick = onStart) { Text(stringResource(R.string.turn_on)) }
            }
            if (running && privateDns != null && privateDns != PrivateDns.Plain) {
                PrivateDnsNote(privateDns)
            }
            if (refused && !running) {
                Text(
                    stringResource(R.string.consent_refused),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

/** Why Watch reads fewer names while Private DNS encrypts the lookups, and what it still names. */
@Composable
private fun PrivateDnsNote(privateDns: PrivateDns) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.private_dns),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            when (privateDns) {
                // The provider's name keeps its own direction inside a right-to-left sentence.
                is PrivateDns.Strict -> stringResource(R.string.private_dns_strict, BidiFormatter.getInstance().unicodeWrap(privateDns.host))
                else -> stringResource(R.string.private_dns_network)
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(stringResource(R.string.private_dns_still_named), style = MaterialTheme.typography.bodyMedium)
    }
}
