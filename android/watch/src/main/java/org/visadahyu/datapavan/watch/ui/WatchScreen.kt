package org.visadahyu.datapavan.watch.ui

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
import org.visadahyu.datapavan.watch.R

/** Watch's one screen in W1: what it is for, whether it is on, and the switch. */
@Composable
internal fun WatchScreen(running: Boolean, refused: Boolean, onStart: () -> Unit, onStop: () -> Unit) {
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
