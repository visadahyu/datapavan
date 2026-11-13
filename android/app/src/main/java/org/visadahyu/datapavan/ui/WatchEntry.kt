package org.visadahyu.datapavan.ui

import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.visadahyu.datapavan.R

/**
 * Datapavan Advanced only (ADR 0045): the way from the audit's network page to Watch, which shows where
 * each app connects. Watch's screen is in the same app but not in the audit's code, so it is opened by its
 * class name; Basic has no such screen and never shows this card.
 */
@Composable
internal fun WatchEntry() {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.watch_entry_title), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.watch_entry_body), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { context.startActivity(Intent().setClassName(context, WATCH_SCREEN)) },
                modifier = Modifier.testTag("open-watch"),
            ) { Text(stringResource(R.string.watch_entry_open)) }
        }
    }
}

/** Watch's screen, in the :watch library. */
private const val WATCH_SCREEN = "org.visadahyu.datapavan.watch.MainActivity"
