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
internal fun NetworkEntry() {
    val context = LocalContext.current
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.watch_entry_title), style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.watch_entry_body), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = { context.startActivity(Intent().setClassName(context, NETWORK_SCREEN)) },
                modifier = Modifier.testTag("open-watch"),
            ) { Text(stringResource(R.string.watch_entry_open)) }
        }
    }
}

/** Watch's screen, in the :network library. */
private const val NETWORK_SCREEN = "org.visadahyu.datapavan.network.MainActivity"

/**
 * Datapavan Advanced only: from the audit's page of an app, Watch's view "Now" for that app (ADR 0046, decision
 * 2 (d)), which says what it sent and whether the user was using it. Opened by class name with the app's package
 * name and nothing else, as [NetworkEntry] opens Watch's screen.
 */
@Composable
internal fun NetworkNowEntry(packageName: String) {
    val context = LocalContext.current
    OutlinedButton(
        onClick = { context.startActivity(Intent().setClassName(context, NETWORK_NOW).putExtra(NETWORK_NOW_PACKAGE, packageName)) },
        modifier = Modifier.padding(vertical = 8.dp).testTag("open-watch-now"),
    ) { Text(stringResource(R.string.watch_now_open)) }
}

/** Watch's view "Now", in the :network library, and the one extra it reads: a package name. */
private const val NETWORK_NOW = "org.visadahyu.datapavan.network.NowActivity"
private const val NETWORK_NOW_PACKAGE = "package"
