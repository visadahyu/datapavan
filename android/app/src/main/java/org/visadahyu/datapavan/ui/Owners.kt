package org.visadahyu.datapavan.ui

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
import org.visadahyu.datapavan.audit.OwnerNotes

/**
 * Who runs the services of this app's SDKs (ADR 0020). A same-group note states the fact and what
 * follows from it, and never lowers, hides or excuses a finding; a shut-down service is said apart.
 */
@Composable
internal fun OwnerSection(notes: OwnerNotes) {
    Column {
        SectionTitle(R.string.owners_heading)
        if (notes.group != null && notes.sameGroup.isNotEmpty()) {
            Text(stringResource(R.string.owner_same_group, notes.group, notes.sameGroup.joinToString(", ")), style = MaterialTheme.typography.bodyMedium)
        }
        notes.shutDown.forEach { (name, date) ->
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.owner_shut_down, name, isolateLtr(date)), style = MaterialTheme.typography.bodyMedium)
        }
    }
}
