package org.visadahyu.datapavan.network.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import java.text.NumberFormat
import org.visadahyu.datapavan.network.guides.GuidePage
import org.visadahyu.datapavan.network.guides.GuideStrings
import org.visadahyu.datapavan.network.guides.GuideView

/**
 * One tool's guide (W8, part 3b; ADR 0041, "How the per-tool guides are built"): how to run it in proxy mode beside
 * the network part, or why it cannot run beside it, block by block as [GuideView] fills them, the steps numbered within
 * each part. Nothing here links out: no download, no store, no tool named as better than another. Null while the labels
 * are read.
 */
@Composable
internal fun GuideScreen(view: GuideView?) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (view == null) return@Column
            Text(
                text(view.title, listOf(view.tool)),
                style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() },
            )
            var step = 0
            for (block in view.blocks) {
                if (GuideStrings.ids[block.string] == null) continue
                when (block.kind) {
                    GuidePage.Kind.HEADING -> {
                        step = 0
                        Text(
                            text(block.string, block.args),
                            style = MaterialTheme.typography.titleSmall,
                            modifier = Modifier.padding(top = 8.dp).semantics { heading() },
                        )
                    }
                    GuidePage.Kind.STEP -> {
                        step += 1
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(NumberFormat.getIntegerInstance().format(step) + ".", style = MaterialTheme.typography.bodyLarge)
                            Text(text(block.string, block.args), style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                    GuidePage.Kind.TEXT -> Text(text(block.string, block.args), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun text(name: String, args: List<String>): String {
    val id = GuideStrings.ids.getValue(name)
    return if (args.isEmpty()) stringResource(id) else stringResource(id, *args.toTypedArray())
}
