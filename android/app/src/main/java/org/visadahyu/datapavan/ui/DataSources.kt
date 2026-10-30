package org.visadahyu.datapavan.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.datapack.DataPack
import org.visadahyu.datapavan.datapack.DataPackRules
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.datapack.ImportResult
import org.visadahyu.datapavan.datapack.PackRefusal
import org.visadahyu.datapavan.datapack.reflow
import org.visadahyu.datapavan.datapack.sourceField

/**
 * The data the audit uses: each dataset with its date and licence, which the ODbL and the other
 * licences ask for wherever the data is used (ADR 0015), and the import of a newer signed pack.
 * [onImported] runs after a pack was imported, so that the audit can run again with the new data.
 */
@Composable
internal fun DataSources(insets: PaddingValues, onBack: () -> Unit, onImported: () -> Unit) {
    val context = LocalContext.current.applicationContext
    val store = remember { DataPackStore.get(context) }
    var pack by remember { mutableStateOf(store.active) }
    var imported by remember { mutableStateOf(store.isImported) }
    var outcome by remember { mutableStateOf<ImportResult?>(null) }
    val scope = rememberCoroutineScope()
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                val result = withContext(Dispatchers.IO) { store.import(uri) }
                outcome = result
                if (result is ImportResult.Imported) {
                    pack = result.pack
                    imported = true
                    onImported()
                }
            }
        }
    }
    val canImport = store.trustedKeys.isNotEmpty()

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(stringResource(R.string.data_sources_title), style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.data_sources_intro), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            Text(
                stringResource(
                    if (imported) R.string.data_pack_imported else R.string.data_pack_bundled,
                    pack.sequence,
                    isolateLtr(pack.date),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (DataPackRules.isStale(pack.date, LocalDate.now())) {
                Text(
                    stringResource(R.string.data_stale, isolateLtr(pack.date)),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(stringResource(R.string.data_fingerprint), style = MaterialTheme.typography.bodySmall)
            SelectionContainer {
                Text(
                    pack.fingerprint,
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace, textDirection = TextDirection.Ltr),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        items(pack.datasets) { dataset -> Dataset(pack, dataset) }
        item {
            Spacer(Modifier.height(8.dp))
            SectionTitle(R.string.data_import_title)
            Text(stringResource(R.string.data_import_body), style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(8.dp))
            if (canImport) {
                OutlinedButton(onClick = { picker.launch(arrayOf("*/*")) }) { Text(stringResource(R.string.data_import_button)) }
            } else {
                Text(stringResource(R.string.data_import_unavailable), style = MaterialTheme.typography.bodyMedium)
            }
            when (val result = outcome) {
                is ImportResult.Imported -> Text(
                    stringResource(R.string.data_import_done, result.pack.sequence),
                    style = MaterialTheme.typography.bodyMedium,
                )
                is ImportResult.Refused -> Text(
                    stringResource(refusalText(result.reason)),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                null -> {}
            }
        }
    }
}

/** On the overview, when the data is more than six months old: the date and the way to newer data. */
@Composable
internal fun StaleDataCard(date: String, onOpen: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.data_stale, isolateLtr(date)), style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = onOpen) { Text(stringResource(R.string.data_sources_title)) }
        }
    }
}

/** One dataset: its name, when it was retrieved, and its licence notice as the repository has it. */
@Composable
private fun Dataset(pack: DataPack, dataset: String) {
    val name = datasetName(dataset)?.let { stringResource(it) } ?: dataset
    val retrieved = pack.text("$dataset/SOURCE")?.let { sourceField(it, "retrieved") }?.take(DATE_LENGTH)
    Spacer(Modifier.height(8.dp))
    Text(name, style = MaterialTheme.typography.titleMedium)
    if (retrieved != null) {
        Text(stringResource(R.string.dataset_retrieved, isolateLtr(retrieved)), style = MaterialTheme.typography.bodyMedium)
    }
    pack.text("$dataset/LICENSE")?.let { licence ->
        // Legal text stays in English, as the licences themselves are.
        SelectionContainer {
            Text(
                reflow(licence),
                style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private const val DATE_LENGTH = 10

/** Datasets the app knows by name; a new one in a newer pack shows its folder name instead. */
@StringRes
private fun datasetName(dataset: String): Int? = when (dataset) {
    "attestation" -> R.string.dataset_attestation
    "exodus" -> R.string.dataset_exodus
    "app-signers" -> R.string.dataset_app_signers
    "sdks" -> R.string.dataset_sdks
    else -> null
}

@StringRes
private fun refusalText(reason: PackRefusal): Int = when (reason) {
    PackRefusal.NOT_SIGNED -> R.string.data_refused_not_signed
    PackRefusal.UNKNOWN_KEY -> R.string.data_refused_unknown_key
    PackRefusal.BAD_SIGNATURE -> R.string.data_refused_bad_signature
    PackRefusal.UNSUPPORTED_VERSION -> R.string.data_refused_unsupported
    PackRefusal.NOT_PACK, PackRefusal.INVALID_HEADER, PackRefusal.INVALID_KEY -> R.string.data_refused_invalid
    PackRefusal.TOO_LARGE -> R.string.data_refused_too_large
    PackRefusal.NOT_NEWER -> R.string.data_refused_not_newer
    PackRefusal.NO_TRUSTED_KEYS -> R.string.data_import_unavailable
    PackRefusal.UNREADABLE -> R.string.data_refused_unreadable
}
