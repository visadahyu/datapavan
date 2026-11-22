package org.visadahyu.datapavan.ui

import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.visadahyu.datapavan.BuildConfig
import org.visadahyu.datapavan.R

/** What the licence screen lists, read from the APK's `assets/licences/` ([LicenceList]). */
private class Listing(
    /** The full texts, in the build's order (`licenceFiles`), without the table of Java and Kotlin libraries. */
    val files: List<String>,
    val jvm: List<LicenceList.Component>,
    /** Each native library's file, with its crates. */
    val native: List<Pair<String, LicenceList.Crates>>,
) {
    fun library(file: String): String? = native.firstOrNull { it.first == file }?.second?.library

    companion object {
        /** Off the main thread: the network part's library's list is some hundred kilobytes. */
        fun load(context: Context): Listing {
            val files = BuildConfig.LICENCE_FILES.split(',').filter { it.isNotBlank() }
            val jvm = LicenceList.jvm(read(context, LicenceList.JVM_TABLE), LicenceList.edition(BuildConfig.ADVANCED, BuildConfig.PLAY))
            val native = files.filter { it.startsWith("native-") }.map { it to LicenceList.crates(it, read(context, it)) }
            return Listing(files - LicenceList.JVM_TABLE, jvm, native)
        }
    }
}

private fun read(context: Context, file: String): String =
    context.assets.open("licences/$file").bufferedReader(Charsets.UTF_8).use { it.readText() }

/**
 * The open-source licences (W7, part 2; ADR 0035's release gate): the full texts the APK carries, then every part
 * of it and its licence, each opening the text that covers it. Nothing here is kept by hand but the table of Java
 * and Kotlin libraries, which the build holds to the classpath; the Rust packages come from the files
 * scripts/licences.py writes. Names, versions and licences read left to right in every language.
 */
@Composable
internal fun LicencesScreen(insets: PaddingValues, onBack: () -> Unit) {
    val context = LocalContext.current
    var openFile by rememberSaveable { mutableStateOf<String?>(null) }
    var openAnchor by rememberSaveable { mutableStateOf<String?>(null) }
    val listing by produceState<Result<Listing>?>(null) {
        value = withContext(Dispatchers.IO) {
            try {
                Result.success(Listing.load(context))
            } catch (e: IOException) {
                Result.failure(e)
            }
        }
    }
    val shown = openFile
    if (shown != null) {
        LicenceText(LicenceList.Text(shown, openAnchor), insets) {
            openFile = null
            openAnchor = null
        }
        return
    }
    val open: (LicenceList.Text) -> Unit = {
        openFile = it.file
        openAnchor = it.anchor
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
            Text(
                stringResource(R.string.licences_title),
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.semantics { heading() },
            )
            Text(stringResource(R.string.licences_intro), style = MaterialTheme.typography.bodyMedium)
        }
        val loaded = listing
        when {
            loaded == null -> item { Text(stringResource(R.string.licences_opening), style = MaterialTheme.typography.bodyMedium) }
            loaded.isFailure -> item { Text(stringResource(R.string.licences_unreadable), style = MaterialTheme.typography.bodyMedium) }
            else -> {
                val list = loaded.getOrThrow()
                item { Heading(stringResource(R.string.licences_texts_title)) }
                items(list.files) { file -> FullText(file, describe(file, list.library(file))) { open(LicenceList.Text(file)) } }
                item { Heading(stringResource(R.string.licences_jvm_title)) }
                item {
                    Part(LicenceList.Component(stringResource(R.string.licences_own), null, "Apache-2.0", listOf(LicenceList.Text(LicenceList.LICENSE))), open)
                }
                items(list.jvm) { Part(it, open) }
                for ((file, crates) in list.native) {
                    item { Heading(stringResource(R.string.licences_native_title, isolateLtr(crates.library ?: file))) }
                    items(crates.crates) { Part(it, open) }
                    items(crates.unread) { line ->
                        Text(stringResource(R.string.licences_unread, isolateLtr(line)), style = MaterialTheme.typography.bodySmall)
                    }
                }
                // The data pack's databases, whose licences the Data sources page shows with each (W7, part 2, fix round,
                // screens review m6): the APK carries them too.
                item {
                    Heading(stringResource(R.string.licences_data_title))
                    Text(stringResource(R.string.licences_data_note), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun describe(file: String, library: String?): String = when {
    file == "NOTICE" -> stringResource(R.string.licences_text_notice)
    file == LicenceList.LICENSE -> stringResource(R.string.licences_text_licence)
    file.startsWith("native-") -> stringResource(R.string.licences_text_native, isolateLtr(library ?: file))
    file == "MPL-2.0.txt" -> stringResource(R.string.licences_text_mpl)
    file == "gotatun-BSD-3-Clause.txt" -> stringResource(R.string.licences_text_gotatun)
    else -> stringResource(R.string.licences_text_other)
}

@Composable
private fun Heading(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(top = 16.dp).semantics { heading() },
    )
}

/** A full text: its file's name and what it is; the whole row opens it. */
@Composable
private fun FullText(file: String, description: String, onOpen: () -> Unit) {
    val label = stringResource(R.string.licences_read, isolateLtr(file))
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(role = Role.Button, onClickLabel = label, onClick = onOpen)
            .padding(vertical = 4.dp),
    ) {
        Text(file, style = MaterialTheme.typography.titleSmall.copy(textDirection = TextDirection.Ltr))
        Text(description, style = MaterialTheme.typography.bodyMedium)
    }
}

/** A part of the app: its name and version, its licence, and a button for each text that covers it. */
@Composable
private fun Part(component: LicenceList.Component, onOpen: (LicenceList.Text) -> Unit) {
    Column {
        HorizontalDivider(Modifier.padding(bottom = 4.dp))
        val name = listOfNotNull(component.name, component.version).joinToString(" ")
        Text(name, style = MaterialTheme.typography.titleSmall.copy(textDirection = TextDirection.Ltr))
        Text(
            component.licence,
            style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        for (text in component.texts) {
            TextButton(onClick = { onOpen(text) }) { Text(stringResource(R.string.licences_read, isolateLtr(text.file))) }
        }
    }
}

/**
 * One full text, read off the main thread and shown paragraph by paragraph, so that a list of some thousand lines
 * is never one Text; opened at the paragraph of [text]'s anchor, where the part's own text begins. Left to right and
 * selectable, as licences are copied.
 */
@Composable
private fun LicenceText(text: LicenceList.Text, insets: PaddingValues, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    val context = LocalContext.current
    val paragraphs by produceState<Result<List<String>>?>(null, text.file) {
        value = withContext(Dispatchers.IO) {
            try {
                Result.success(LicenceList.paragraphs(read(context, text.file)))
            } catch (e: IOException) {
                Result.failure(e)
            }
        }
    }
    val state = rememberLazyListState()
    var placed by rememberSaveable(text.file, text.anchor) { mutableStateOf(false) }
    LaunchedEffect(paragraphs) {
        val loaded = paragraphs?.getOrNull() ?: return@LaunchedEffect
        if (!placed) {
            // The first item is the heading; the anchor's paragraph comes after it.
            val at = LicenceList.anchorIn(loaded, text.anchor)
            if (at > 0) state.scrollToItem(1 + at)
            placed = true
        }
    }
    LazyColumn(
        state = state,
        modifier = Modifier.fillMaxSize().padding(insets),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.licences_back)) }
            Text(
                text.file,
                style = MaterialTheme.typography.headlineSmall.copy(textDirection = TextDirection.Ltr),
                modifier = Modifier.semantics { heading() },
            )
        }
        val loaded = paragraphs
        when {
            loaded == null -> item { Text(stringResource(R.string.licences_opening), style = MaterialTheme.typography.bodyMedium) }
            loaded.isFailure -> item { Text(stringResource(R.string.licences_unreadable), style = MaterialTheme.typography.bodyMedium) }
            else -> items(loaded.getOrThrow()) { paragraph ->
                SelectionContainer {
                    Text(paragraph, style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr))
                }
            }
        }
    }
}
