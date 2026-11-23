package org.visadahyu.datapavan.network.ui

import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.labels.PhoneLabels
import org.visadahyu.datapavan.labels.SystemLabels
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.NetworkPacks

/**
 * Android's own labels as the network part's screens quote them (ADR 0054): read from the phone's Settings in
 * the phone's language, with Datapavan's beside them where the two differ, else Datapavan's copy of AOSP's text.
 * NetworkTheme gives each screen one [SystemLabels] for its locales, which reads nothing until a label is asked for.
 */
internal object AndroidLabels {
    /**
     * Datapavan's copy of each key's AOSP text (android_label_* in strings.xml), from the release most phones run; a
     * key whose text changes later has a second string from that Android version on, picked by Build.VERSION.SDK_INT.
     */
    private val FALLBACKS: Map<String, List<Pair<Int, Int>>> = mapOf(
        "private_dns" to listOf(0 to R.string.android_label_private_dns),
        "private_dns_off" to listOf(0 to R.string.android_label_private_dns_off),
        "private_dns_automatic" to listOf(0 to R.string.android_label_private_dns_automatic),
        "always_on_vpn" to listOf(0 to R.string.android_label_always_on_vpn),
        "usage_access" to listOf(36 to R.string.android_label_usage_access_api36, 0 to R.string.android_label_usage_access),
        "screen_lock" to listOf(
            37 to R.string.android_label_screen_lock_api37,
            36 to R.string.android_label_screen_lock_api36,
            0 to R.string.android_label_screen_lock,
        ),
    )

    val keys: Set<String> get() = FALLBACKS.keys

    /** Every fallback string, for the check that each android_label_* resource has its key. */
    val strings: List<Int> get() = FALLBACKS.values.flatten().map { it.second }

    @StringRes
    fun fallback(key: String, sdk: Int): Int? = FALLBACKS[key]?.firstOrNull { sdk >= it.first }?.second

    /** Each key's strings with the Android version they hold from, for the check against their names' _apiN. */
    val thresholds: Map<String, List<Pair<Int, Int>>> get() = FALLBACKS

    /**
     * The labels for [context]'s screens, from [rows], the text of labels.tsv in the data pack in use (an imported one's
     * rows win), and the phone.
     */
    fun of(context: Context, rows: String?): SystemLabels = PhoneLabels.of(context, rows = { rows }, fallback = ::fallback)

    /** labels.tsv's text from the data pack in use; it parses the pack, so never on the main thread (the fix round's m3). */
    fun rows(context: Context): String = runCatching { DataPackStore.read(context, NetworkPacks).text(LabelRow.PATH) }.getOrNull().orEmpty()
}

/**
 * A screen's labels: [labels] for its locales, and whether the data pack's rows are read yet ([ready]). Until they
 * are, the labels are Datapavan's copies of AOSP's texts, and no note says so.
 */
internal data class ScreenLabels(val labels: SystemLabels, val ready: Boolean)

/** The labels of a screen, which NetworkTheme sets for its locales. */
internal val LocalAndroidLabels = staticCompositionLocalOf<ScreenLabels?> { null }

/** The labels for this screen's locales, the data pack's rows read on a thread of their own. */
@Composable
internal fun rememberAndroidLabels(): ScreenLabels {
    val context = LocalContext.current
    val locales = LocalConfiguration.current.locales
    val rows = remember(context) { mutableStateOf<String?>(null) }
    DisposableEffect(context) {
        Thread { rows.value = AndroidLabels.rows(context) }.apply { name = "android-labels" }.start()
        onDispose { }
    }
    val text = rows.value
    return remember(context, locales, text) { ScreenLabels(AndroidLabels.of(context, text), ready = text != null) }
}

@Composable
private fun screenLabels(): ScreenLabels = LocalAndroidLabels.current ?: rememberAndroidLabels()

/** An Android label as a sentence quotes it: each part in its own direction, Datapavan's beside the phone's. */
@Composable
internal fun quotedLabel(key: String): String {
    val labels = screenLabels().labels
    val both = stringResource(R.string.label_with_own)
    return remember(labels, key, both) { labels.label(key).quoted { first, second -> String.format(both, first, second) } }
}

/** An Android label standing alone, as a heading: plain, or both parts isolated where there are two. */
@Composable
internal fun labelAlone(key: String): String {
    val labels = screenLabels().labels
    val both = stringResource(R.string.label_with_own)
    return remember(labels, key, both) {
        val label = labels.label(key)
        if (label.also == null) label.text else label.quoted { first, second -> String.format(both, first, second) }
    }
}

/**
 * Under a part that names Android's settings or switches [keys]: names those of them that are Android's own names
 * rather than this phone's (the audit's C2, the fix round's M1): this phone's maker has not been seen to show them, or
 * the phone gave none. Nothing is said before the data pack's rows are read.
 */
@Composable
internal fun AndroidLabelsNote(vararg keys: String) {
    val screen = screenLabels()
    val named = remember(screen, keys.toList()) { if (screen.ready) screen.labels.androids(keys.toList()) else emptyList() }
    if (named.isEmpty()) return
    val both = stringResource(R.string.label_with_own)
    val quote = stringResource(R.string.label_named)
    val separator = stringResource(R.string.labels_list_separator)
    val list = named.joinToString(separator) { label -> String.format(quote, label.quoted { first, second -> String.format(both, first, second) }) }
    Text(stringResource(R.string.labels_android_note, list), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}
