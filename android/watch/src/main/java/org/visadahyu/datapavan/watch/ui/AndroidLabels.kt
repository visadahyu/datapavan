package org.visadahyu.datapavan.watch.ui

import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.labels.LabelSource
import org.visadahyu.datapavan.labels.PhoneLabels
import org.visadahyu.datapavan.labels.SystemLabels
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.WatchPacks

/**
 * Android's own labels as the network monitoring's screens quote them (ADR 0054): read from the phone's Settings in
 * the phone's language, with Datapavan's beside them where the two differ, else Datapavan's copy of AOSP's text.
 * WatchTheme gives each screen one [SystemLabels] for its locales, which reads nothing until a label is asked for.
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

    /** The labels for [context]'s screens, read from the data pack in use (an imported one's rows win) and the phone. */
    fun of(context: Context): SystemLabels =
        PhoneLabels.of(context, rows = { DataPackStore.read(context, WatchPacks).text(LabelRow.PATH) }, fallback = ::fallback)
}

/** The labels of a screen, which WatchTheme sets for its locales. */
internal val LocalAndroidLabels = staticCompositionLocalOf<SystemLabels?> { null }

@Composable
internal fun rememberAndroidLabels(): SystemLabels {
    val context = LocalContext.current
    val locales = LocalConfiguration.current.locales
    return remember(context, locales) { AndroidLabels.of(context) }
}

@Composable
private fun labels(): SystemLabels = LocalAndroidLabels.current ?: rememberAndroidLabels()

/** An Android label as a sentence quotes it: each part in its own direction, Datapavan's beside the phone's. */
@Composable
internal fun quotedLabel(key: String): String {
    val labels = labels()
    val both = stringResource(R.string.label_with_own)
    return remember(labels, key, both) { labels.label(key).quoted { first, second -> String.format(both, first, second) } }
}

/** An Android label standing alone, as a heading: plain, or both parts isolated where there are two. */
@Composable
internal fun labelAlone(key: String): String {
    val labels = labels()
    val both = stringResource(R.string.label_with_own)
    return remember(labels, key, both) {
        val label = labels.label(key)
        if (label.also == null) label.text else label.quoted { first, second -> String.format(both, first, second) }
    }
}

/**
 * Whether a part that quotes Android's labels [keys] must say they are Android's own names: one of them was not read
 * from this phone as its screen names it (the audit's C2), since the phone's maker has rows for other labels only, or
 * the phone gave none.
 */
@Composable
internal fun labelsAreAndroids(vararg keys: String): Boolean {
    val labels = labels()
    return remember(labels, keys.toList()) { keys.any { labels.label(it).source != LabelSource.PHONE } }
}

/** Under a part that quotes Android's labels [keys]: says they are Android's own names where [labelsAreAndroids]. */
@Composable
internal fun AndroidLabelsNote(vararg keys: String) {
    if (labelsAreAndroids(*keys)) {
        Text(stringResource(R.string.labels_android_note), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
