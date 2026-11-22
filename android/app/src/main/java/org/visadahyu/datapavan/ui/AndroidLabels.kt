package org.visadahyu.datapavan.ui

import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.SpecialAccess
import org.visadahyu.datapavan.core.NativePacks
import org.visadahyu.datapavan.datapack.DataPackStore
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.labels.PhoneLabels
import org.visadahyu.datapavan.labels.SystemLabels

/**
 * Android's own labels as the audit's screens quote them (ADR 0054): read from the phone's Settings in the phone's
 * language, with Datapavan's beside them where the two differ, else Datapavan's copy of AOSP's text. Every screen of
 * the activity shares one [SystemLabels], made for its locales ([LocalAndroidLabels], set by MainActivity).
 */
internal object AndroidLabels {
    /**
     * Datapavan's copy of each key's AOSP text (android_label_* in strings.xml), from the release most phones run; a
     * key whose text changes later has a second string from that Android version on, picked by Build.VERSION.SDK_INT.
     */
    private val FALLBACKS: Map<String, List<Pair<Int, Int>>> = mapOf(
        "usage_access" to listOf(36 to R.string.android_label_usage_access_api36, 0 to R.string.android_label_usage_access),
        "permit_usage_access" to listOf(36 to R.string.android_label_permit_usage_access_api36, 0 to R.string.android_label_permit_usage_access),
        "install_unknown_apps" to listOf(37 to R.string.android_label_install_unknown_apps_api37, 0 to R.string.android_label_install_unknown_apps),
        "device_admin" to listOf(
            37 to R.string.android_label_device_admin_api37,
            36 to R.string.android_label_device_admin_api36,
            0 to R.string.android_label_device_admin,
        ),
        "accessibility" to listOf(36 to R.string.android_label_accessibility_api36, 0 to R.string.android_label_accessibility),
        "battery_optimisation" to listOf(0 to R.string.android_label_battery_optimisation),
        "developer_options" to listOf(0 to R.string.android_label_developer_options),
        "usb_debugging" to listOf(0 to R.string.android_label_usb_debugging),
        "wireless_debugging" to listOf(0 to R.string.android_label_wireless_debugging),
        "encryption_credentials" to listOf(37 to R.string.android_label_encryption_credentials_api37, 0 to R.string.android_label_encryption_credentials),
        "disable" to listOf(0 to R.string.android_label_disable),
        "overlay" to listOf(36 to R.string.android_label_overlay_api36, 0 to R.string.android_label_overlay),
        "all_files_access" to listOf(0 to R.string.android_label_all_files_access),
        "notification_access" to listOf(0 to R.string.android_label_notification_access),
        "vpn" to listOf(0 to R.string.android_label_vpn),
        "unused_app_setting" to listOf(0 to R.string.android_label_unused_app_setting),
        "restricted_settings" to listOf(0 to R.string.android_label_restricted_settings),
    )

    val keys: Set<String> get() = FALLBACKS.keys

    /** Every fallback string, for the check that each android_label_* resource has its key. */
    val strings: List<Int> get() = FALLBACKS.values.flatten().map { it.second }

    /** Each key's strings with the Android version they hold from, for the check against their names' _apiN. */
    val thresholds: Map<String, List<Pair<Int, Int>>> get() = FALLBACKS

    @StringRes
    fun fallback(key: String, sdk: Int): Int? = FALLBACKS[key]?.firstOrNull { sdk >= it.first }?.second

    /** The labels for [context]'s screens, read from the data pack in use and the phone. */
    fun of(context: Context): SystemLabels =
        PhoneLabels.of(context, rows = { DataPackStore.get(context, NativePacks).text(LabelRow.PATH) }, fallback = ::fallback)

    /**
     * The label of a kind of special access where Android's own words name it; null where Datapavan's do. Device admin
     * is Datapavan's "Device admin" in a list of one app's access: Android's label names the page of all such apps.
     */
    fun special(access: SpecialAccess): String? = when (access) {
        SpecialAccess.OVERLAY -> "overlay"
        SpecialAccess.USAGE_ACCESS -> "usage_access"
        SpecialAccess.INSTALL_UNKNOWN_APPS -> "install_unknown_apps"
        SpecialAccess.ALL_FILES -> "all_files_access"
        SpecialAccess.DEVICE_ADMIN, SpecialAccess.ACCESSIBILITY, SpecialAccess.NOTIFICATION_LISTENER, SpecialAccess.BATTERY_EXEMPT -> null
    }
}

/** The labels of the activity's screens; MainActivity sets them for its locales. */
internal val LocalAndroidLabels = staticCompositionLocalOf<SystemLabels?> { null }

@Composable
private fun labels(): SystemLabels {
    val context = LocalContext.current
    val locales = LocalConfiguration.current.locales
    return LocalAndroidLabels.current ?: remember(context, locales) { AndroidLabels.of(context) }
}

/** An Android label as a sentence quotes it: each part in its own direction, Datapavan's beside the phone's. */
@Composable
internal fun quotedLabel(key: String): String {
    val labels = labels()
    val both = stringResource(R.string.label_both)
    return remember(labels, key, both) { labels.label(key).quoted { first, second -> String.format(both, first, second) } }
}

/** An Android label standing alone, as a button or a list item: plain, or both parts isolated where there are two. */
@Composable
internal fun labelAlone(key: String): String {
    val labels = labels()
    val both = stringResource(R.string.label_both)
    return remember(labels, key, both) {
        val label = labels.label(key)
        if (label.also == null) label.text else label.quoted { first, second -> String.format(both, first, second) }
    }
}

/**
 * An Android label as an item of a list inside a sentence ("It holds: …", "To undo, turn back on: …"): always isolated
 * in its language's direction, so that two right-to-left items keep their order around the comma.
 */
@Composable
internal fun labelInList(key: String): String {
    val labels = labels()
    val both = stringResource(R.string.label_both)
    return remember(labels, key, both) { labels.label(key).quoted { first, second -> String.format(both, first, second) } }
}

/** A kind of special access by its name, as an item of a list: Android's label where Android's words name it, else Datapavan's. */
@Composable
internal fun specialText(access: SpecialAccess): String =
    AndroidLabels.special(access)?.let { labelInList(it) } ?: stringResource(specialName(access) ?: R.string.detail_none)

/**
 * Under a part that names Android's pages, switches or buttons [keys]: names those of them that are Android's own
 * names rather than this phone's (the audit's C2, the fix round's M1): this phone's maker has not been seen to show
 * them, or the phone gave none.
 */
@Composable
internal fun AndroidLabelsNote(keys: List<String>) {
    val labels = labels()
    val named = remember(labels, keys) { labels.androids(keys) }
    if (named.isEmpty()) return
    val both = stringResource(R.string.label_both)
    val quote = stringResource(R.string.label_named)
    val separator = stringResource(R.string.list_separator)
    val list = named.joinToString(separator) { label -> String.format(quote, label.quoted { first, second -> String.format(both, first, second) }) }
    Note(stringResource(R.string.android_labels_android, list))
}
