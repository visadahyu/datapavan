package org.visadahyu.datapavan.audit

/**
 * App stores whose installs are not reported as an unknown source, with the names people know them by.
 * The names are proper nouns and stay untranslated. They come from this list, never from the
 * installer's own label, which any app can choose.
 */
object Stores {
    val names: Map<String, String> = mapOf(
        "com.android.vending" to "Google Play",
        "com.sec.android.app.samsungapps" to "Galaxy Store",
        "org.fdroid.fdroid" to "F-Droid",
        "org.fdroid.basic" to "F-Droid",
        "com.aurora.store" to "Aurora Store",
        "com.huawei.appmarket" to "AppGallery",
        "com.xiaomi.market" to "GetApps",
    )
}

/** Where an app came from, said in one line on its page. */
sealed interface InstallSource {
    /** Came with the phone, with no installer recorded. */
    data object Preinstalled : InstallSource

    /** Came with the phone; Android records [source] (a store's name or a package) as its installer. */
    data class PreinstalledWith(val source: String) : InstallSource

    /** Installed from one of the [Stores]. */
    data class FromStore(val store: String) : InstallSource

    /**
     * Installed by another app, such as a file manager or a browser. Its package name always shows,
     * since its [label] is the app's own choice.
     */
    data class ByApp(val label: String?, val packageName: String) : InstallSource

    /** Installed by the user, and Android records no installer, as after an install from a computer. */
    data object Unknown : InstallSource

    companion object {
        /** [installerLabel] is the installer's label on this phone, if it is installed. */
        fun of(isSystem: Boolean, installer: String?, installerLabel: String?): InstallSource {
            val store = Stores.names[installer]
            return when {
                isSystem && installer == null -> Preinstalled
                isSystem -> PreinstalledWith(store ?: installer!!)
                store != null -> FromStore(store)
                installer != null -> ByApp(installerLabel?.takeIf { it.isNotBlank() && it != installer }, installer)
                else -> Unknown
            }
        }
    }
}
