package org.visadahyu.datapavan.labels

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import java.util.Locale

/**
 * [SystemLabels] on this phone (ADR 0054): the rows from the data pack, its maker and Android version, its languages
 * and Datapavan's, labels read only from system apps, and Datapavan's copies of AOSP's texts as the fallback. One per
 * screen, made for the screen's locales; nothing is read until a label is asked for.
 */
object PhoneLabels {
    /**
     * [rows] gives labels.tsv's text from the data pack (`DataPackStore.text(LabelRow.PATH)`, so that an imported pack's
     * rows win); [fallback] the string resource of Datapavan's copy of a key's AOSP text on this Android version, or null.
     * [phone] and [own] are the phone's languages and Datapavan's, which the debug dump sets to one language at a time.
     */
    fun of(
        context: Context,
        rows: () -> String?,
        fallback: (key: String, sdk: Int) -> Int?,
        phone: List<Locale> = PhoneLocales.of(context),
        own: List<Locale> = PhoneLocales.own(context),
    ): SystemLabels {
        val readers = HashMap<String, ((String, String, Int?, List<Locale>) -> String?)?>()
        val contexts = HashMap<Locale, Context>()
        val sdk = Build.VERSION.SDK_INT
        return SystemLabels(
            rows = { rows()?.let(LabelRow::parse).orEmpty() },
            maker = Build.MANUFACTURER.orEmpty().lowercase(Locale.ROOT),
            sdk = sdk,
            phone = phone,
            own = own,
            read = { packageName, type, name, locales ->
                val reader = synchronized(readers) {
                    readers.getOrPut(packageName) { if (isSystem(context, packageName)) OtherAppResources.reader(context, packageName) else null }
                }
                reader?.invoke(type, name, null, locales)
            },
            handler = { action -> handler(context, action) },
            fallback = { key, locale ->
                fallback(key, sdk)?.let { id ->
                    if (locale == null) {
                        context.getString(id)
                    } else {
                        synchronized(contexts) { contexts.getOrPut(locale) { inLocale(context, locale) } }.getString(id)
                    }
                }
            },
        )
    }

    /** Whether [packageName] is installed as part of the system image (m12: labels come only from system apps). */
    fun isSystem(context: Context, packageName: String): Boolean = try {
        context.packageManager.getApplicationInfo(packageName, 0).flags and ApplicationInfo.FLAG_SYSTEM != 0
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    /**
     * The system app that opens [action] for Datapavan's own package (the audit's M5): null when none does, when Android
     * would ask which app to use (its chooser, in the package "android"), or when the app is not a system app.
     */
    fun handler(context: Context, action: String): String? {
        val withPackage = Intent(action, Uri.fromParts("package", context.packageName, null))
        val info = context.packageManager.resolveActivity(withPackage, 0)?.activityInfo
            ?: context.packageManager.resolveActivity(Intent(action), 0)?.activityInfo
            ?: return null
        return info.packageName.takeIf { it != "android" && isSystem(context, it) }
    }

    /** Datapavan's own resources in [locale], for its copy of a label in the phone's language. */
    @SuppressLint("AppBundleLocaleChanges") // Datapavan carries every language's strings in one APK.
    fun inLocale(context: Context, locale: Locale): Context =
        context.createConfigurationContext(Configuration(context.resources.configuration).apply { setLocale(locale) })
}
