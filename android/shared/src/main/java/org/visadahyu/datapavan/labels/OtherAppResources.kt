package org.visadahyu.datapavan.labels

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.content.res.Resources
import android.os.LocaleList
import java.util.Locale

/**
 * Words of another app's interface, read from its resources as a launcher reads an app's name: the tools' labels for
 * the per-tool guides (ADR 0041, "How the per-tool guides are built") and Android's own labels from the system's
 * Settings (ADR 0054). The package's resources are opened without its code (`createPackageContext` with no flags), for
 * the locales asked, and a resource is looked up by the name the data records. Nothing is decompiled, and nothing of
 * the other app runs. In the shared module since ADR 0054, so that both editions read the same way.
 */
object OtherAppResources {
    /** The longest label shown; a longer one is cut, so that no app's resource can fill the screen. */
    const val MAX = 80

    /**
     * A label fit to quote: one line, a control character turned into a space, no direction characters (which could turn
     * the sentence around it), no soft hyphen or zero-width space, at most [MAX] characters. Only ASCII's whitespace
     * collapses, so a French no-break space before a colon stays. The screen isolates it: a tool's label in its own
     * direction, Android's in the direction of the language it was read in (ADR 0054), since a right-to-left label that begins with a Latin word ("DNS
     * خصوصی") would otherwise be laid out left to right.
     */
    fun clean(text: String): String {
        val flat = text.filterNot { it in DIRECTION_MARKS }
            .map { if (Character.getType(it) == Character.CONTROL.toInt()) ' ' else it }.joinToString("")
            .replace(SPACES, " ").trim(' ', '\t', '\n', '\u000B', '\u000C', '\r')
        if (flat.codePointCount(0, flat.length) <= MAX) return flat
        // Cut by code point, so that no character outside the basic plane is split in two.
        return flat.substring(0, flat.offsetByCodePoints(0, MAX - 1)).trimEnd() + "…"
    }

    /**
     * ASCII's whitespace, written out: Android's regular expressions, which are ICU's, take a no-break space for \s where
     * the JVM's do not, and a French label's no-break space before its colon must stay on the phone as in the tests.
     */
    private val SPACES = Regex("[ \t\n\u000B\u000C\r]+")

    /** Direction marks, overrides and isolates, and the soft hyphen and zero-width space that AOSP's German has. */
    private val DIRECTION_MARKS = setOf('‎', '‏', '‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩', '؜', '\u00AD', '\u200B')

    /**
     * Reads labels from the installed [packageName]: its resources opened for the locales asked, without its code, one
     * configuration per list of locales. Null when the package is not installed or Android cannot open it. Package
     * visibility: every edition holds QUERY_ALL_PACKAGES for the audit (ADR 0014), which shows every package.
     */
    @SuppressLint("AppBundleLocaleChanges") // Another app's resources are read for a locale; Datapavan's own stay as they are.
    fun reader(context: Context, packageName: String): ((type: String, name: String, index: Int?, locales: List<Locale>) -> String?)? {
        val other = try {
            context.createPackageContext(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            return null
        } catch (e: SecurityException) {
            return null
        }
        // The name its resource table goes by, which can differ from the package's: Google's permission controller,
        // com.google.android.permissioncontroller, keeps AOSP's com.android.permissioncontroller there (seen on the
        // Android 11 emulator, 2026-11-22), so a lookup by the package's own name finds nothing.
        val table = resourcePackage(other.resources, other.applicationInfo.labelRes) ?: packageName
        val cache = HashMap<List<Locale>, Resources>()
        return { type, name, index, locales ->
            val resources = synchronized(cache) {
                cache.getOrPut(locales) {
                    val configuration = Configuration(other.resources.configuration).apply { setLocales(LocaleList(*locales.toTypedArray())) }
                    other.createConfigurationContext(configuration).resources
                }
            }
            read(resources, table, type, name, index)
        }
    }

    /** The package name of [resources]' own table, from one of its resources ([id], the app's label), or null. */
    fun resourcePackage(resources: Resources, id: Int): String? =
        if (id == 0) null else runCatching { resources.getResourcePackageName(id) }.getOrNull()

    /**
     * One label of another app's [resources] by its name. The name is all Datapavan has of the other app's
     * resources, so the lookup is by name: Android's own launchers read app labels so too. An array item comes
     * through a typed array, which also reads a plain `<array>` of strings.
     */
    @SuppressLint("DiscouragedApi")
    fun read(resources: Resources, packageName: String, type: String, name: String, index: Int?): String? = try {
        val id = resources.getIdentifier(name, type, packageName)
        when {
            id == 0 -> null
            type == "string" -> resources.getString(id)
            else -> resources.obtainTypedArray(id).let { items ->
                try {
                    index?.takeIf { it in 0 until items.length() }?.let { items.getString(it) }
                } finally {
                    items.recycle()
                }
            }
        }?.takeIf { it.isNotBlank() }
    } catch (e: Resources.NotFoundException) {
        null
    }

    /** Whether [locale] is Chinese in its traditional script, which Datapavan's Simplified Chinese does not serve. */
    fun traditionalChinese(locale: Locale): Boolean =
        locale.language == "zh" && (locale.script == "Hant" || (locale.script.isEmpty() && locale.country in setOf("TW", "HK", "MO")))

    /**
     * Whether two locales read the same words: the same language and, for Chinese, the same script, so that a phone in
     * Traditional Chinese with Datapavan in Simplified gets both (m6 of ADR 0054's audit).
     */
    fun sameWords(a: Locale?, b: Locale?): Boolean =
        a != null && b != null && a.language == b.language && (a.language != "zh" || traditionalChinese(a) == traditionalChinese(b))
}
