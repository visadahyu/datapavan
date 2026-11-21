package org.visadahyu.datapavan.watch.guides

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.content.res.Resources
import android.os.LocaleList
import java.util.Locale

/**
 * A tool's labels as the guide quotes them (ADR 0041, "How the per-tool guides are built"). A tool speaks the phone's
 * language, or the one the user chose in the tool; Android does not tell another app which (LocaleManager answers only
 * the app itself, its installer and the keyboard). So each label is read from the installed tool, by the resource name
 * the data records, in the phone's language, and also in Datapavan's own language where that differs, since a user who
 * chose a language for Datapavan has likely chosen it for the tool too. A label the tool does not keep as an Android
 * resource (Flutter's i18n files, text written in code), or that the installed version no longer has, is the data's,
 * in the first of those languages the source has, else in English. Nothing of the tool is decompiled, and no code of it
 * runs: Android reads its resource table, as a launcher reads an app's name.
 */
class ToolLabels(
    private val book: GuideBook,
    private val guide: Guide,
    /** The label at [Resource] in the tool, in the language of the locales given, or null when it has none. */
    private val read: (Resource, List<Locale>) -> String?,
    /** The phone's languages, and Datapavan's own, first first. */
    private val phone: List<Locale>,
    private val own: List<Locale>,
    /**
     * Whether the installed tool has its own words in a language. Android gives a tool's default words, often English,
     * for a language it lacks, and a tool installed from Google Play in language splits has only the phone's languages:
     * Datapavan's language is added beside the phone's only where the tool has it.
     */
    private val hasLanguage: (Locale) -> Boolean = { true },
) {
    /** One label as shown: [text] first, and [also] in Datapavan's language when the tool's differs. */
    data class Shown(val text: String, val also: String?, val fromTool: Boolean)

    /** Whether any label shown so far came from the installed tool; the screen says which. */
    var anyFromTool = false
        private set

    fun shown(key: String): Shown {
        val rows = book.label(guide.id, key)
        val resource = rows.firstOrNull { it.resource != null }?.resource
        if (resource != null) {
            val first = read(resource, phone)?.let(::clean)
            if (first != null) {
                anyFromTool = true
                val ownFirst = own.firstOrNull()
                val second = if (ownFirst != null && ownFirst.language != phone.firstOrNull()?.language && hasLanguage(ownFirst)) {
                    read(resource, own)?.let(::clean)
                } else {
                    null
                }
                return Shown(first, second?.takeIf { it != first }, fromTool = true)
            }
        }
        val first = recorded(rows, phone) ?: rows.firstOrNull { it.lang == "en" }?.text ?: key
        val second = recorded(rows, own)?.takeIf { it != first }
        return Shown(clean(first), second?.let(::clean), fromTool = false)
    }

    private fun recorded(rows: List<ToolLabel>, locales: List<Locale>): String? =
        locales.asSequence().mapNotNull { locale -> rows.firstOrNull { it.lang == language(locale) }?.text }.firstOrNull()

    companion object {
        /** The longest label shown; a longer one is cut, so that no tool's resource can fill the screen. */
        const val MAX = 80

        /** The data's language code for [locale]: its language, with Chinese only in its simplified script. */
        fun language(locale: Locale): String? {
            val traditional = locale.script == "Hant" || locale.country in setOf("TW", "HK", "MO")
            return when {
                locale.language == "zh" && traditional -> null
                else -> locale.language.takeIf { it.isNotEmpty() }
            }
        }

        /**
         * A label fit to quote: one line, no control or direction-override characters (which could turn the sentence
         * around it), at most [MAX] characters. The screen isolates it in the sentence's direction.
         */
        fun clean(text: String): String {
            val flat = text.filterNot { Character.getType(it) == Character.CONTROL.toInt() || it in OVERRIDES }
                .replace(Regex("\\s+"), " ").trim()
            return if (flat.length <= MAX) flat else flat.take(MAX - 1).trimEnd() + "…"
        }

        private val OVERRIDES = setOf('‎', '‏', '‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩', '؜')

        /**
         * Reads labels from the installed [packageName]: its resources opened for the locales asked, without its code.
         * Null when the package is not installed or Android cannot open it. Advanced sees every app (the audit's
         * QUERY_ALL_PACKAGES, ADR 0014), and Watch's own launcher query (ADR 0034) covers any tool a user can open.
         */
        @SuppressLint("AppBundleLocaleChanges") // Watch reads another app's resources for a locale; its own stays as it is.
        fun reader(context: Context, packageName: String): ((Resource, List<Locale>) -> String?)? {
            val tool = try {
                context.createPackageContext(packageName, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                return null
            } catch (e: SecurityException) {
                return null
            }
            val cache = HashMap<List<Locale>, Resources>()
            return { resource, locales ->
                val resources = cache.getOrPut(locales) {
                    val configuration = Configuration(tool.resources.configuration).apply { setLocales(LocaleList(*locales.toTypedArray())) }
                    tool.createConfigurationContext(configuration).resources
                }
                read(resources, packageName, resource)
            }
        }

        /** The languages [packageName]'s resources have words in, as its installed APKs hold them; null when it cannot be read. */
        fun languages(context: Context, packageName: String): Set<String>? = try {
            context.createPackageContext(packageName, 0).assets.locales.mapNotNull { tag ->
                Locale.forLanguageTag(tag.replace('_', '-')).language.takeIf { it.isNotEmpty() }
            }.toSet()
        } catch (e: PackageManager.NameNotFoundException) {
            null
        } catch (e: SecurityException) {
            null
        }

        /**
         * One label of another app's [resources] by its name. The name is all Watch has of the tool's resources, so the
         * lookup is by name: Android's own launchers read app labels so too. An array item comes through a typed
         * array, which also reads a plain `<array>` of strings.
         */
        @SuppressLint("DiscouragedApi")
        fun read(resources: Resources, packageName: String, resource: Resource): String? = try {
            val id = resources.getIdentifier(resource.name, resource.type, packageName)
            when {
                id == 0 -> null
                resource.type == "string" -> resources.getString(id)
                else -> resources.obtainTypedArray(id).let { items ->
                    try {
                        resource.index?.takeIf { it in 0 until items.length() }?.let { items.getString(it) }
                    } finally {
                        items.recycle()
                    }
                }
            }?.takeIf { it.isNotBlank() }
        } catch (e: Resources.NotFoundException) {
            null
        }
    }
}
