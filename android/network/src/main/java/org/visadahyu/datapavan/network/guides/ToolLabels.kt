package org.visadahyu.datapavan.network.guides

import android.content.Context
import java.util.Locale
import org.visadahyu.datapavan.labels.OtherAppResources

/**
 * A tool's labels as the guide quotes them (ADR 0041, "How the per-tool guides are built"). A tool speaks the phone's
 * language, or the one the user chose in the tool; Android does not tell another app which (LocaleManager answers only
 * the app itself, its installer and the keyboard). So each label is read from the installed tool, by the resource name
 * the data records, in the phone's language, and also in Datapavan's own language where that differs, since a user who
 * chose a language for Datapavan has likely chosen it for the tool too. A label the tool does not keep as an Android
 * resource (Flutter's i18n files, text written in code), or that the installed version no longer has, is the data's,
 * in the first of those languages the source has, else in English. Nothing of the tool is decompiled, and no code of it
 * runs: Android reads its resource table, as a launcher reads an app's name. The reading itself is the shared
 * module's [OtherAppResources] since ADR 0054, which reads Android's own labels the same way.
 */
class ToolLabels(
    private val book: GuideBook,
    private val guide: Guide,
    /** The label at [Resource] in the tool, in the language of the locales given, or null when it has none. */
    private val read: (Resource, List<Locale>) -> String?,
    /** The phone's languages, and Datapavan's own, first first. */
    private val phone: List<Locale>,
    private val own: List<Locale>,
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
                val second = if (ownFirst != null && !OtherAppResources.sameWords(ownFirst, phone.firstOrNull()) && hasLanguage(resource, ownFirst)) {
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

    /**
     * Whether the installed tool has its own words for [resource] in [locale]'s language. Android gives a tool's default
     * words, often English, for a language it lacks, and a tool installed from Google Play in language splits has only
     * the phone's languages. So a language is there when the label read in it differs from the tool's default words, the
     * ones read for a language no app has; English is taken as there, since it is most tools' default. (W8, part 3b,
     * asked Android which languages the tool's APKs hold, which also counts the framework's, so every language looked
     * present: ADR 0054's audit, M4.)
     */
    private fun hasLanguage(resource: Resource, locale: Locale): Boolean =
        locale.language == "en" || read(resource, listOf(locale)) != read(resource, listOf(NO_LANGUAGE))

    private fun recorded(rows: List<ToolLabel>, locales: List<Locale>): String? =
        locales.asSequence().mapNotNull { locale -> rows.firstOrNull { it.lang == language(locale) }?.text }.firstOrNull()

    companion object {
        /** The longest label shown; a longer one is cut, so that no tool's resource can fill the screen. */
        const val MAX = OtherAppResources.MAX

        /** A language no app has words in, for which Android gives an app's default words. */
        val NO_LANGUAGE: Locale = Locale.forLanguageTag("zz")

        /** The data's language code for [locale]: its language, with Chinese only in its simplified script. */
        fun language(locale: Locale): String? = when {
            OtherAppResources.traditionalChinese(locale) -> null
            else -> locale.language.takeIf { it.isNotEmpty() }
        }

        /** As [OtherAppResources.clean]: one line, no direction overrides, at most [MAX] characters. */
        fun clean(text: String): String = OtherAppResources.clean(text)

        /**
         * Reads labels from the installed [packageName]: its resources opened for the locales asked, without its code.
         * Null when the package is not installed or Android cannot open it. Advanced sees every app (the audit's
         * QUERY_ALL_PACKAGES, ADR 0014), and the network part's own launcher query (ADR 0034) covers any tool a user
         * can open.
         */
        fun reader(context: Context, packageName: String): ((Resource, List<Locale>) -> String?)? =
            OtherAppResources.reader(context, packageName)?.let { read -> { resource, locales -> read(resource.type, resource.name, resource.index, locales) } }
    }
}
