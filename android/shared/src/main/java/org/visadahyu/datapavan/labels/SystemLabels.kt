package org.visadahyu.datapavan.labels

import java.util.Locale
import org.visadahyu.datapavan.ui.isolateIn

/**
 * One row of `data/android-labels/labels.tsv` (ADR 0054): a place to read a label of Android's own screens from, for
 * a maker ("aosp" for any phone) and a range of Android versions. [packageName] is a package, or null where [handler]
 * names the intent action whose system app holds the label.
 */
data class LabelRow(
    val key: String,
    val maker: String,
    val apis: IntRange,
    val packageName: String?,
    val handler: String?,
    val type: String,
    val name: String,
    val verified: String?,
) {
    companion object {
        /** The dataset's path in the data pack, read through DataPackStore so that an imported pack's rows win. */
        const val PATH = "android-labels/labels.tsv"

        private val API = Regex("""(\d+)-(\d*)""")

        /** The rows of [text]; a row that is not well-formed is left out, as scripts/android-labels.py refuses it. */
        fun parse(text: String): List<LabelRow> = text.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .mapNotNull { line ->
                val cells = line.split('\t')
                if (cells.size != 8 || cells[4] != "string") return@mapNotNull null
                val range = API.matchEntire(cells[2]) ?: return@mapNotNull null
                val low = range.groupValues[1].toInt()
                val high = range.groupValues[2].toIntOrNull() ?: Int.MAX_VALUE
                val handler = cells[3].removePrefix("handler:").takeIf { cells[3].startsWith("handler:") }
                LabelRow(
                    key = cells[0], maker = cells[1], apis = low..high,
                    packageName = cells[3].takeIf { handler == null }, handler = handler,
                    type = cells[4], name = cells[5], verified = cells[6].takeIf { it != "-" && it.isNotBlank() },
                )
            }.toList()
    }
}

/** Where a label shown came from, which decides how the screen words it. */
enum class LabelSource {
    /** Read from this phone: through its maker's row, seen on a screen, or through AOSP's name on a maker with no rows. */
    PHONE,

    /**
     * Read from this phone through AOSP's name, on a maker whose rows lack this label: Android's name as the maker's
     * Settings hold it, which its screen may not show (the audit's C2).
     */
    ANDROID,

    /** Datapavan's copy of AOSP's text, where the phone gave none. */
    FALLBACK,
}

/**
 * One label as shown: [text] in [locale], and [also], the same label in Datapavan's language ([alsoLocale]), where
 * that differs from the phone's.
 */
data class SystemLabel(
    val text: String,
    val locale: Locale?,
    val also: String?,
    val alsoLocale: Locale?,
    val source: LabelSource,
    /** The row that answered, or null for the fallback. */
    val row: LabelRow? = null,
) {
    /**
     * The label as a sentence quotes it: each part isolated in the direction of the language it is in, the second set
     * after the first by [both], Datapavan's translatable pattern ("%1$s (%2$s)", with full-width brackets in Chinese).
     */
    fun quoted(both: (String, String) -> String): String {
        val first = isolateIn(text, locale)
        return also?.let { both(first, isolateIn(it, alsoLocale)) } ?: first
    }
}

/**
 * Android's own labels, read from the phone's system apps at run time (ADR 0054), as part 3b reads the tools' labels:
 * Settings follows the phone's language, so a label is read in the phone's languages, and also in Datapavan's own
 * where that differs. The rows of the phone's maker are tried first, then AOSP's; a row's package is a system app or
 * the row is skipped. Where no row answers, the label is Datapavan's copy of AOSP's text: in the phone's language
 * where Datapavan has it, else in Datapavan's (the rule of the restricted-settings label before it). Each label is
 * read once; a screen keeps one of these for its locales, so a change of language reads them again.
 */
class SystemLabels(
    rows: () -> List<LabelRow>,
    /** Build.MANUFACTURER in lower case. */
    private val maker: String,
    /** Build.VERSION.SDK_INT. */
    private val sdk: Int,
    /** The phone's languages, first first, and Datapavan's own. */
    private val phone: List<Locale>,
    private val own: List<Locale>,
    /** A label of a system package by its resource, in the locales given; null when it has none or is no system app. */
    private val read: (packageName: String, type: String, name: String, locales: List<Locale>) -> String?,
    /** The system package that opens the intent [action], or null. */
    private val handler: (action: String) -> String?,
    /** Datapavan's copy of AOSP's text for a key, in a locale, or in Datapavan's own language for null. */
    private val fallback: (key: String, locale: Locale?) -> String?,
) {
    private val rows by lazy(rows)
    private val shown = HashMap<String, SystemLabel>()

    /** The label [key], read once. */
    fun label(key: String): SystemLabel = synchronized(shown) { shown.getOrPut(key) { find(key) } }

    /** Whether any of [keys] is worded as Android's name rather than as this phone's. */
    fun anyAndroids(keys: Collection<String>): Boolean = keys.any { label(it).source != LabelSource.PHONE }

    private fun find(key: String): SystemLabel {
        val theirs = rows.filter { it.key == key && it.maker == maker && sdk in it.apis }
        val aosp = rows.filter { it.key == key && it.maker == AOSP && sdk in it.apis }
        val makerHasRows = maker != AOSP && rows.any { it.maker == maker }
        for (row in theirs + aosp) {
            val packageName = row.packageName ?: row.handler?.let(handler) ?: continue
            val text = usable(row, read(packageName, row.type, row.name, phone)) ?: continue
            val source = if (row.maker == AOSP && makerHasRows) LabelSource.ANDROID else LabelSource.PHONE
            val ownFirst = own.firstOrNull()
            val also = if (ownFirst != null && !OtherAppResources.sameWords(ownFirst, phone.firstOrNull())) {
                usable(row, read(packageName, row.type, row.name, own)) ?: fallback(key, null)?.let(OtherAppResources::clean)
            } else {
                null
            }
            return SystemLabel(text, phone.firstOrNull(), also?.takeIf { it != text }, ownFirst, source, row)
        }
        return fallbackLabel(key)
    }

    /** Datapavan's copy of AOSP's text: in the phone's language where Datapavan has it, then in Datapavan's own. */
    private fun fallbackLabel(key: String): SystemLabel {
        val phoneFirst = phone.firstOrNull()
        val ownFirst = own.firstOrNull()
        val inOwn = fallback(key, null)?.let(OtherAppResources::clean) ?: key
        if (phoneFirst == null || OtherAppResources.sameWords(phoneFirst, ownFirst) || !hasLanguage(phoneFirst)) {
            return SystemLabel(inOwn, ownFirst, null, null, LabelSource.FALLBACK)
        }
        val inPhone = fallback(key, phoneFirst)?.let(OtherAppResources::clean) ?: return SystemLabel(inOwn, ownFirst, null, null, LabelSource.FALLBACK)
        return SystemLabel(inPhone, phoneFirst, inOwn.takeIf { it != inPhone }, ownFirst, LabelSource.FALLBACK)
    }

    companion object {
        const val AOSP = "aosp"

        /** Datapavan's languages (ADR 0030), whose copies of AOSP's texts it carries: Chinese in its simplified script. */
        val LANGUAGES = setOf("en", "fa", "ar", "fr", "de", "es", "ru", "zh")

        fun hasLanguage(locale: Locale): Boolean = locale.language in LANGUAGES && !OtherAppResources.traditionalChinese(locale)

        /**
         * A read label, cleaned, or null where it is unusable (m12): blank, its own resource name (a vendor's untranslated
         * placeholder), or a format with a place in it.
         */
        fun usable(row: LabelRow, text: String?): String? =
            text?.let(OtherAppResources::clean)?.takeIf { it.isNotBlank() && it != row.name && '%' !in it }
    }
}
