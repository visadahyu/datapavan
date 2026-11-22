package org.visadahyu.datapavan.labels

import java.util.Locale
import org.visadahyu.datapavan.ui.isolateIn

/**
 * One row of `data/android-labels/labels.tsv` (ADR 0054): a place to read a label of Android's own screens from, for
 * a maker ("aosp" for any phone) and a range of Android versions.
 */
data class LabelRow(
    val key: String,
    val maker: String,
    val apis: IntRange,
    val packageName: String,
    val type: String,
    val name: String,
    val verified: String?,
) {
    companion object {
        /** The dataset's path in the data pack, read through DataPackStore so that an imported pack's rows win. */
        const val PATH = "android-labels/labels.tsv"

        /** The most rows a key may have, so that no pack can make a screen read without end. */
        const val MAX_ROWS_PER_KEY = 8

        private val KEY = Regex("[a-z][a-z0-9_]{0,63}")
        private val MAKER = Regex("[a-z0-9][a-z0-9 _-]{0,31}")
        private val API = Regex("""(\d{1,2})-(\d{0,2})""")
        private val PACKAGE = Regex("""[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+""")
        private val NAME = Regex("[a-z][a-z0-9_]{0,127}")

        /**
         * The rows of [text], held to the data check's forms (scripts/android-labels.py), since an imported pack is
         * signed but may still be mistaken: a row that is not well-formed is left out, and so is an AOSP row whose
         * package is not Settings or the permission controller, and every row of a key past its [MAX_ROWS_PER_KEY].
         */
        fun parse(text: String): List<LabelRow> {
            val perKey = HashMap<String, Int>()
            return rows(text).filter { row -> (perKey.merge(row.key, 1, Int::plus) ?: 0) <= MAX_ROWS_PER_KEY }.toList()
        }

        private fun rows(text: String): Sequence<LabelRow> = text.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .mapNotNull { line ->
                val cells = line.split('\t')
                if (cells.size != 8 || cells[4] != "string") return@mapNotNull null
                if (!KEY.matches(cells[0]) || !MAKER.matches(cells[1]) || !PACKAGE.matches(cells[3]) || !NAME.matches(cells[5])) return@mapNotNull null
                val range = API.matchEntire(cells[2]) ?: return@mapNotNull null
                val low = range.groupValues[1].toIntOrNull()?.takeIf { it in 29..99 } ?: return@mapNotNull null
                val high = if (range.groupValues[2].isEmpty()) Int.MAX_VALUE else range.groupValues[2].toIntOrNull()?.takeIf { it in low..99 } ?: return@mapNotNull null
                if (cells[1] == SystemLabels.AOSP && cells[3] !in SystemLabels.AOSP_PACKAGES) return@mapNotNull null
                val verified = cells[6].takeIf { it != "-" && it.isNotBlank() }
                if (cells[1] != SystemLabels.AOSP && verified == null) return@mapNotNull null
                LabelRow(cells[0], cells[1], low..high, cells[3], cells[4], cells[5], verified)
            }
    }
}

/** Where a label shown came from, which decides how the screen words it. */
enum class LabelSource {
    /**
     * This phone's own: read through its maker's row, which a device's screen showed, or through AOSP's name on a maker
     * whose Settings show AOSP's labels ([SystemLabels.AOSP_MAKERS]).
     */
    PHONE,

    /**
     * Read from this phone through AOSP's name, on a maker the data has not seen show it: Android's name as the maker's
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
 * Settings follows the phone's language, so a label is read in the phone's languages, region included, and also in
 * Datapavan's own where that differs. The rows of the phone's maker are tried first, then AOSP's; a row's package must
 * be a system app, and a screen reads from at most [MAX_PACKAGES] of them. Where no row answers, the label is
 * Datapavan's copy of AOSP's text: in the phone's language where Datapavan has it, else in Datapavan's (the rule of
 * the restricted-settings label before it). Each label is read once; a screen keeps one of these for its locales, so a
 * change of language reads them again. No other app's resource can break the screen: a read that fails is no label.
 */
class SystemLabels(
    rows: () -> List<LabelRow>,
    /** Build.MANUFACTURER in lower case. */
    private val maker: String,
    /** Build.VERSION.SDK_INT. */
    private val sdk: Int,
    /** The phone's languages, first first, region included. */
    private val phone: List<Locale>,
    /** Datapavan's configuration's languages; the first it has words in is the one it shows ([ownLanguage]). */
    own: List<Locale>,
    /** A label of a package by its resource, in the locales given; null when it has none. */
    private val read: (packageName: String, type: String, name: String, locales: List<Locale>) -> String?,
    /** Whether a package is part of the system image (m12): labels come only from system apps. */
    private val isSystem: (packageName: String) -> Boolean,
    /** Datapavan's copy of AOSP's text for a key, in a locale, or in Datapavan's own language for null. */
    private val fallback: (key: String, locale: Locale?) -> String?,
) {
    private val rows by lazy(rows)
    private val shown = HashMap<String, SystemLabel>()
    private val packages = LinkedHashSet<String>()

    /** The language Datapavan's screens are in: the first of its configuration's it has words in, else English. */
    val ownLanguage: Locale = ownLanguage(own)

    /** The label [key], read once. */
    fun label(key: String): SystemLabel = synchronized(shown) { shown.getOrPut(key) { find(key) } }

    /** The labels among [keys] that are worded as Android's names rather than as this phone's, for the screen's note. */
    fun androids(keys: Collection<String>): List<SystemLabel> = keys.distinct().map(::label).filter { it.source != LabelSource.PHONE }

    private fun find(key: String): SystemLabel {
        val theirs = rows.filter { it.key == key && it.maker == maker && sdk in it.apis }
        val aosp = rows.filter { it.key == key && it.maker == AOSP && sdk in it.apis }
        for (row in theirs + aosp) {
            val text = usable(row, readFrom(row, phone)) ?: continue
            val source = if (row.maker != AOSP || maker in AOSP_MAKERS) LabelSource.PHONE else LabelSource.ANDROID
            val also = if (!OtherAppResources.sameWords(ownLanguage, phone.firstOrNull())) {
                usable(row, readFrom(row, listOf(regional(ownLanguage)))) ?: fallback(key, null)?.let(OtherAppResources::clean)
            } else {
                null
            }
            return SystemLabel(text, phone.firstOrNull(), also?.takeIf { it != text }, ownLanguage, source, row)
        }
        return fallbackLabel(key)
    }

    /** A row's label in [locales], from a system app only, and from no more than [MAX_PACKAGES] packages. */
    private fun readFrom(row: LabelRow, locales: List<Locale>): String? = runCatching {
        val allowed = synchronized(packages) {
            row.packageName in packages || (packages.size < MAX_PACKAGES && isSystem(row.packageName) && packages.add(row.packageName))
        }
        if (allowed) read(row.packageName, row.type, row.name, locales) else null
    }.getOrNull()

    /** Datapavan's language as the phone writes it where the phone has it (en-US, not en: Samsung's English is British). */
    private fun regional(locale: Locale): Locale = phone.firstOrNull { OtherAppResources.sameWords(it, locale) } ?: locale

    /** Datapavan's copy of AOSP's text: in the phone's language where Datapavan has it, then in Datapavan's own. */
    private fun fallbackLabel(key: String): SystemLabel {
        val phoneFirst = phone.firstOrNull()
        val inOwn = fallback(key, null)?.let(OtherAppResources::clean) ?: key
        if (phoneFirst == null || OtherAppResources.sameWords(phoneFirst, ownLanguage) || !hasLanguage(phoneFirst)) {
            return SystemLabel(inOwn, ownLanguage, null, null, LabelSource.FALLBACK)
        }
        val inPhone = fallback(key, phoneFirst)?.let(OtherAppResources::clean) ?: return SystemLabel(inOwn, ownLanguage, null, null, LabelSource.FALLBACK)
        return SystemLabel(inPhone, phoneFirst, inOwn.takeIf { it != inPhone }, ownLanguage, LabelSource.FALLBACK)
    }

    companion object {
        const val AOSP = "aosp"

        /**
         * The makers whose Settings show AOSP's labels, on which a label read through AOSP's name is the phone's own:
         * Google's, for Pixels and the emulators. On any other maker it is worded as Android's name until that maker's
         * own row, seen on a device's screen, says otherwise (the audit's C2, the fix round's M1).
         */
        val AOSP_MAKERS = setOf("google")

        /** The packages an AOSP row may read: Settings, with SettingsLib's strings, and the permission controller. */
        val AOSP_PACKAGES = setOf("com.android.settings", "com.google.android.permissioncontroller", "com.android.permissioncontroller")

        /** The most packages one screen's labels are read from, so that no pack can load many apps' resources. */
        const val MAX_PACKAGES = 3

        /** Datapavan's languages (ADR 0030), whose copies of AOSP's texts it carries: Chinese in its simplified script. */
        val LANGUAGES = setOf("en", "fa", "ar", "fr", "de", "es", "ru", "zh")

        fun hasLanguage(locale: Locale): Boolean = locale.language in LANGUAGES && !OtherAppResources.traditionalChinese(locale)

        /**
         * The language Datapavan shows for its configuration's [locales]: as Android picks resources, the first of them
         * it has words in, else its default, English (the fix round's m5: a Hebrew phone shows Datapavan in English).
         */
        fun ownLanguage(locales: List<Locale>): Locale = locales.firstOrNull(::hasLanguage) ?: Locale.ENGLISH

        /**
         * A read label, cleaned, or null where it is unusable (m12): blank, its own resource name (a vendor's untranslated
         * placeholder), or a format with a place in it.
         */
        fun usable(row: LabelRow, text: String?): String? =
            text?.let(OtherAppResources::clean)?.takeIf { it.isNotBlank() && it != row.name && '%' !in it }
    }
}
