package org.visadahyu.datapavan

import java.time.LocalDate
import java.time.format.DateTimeParseException
import java.util.Locale

/**
 * This version's release, and where newer ones are. Datapavan has no internet access, so it cannot
 * learn that a newer version exists; it can only say how old this one is and where to look. Copies
 * installed from a file, not through a store or Obtainium, have no other way to hear of an update.
 */
object Release {
    /** The release's date, ISO 8601, from android/app/build.gradle.kts. */
    val date: String = BuildConfig.RELEASE_DATE

    /** Shown as text, so that they can be copied into a browser of the user's choice. */
    const val WEBSITE = "datapavan.org"
    const val RELEASES = "github.com/visadahyu/datapavan/releases"

    /** After this many days the overview says that a newer version may be out. */
    private const val OLD_DAYS = 120L

    /** The website's languages besides English; Chinese is Simplified, as in the app. */
    private val SITE_LANGUAGES = setOf("ar", "de", "es", "fa", "fr", "ru", "zh")
    private val TRADITIONAL_CHINESE = setOf("TW", "HK", "MO")

    /** Whether a version released on [date] is old enough to say so. A clock set before it never is. */
    fun isOld(date: String, today: LocalDate): Boolean = try {
        LocalDate.parse(date).plusDays(OLD_DAYS).isBefore(today)
    } catch (_: DateTimeParseException) {
        false
    }

    /** The website's download section, which names the newest version, in [locale]'s language. */
    fun downloadPage(locale: Locale): String {
        val language = locale.language
        val traditional = language == "zh" && (locale.script == "Hant" || locale.country in TRADITIONAL_CHINESE)
        val path = if (language in SITE_LANGUAGES && !traditional) "$language/" else ""
        return "https://$WEBSITE/$path#get"
    }
}
