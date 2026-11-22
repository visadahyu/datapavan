package org.visadahyu.datapavan.ui

import java.util.Locale

private const val LEFT_TO_RIGHT_ISOLATE = '\u2066'
private const val RIGHT_TO_LEFT_ISOLATE = '\u2067'
private const val FIRST_STRONG_ISOLATE = '\u2068'
private const val POP_DIRECTIONAL_ISOLATE = '\u2069'

/**
 * In the shared module since W5's third part, so that Watch's screens isolate destinations as the audit does.
 *
 * Wraps a technical token that is always left-to-right (domain, IP address, package name,
 * version) in a Unicode left-to-right isolate, so that it cannot reorder the surrounding
 * sentence in right-to-left languages such as Persian or Arabic.
 *
 * Every such token must pass through this function before it is inserted into translated text.
 */
fun isolateLtr(token: String): String = "$LEFT_TO_RIGHT_ISOLATE$token$POP_DIRECTIONAL_ISOLATE"

/**
 * Wraps text whose direction depends on its content, such as an app's name or a data size with a
 * Latin unit, in a Unicode first-strong isolate: it keeps its own direction and cannot reorder the
 * sentence around it ("Google: 15.32 MB" in a Persian list).
 */
fun isolate(text: String): String = "$FIRST_STRONG_ISOLATE$text$POP_DIRECTIONAL_ISOLATE"

/**
 * Wraps a label read in [locale] in an isolate of that language's direction (ADR 0054, the audit's M3): right to left
 * for Persian, Arabic and the other right-to-left scripts, else left to right, or first-strong where the language is
 * not known. AOSP's Persian and Arabic labels that begin with a Latin word ("DNS خصوصی") carry a right-to-left mark,
 * which the label's cleaning drops, so their direction comes from the language they were read in.
 */
fun isolateIn(text: String, locale: Locale?): String = when {
    locale == null || locale.language.isEmpty() -> isolate(text)
    rightToLeft(locale) -> "$RIGHT_TO_LEFT_ISOLATE$text$POP_DIRECTIONAL_ISOLATE"
    else -> isolateLtr(text)
}

/** Whether [locale]'s script is written right to left. */
fun rightToLeft(locale: Locale): Boolean =
    locale.script in RIGHT_TO_LEFT_SCRIPTS || (locale.script.isEmpty() && locale.language in RIGHT_TO_LEFT_LANGUAGES)

private val RIGHT_TO_LEFT_SCRIPTS = setOf("Arab", "Hebr", "Thaa", "Syrc", "Nkoo", "Adlm", "Rohg", "Mand", "Samr")
private val RIGHT_TO_LEFT_LANGUAGES = setOf("ar", "fa", "he", "iw", "ur", "ps", "sd", "ug", "yi", "ji", "dv", "ckb", "ks", "syr")
