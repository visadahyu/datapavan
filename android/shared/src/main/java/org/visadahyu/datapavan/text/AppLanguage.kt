package org.visadahyu.datapavan.text

import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.intl.LocaleList

/** [text] marked whole as written in [languageTag]: a language's own name in the language picker, read in its voice. */
fun inLanguage(text: String, languageTag: String): AnnotatedString =
    AnnotatedString(text, listOf(AnnotatedString.Range(SpanStyle(localeList = LocaleList(languageTag)), 0, text.length)))

/**
 * [text] marked as written in the app's own language ([languageTag]), so that a screen reader reads it with that
 * language's voice even when the phone speaks another (the accessibility unit, part 2: TalkBack takes a text's language
 * from its LocaleSpan, which Compose makes from a SpanStyle's localeList, and otherwise reads every text in the phone's
 * language).
 *
 * What stands between Unicode isolates (U+2066 to U+2068, closed by U+2069), or between the embeddings and overrides that
 * BidiFormatter.unicodeWrap writes (U+202A, U+202B, U+202D, U+202E, closed by U+202C), is left unmarked: the placeholders that
 * carry an app's name, a tool's label or one of Android's own labels in the phone's language. A screen reader reads
 * those in the phone's language, which is theirs more often than the app's.
 */
fun inAppLanguage(text: String, languageTag: String): AnnotatedString {
    val style = SpanStyle(localeList = LocaleList(languageTag))
    val spans = mutableListOf<AnnotatedString.Range<SpanStyle>>()
    var depth = 0
    var start = -1
    for ((i, c) in text.withIndex()) {
        when (c) {
            '\u2066', '\u2067', '\u2068', '\u202A', '\u202B', '\u202D', '\u202E' -> {
                if (depth == 0 && start >= 0) {
                    spans += AnnotatedString.Range(style, start, i)
                    start = -1
                }
                depth++
            }
            '\u2069', '\u202C' -> if (depth > 0) depth--
            else -> if (depth == 0 && start < 0) start = i
        }
    }
    if (start >= 0) spans += AnnotatedString.Range(style, start, text.length)
    return AnnotatedString(text, spans)
}
