package org.visadahyu.datapavan.text

import androidx.compose.ui.text.intl.LocaleList
import org.junit.Assert.assertEquals
import org.junit.Test

class AppLanguageTest {
    private fun marked(text: String) = inAppLanguage(text, "fa").spanStyles.map { text.substring(it.start, it.end) }

    @Test
    fun plainTextIsMarkedWhole() {
        assertEquals(listOf("برنامه‌ها"), marked("برنامه‌ها"))
        assertEquals(LocaleList("fa"), inAppLanguage("برنامه‌ها", "fa").spanStyles.single().item.localeList)
    }

    @Test
    fun isolatedPlaceholdersKeepThePhonesLanguage() {
        // An app's name and an Android label, each between an isolate and its close.
        assertEquals(
            listOf("دادهٔ ", " و ", " را ببینید"),
            marked("دادهٔ \u2068Google Play\u2069 و \u2066Settings\u2069 را ببینید"),
        )
    }

    @Test
    fun nestedIsolatesStayOutUntilTheOuterOneCloses() {
        assertEquals(listOf("a ", " b"), marked("a \u2068x \u2067y\u2069 z\u2069 b"))
    }

    @Test
    fun textMadeOnlyOfAPlaceholderIsNotMarked() {
        assertEquals(emptyList<String>(), marked("\u2068Datapavan\u2069"))
    }

    @Test
    fun bidiFormattersEmbeddingsArePlaceholdersToo() {
        assertEquals(listOf("policy: "), marked("policy: \u202AQuad9\u202C"))
    }

    @Test
    fun aLanguagesNameIsMarkedWholeWithItsOwnLanguage() {
        val name = inLanguage("\u2068Русский\u2069", "ru")
        assertEquals(LocaleList("ru"), name.spanStyles.single().item.localeList)
        assertEquals(0 to name.length, name.spanStyles.single().let { it.start to it.end })
    }

    @Test
    fun anUnclosedIsolateLeavesTheRestUnmarked() {
        assertEquals(listOf("a "), marked("a \u2068b"))
    }
}
