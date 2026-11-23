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
            marked("دادهٔ ⁨Google Play⁩ و ⁦Settings⁩ را ببینید"),
        )
    }

    @Test
    fun nestedIsolatesStayOutUntilTheOuterOneCloses() {
        assertEquals(listOf("a ", " b"), marked("a ⁨x ⁧y⁩ z⁩ b"))
    }

    @Test
    fun textMadeOnlyOfAPlaceholderIsNotMarked() {
        assertEquals(emptyList<String>(), marked("⁨Datapavan⁩"))
    }

    @Test
    fun anUnclosedIsolateLeavesTheRestUnmarked() {
        assertEquals(listOf("a "), marked("a ⁨b"))
    }
}
