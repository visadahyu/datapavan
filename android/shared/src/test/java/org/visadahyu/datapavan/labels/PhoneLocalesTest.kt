package org.visadahyu.datapavan.labels

import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.ui.rightToLeft

/** Where the phone's own languages come from (ADR 0054, the audit's M1). */
class PhoneLocalesTest {
    private val english = listOf(Locale.forLanguageTag("en-US"))
    private val persian = listOf(Locale.forLanguageTag("fa"))

    @Test
    fun fromAndroid13TheyAreLocaleManagersSystemLocales() {
        // On the Android 17 emulator with Datapavan in Persian, Resources.getSystem() said Persian too.
        assertEquals(english, PhoneLocales.choose(33, system = { english }, resources = { persian }))
        assertEquals(english, PhoneLocales.choose(37, system = { english }, resources = { persian }))
        // An answer without a language: the resources' own.
        assertEquals(persian, PhoneLocales.choose(34, system = { emptyList() }, resources = { persian }))
        assertEquals(persian, PhoneLocales.choose(34, system = { null }, resources = { persian }))
    }

    @Test
    fun beforeAndroid13TheyAreTheSystemResources() {
        assertEquals(persian, PhoneLocales.choose(29, system = { error("no LocaleManager before Android 13") }, resources = { persian }))
        assertEquals(english, PhoneLocales.choose(32, system = { error("no LocaleManager before Android 13") }, resources = { english }))
    }

    @Test
    fun theDirectionOfALanguage() {
        for (tag in listOf("fa", "ar", "he", "iw", "ur", "ar-Arab-EG", "ks", "pa-Arab")) assertEquals(tag, true, rightToLeft(Locale.forLanguageTag(tag)))
        for (tag in listOf("en", "de", "ru", "zh-CN", "pa", "ku", "az-Latn")) assertEquals(tag, false, rightToLeft(Locale.forLanguageTag(tag)))
    }
}
