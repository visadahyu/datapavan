package org.visadahyu.datapavan.ui

import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PhoneLabelTest {
    private fun locale(tag: String) = Locale.forLanguageTag(tag)

    @Test
    fun usesThePhonesLanguageWhenItDiffersAndDatapavanHasIt() {
        // The Galaxy A56: Settings in English, Datapavan in Persian.
        assertEquals(locale("en-US"), PhoneLabel.locale(locale("en-US"), locale("fa")))
        assertEquals(locale("fa-IR"), PhoneLabel.locale(locale("fa-IR"), locale("en")))
        assertEquals(locale("zh-CN"), PhoneLabel.locale(locale("zh-CN"), locale("ru")))
    }

    @Test
    fun keepsTheAppsLanguageWhenBothAreTheSame() {
        assertNull(PhoneLabel.locale(locale("fa-IR"), locale("fa")))
        assertNull(PhoneLabel.locale(locale("en-GB"), locale("en-US")))
    }

    @Test
    fun keepsTheAppsLanguageWhenDatapavanLacksThePhones() {
        assertNull(PhoneLabel.locale(locale("tr-TR"), locale("fa")))
        assertNull(PhoneLabel.locale(locale("zh-TW"), locale("en")))
        assertNull(PhoneLabel.locale(locale("zh-Hant-HK"), locale("fa")))
    }
}
