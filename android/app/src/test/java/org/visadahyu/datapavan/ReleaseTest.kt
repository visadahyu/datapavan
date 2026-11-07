package org.visadahyu.datapavan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate
import java.util.Locale

class ReleaseTest {
    @Test
    fun aVersionIsOldAfterAboutFourMonths() {
        assertFalse(Release.isOld("2026-11-07", LocalDate.parse("2026-11-07")))
        assertFalse(Release.isOld("2026-11-07", LocalDate.parse("2027-03-07")))
        assertTrue(Release.isOld("2026-11-07", LocalDate.parse("2027-03-08")))
    }

    @Test
    fun aClockBeforeTheReleaseOrAnUnreadableDateSaysNothing() {
        assertFalse(Release.isOld("2026-11-07", LocalDate.parse("2020-01-01")))
        assertFalse(Release.isOld("", LocalDate.parse("2030-01-01")))
        assertFalse(Release.isOld("7.11.2026", LocalDate.parse("2030-01-01")))
    }

    @Test
    fun theReleaseDateIsADate() {
        LocalDate.parse(Release.date)
    }

    @Test
    fun theDownloadPageIsInTheAppsLanguage() {
        assertEquals("https://datapavan.org/fa/#get", Release.downloadPage(Locale.forLanguageTag("fa-IR")))
        assertEquals("https://datapavan.org/ar/#get", Release.downloadPage(Locale.forLanguageTag("ar")))
        assertEquals("https://datapavan.org/zh/#get", Release.downloadPage(Locale.forLanguageTag("zh-CN")))
        assertEquals("https://datapavan.org/#get", Release.downloadPage(Locale.forLanguageTag("en-GB")))
    }

    @Test
    fun languagesTheSiteLacksGetEnglish() {
        assertEquals("https://datapavan.org/#get", Release.downloadPage(Locale.forLanguageTag("tr")))
        assertEquals("https://datapavan.org/#get", Release.downloadPage(Locale.forLanguageTag("zh-TW")))
        assertEquals("https://datapavan.org/#get", Release.downloadPage(Locale.forLanguageTag("zh-Hant-HK")))
    }
}
