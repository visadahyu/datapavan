package org.visadahyu.datapavan.ui

import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.Screen
import org.visadahyu.datapavan.audit.SpecialAccess
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.labels.SystemLabels

/** The audit's Android labels (ADR 0054): its keys, its fallback strings and its languages agree with the data. */
class AndroidLabelsTest {
    private val keys = LabelRow.parse(File("../../data/android-labels/labels.tsv").readText()).map { it.key }.toSet()

    @Test
    fun everyFallbackStringHasItsKeyAndEveryKeyItsRows() {
        val strings = R.string::class.java.fields.filter { it.name.startsWith("android_label_") }.map { it.getInt(null) }.toSet()
        assertEquals(strings, AndroidLabels.strings.toSet())
        assertTrue(AndroidLabels.keys - keys == emptySet<String>())
        // Each picks its newest string on later Android versions.
        assertEquals(R.string.android_label_usage_access, AndroidLabels.fallback("usage_access", 35))
        assertEquals(R.string.android_label_usage_access_api36, AndroidLabels.fallback("usage_access", 36))
        assertEquals(R.string.android_label_device_admin_api37, AndroidLabels.fallback("device_admin", 37))
        assertEquals(R.string.android_label_usage_access, AndroidLabels.fallback("usage_access", 29))
    }

    @Test
    fun everyLabelledScreenAndAccessHasAFallback() {
        for (screen in Screen.entries) screenLabel(screen)?.let { assertTrue("$screen: $it", it in AndroidLabels.keys) }
        for (access in SpecialAccess.entries) AndroidLabels.special(access)?.let { assertTrue("$access: $it", it in AndroidLabels.keys) }
    }

    @Test
    fun theLanguagesOfTheFallbacksAreDatapavans() {
        val languages = AppLanguage.entries.mapNotNull { it.tag?.let(Locale::forLanguageTag)?.language }.toSet()
        assertEquals(languages, SystemLabels.LANGUAGES)
    }
}
