package org.visadahyu.datapavan.watch.ui

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.watch.R

/** The network monitoring's Android labels (ADR 0054): its keys and its fallback strings agree with the data. */
class AndroidLabelsTest {
    @Test
    fun everyFallbackStringHasItsKeyAndEveryKeyItsRows() {
        val keys = LabelRow.parse(File("../../data/android-labels/labels.tsv").readText()).map { it.key }.toSet()
        val strings = R.string::class.java.fields.filter { it.name.startsWith("android_label_") }.map { it.getInt(null) }.toSet()
        assertEquals(strings, AndroidLabels.strings.toSet())
        assertTrue(AndroidLabels.keys - keys == emptySet<String>())
        assertEquals(R.string.android_label_screen_lock_api36, AndroidLabels.fallback("screen_lock", 36))
        assertEquals(R.string.android_label_screen_lock, AndroidLabels.fallback("screen_lock", 30))
    }
}
