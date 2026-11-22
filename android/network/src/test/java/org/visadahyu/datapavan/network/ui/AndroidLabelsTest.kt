package org.visadahyu.datapavan.network.ui

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.network.R

/** The network monitoring's Android labels (ADR 0054): its keys and its fallback strings agree with the data. */
class AndroidLabelsTest {
    private val fields = R.string::class.java.fields.filter { it.name.startsWith("android_label_") }.associate { it.getInt(null) to it.name }

    @Test
    fun everyFallbackStringHasItsKeyAndEveryKeyItsRows() {
        val keys = LabelRow.parse(File("../../data/android-labels/labels.tsv").readText()).map { it.key }.toSet()
        assertEquals(fields.keys, AndroidLabels.strings.toSet())
        assertTrue(AndroidLabels.keys - keys == emptySet<String>())
    }

    /** Each string is picked from the Android version its name's _apiN says, and its key is its name's. */
    @Test
    fun eachStringHoldsFromTheVersionItsNameSays() {
        for ((key, strings) in AndroidLabels.thresholds) {
            for ((from, id) in strings) {
                val name = fields.getValue(id)
                val api = Regex("_api(\\d+)$").find(name)?.groupValues?.get(1)?.toInt() ?: 0
                assertEquals(name, api, from)
                assertEquals(name, "android_label_$key", name.replace(Regex("_api\\d+$"), ""))
                assertEquals(name, id, AndroidLabels.fallback(key, maxOf(api, 29)))
            }
        }
    }

    /** The note names the labels it is about (the fix round's M1). */
    @Test
    fun theNoteNamesTheLabelsItIsAbout() {
        val untranslated = File("src/main/res/values/strings_untranslated.xml").readText()
        val note = Regex("""<string name="labels_android_note">([^<]*)</string>""").find(untranslated)!!.groupValues[1]
        assertTrue(note, "%1\$s" in note)
        assertFalse(note, "quotes" in note)
    }
}
