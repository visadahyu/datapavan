package org.visadahyu.datapavan.ui

import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.PlanItem
import org.visadahyu.datapavan.audit.PlanReason
import org.visadahyu.datapavan.audit.Screen
import org.visadahyu.datapavan.audit.SpecialAccess
import org.visadahyu.datapavan.labels.LabelRow
import org.visadahyu.datapavan.labels.SystemLabels

/** The audit's Android labels (ADR 0054): its keys, its fallback strings and its languages agree with the data. */
class AndroidLabelsTest {
    private val keys = LabelRow.parse(File("../../data/android-labels/labels.tsv").readText()).map { it.key }.toSet()
    private val fields = R.string::class.java.fields.filter { it.name.startsWith("android_label_") }.associate { it.getInt(null) to it.name }

    @Test
    fun everyFallbackStringHasItsKeyAndEveryKeyItsRows() {
        assertEquals(fields.keys, AndroidLabels.strings.toSet())
        assertTrue(AndroidLabels.keys - keys == emptySet<String>())
    }

    /** Each string is picked from the Android version its name's _apiN says, and its key is its name's (K14). */
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

    @Test
    fun everyLabelledScreenAndAccessHasAFallback() {
        for (screen in Screen.entries) screenLabel(screen)?.let { assertTrue("$screen: $it", it in AndroidLabels.keys) }
        for (access in SpecialAccess.entries) {
            val label = AndroidLabels.special(access)
            label?.let { assertTrue("$access: $it", it in AndroidLabels.keys) }
            // A kind of access has Android's label or Datapavan's name, never neither (n5).
            assertTrue("$access", (label == null) != (specialName(access) == null))
        }
    }

    /** The card for an app not opened names Android's switch only where Android has it for the app (the fix round's M2). */
    @Test
    fun theNotOpenedCardNamesTheUnusedSwitchOnlyWhereItIsOffered() {
        val offered = PlanItem(PlanReason.NOT_OPENED_SENSITIVE, null, listOf(Screen.APP_INFO, Screen.UNUSED_APP_SETTING))
        val notOffered = PlanItem(PlanReason.NOT_OPENED_SENSITIVE, null, listOf(Screen.APP_INFO, Screen.USAGE_ACCESS))
        assertTrue(offersUnusedSwitch(offered.screens, 30))
        assertTrue("unused_app_setting" in labelKeys(offered, 35))
        // Android 10 has no such switch.
        assertFalse(offersUnusedSwitch(offered.screens, 29))
        assertFalse("unused_app_setting" in labelKeys(offered, 29))
        // A system app, or one holding only special access: the plan does not offer it.
        assertFalse(offersUnusedSwitch(notOffered.screens, 35))
        assertFalse("unused_app_setting" in labelKeys(notOffered, 35))
        // The button to it is named as its page, not as the switch (screens review, m3).
        assertEquals(null, screenLabel(Screen.UNUSED_APP_SETTING))
    }

    /** The note names the labels it is about, buttons included, where "words in quotes" named none (the fix round's M1). */
    @Test
    fun theNoteNamesTheLabelsItIsAbout() {
        val strings = File("src/main/res/values/strings.xml").readText()
        val note = Regex("""<string name="android_labels_android">([^<]*)</string>""").find(strings)!!.groupValues[1]
        assertTrue(note, "%1\$s" in note)
        assertFalse(note, "quotes" in note)
    }

    @Test
    fun theLanguagesOfTheFallbacksAreDatapavans() {
        val languages = AppLanguage.entries.mapNotNull { it.tag?.let(Locale::forLanguageTag)?.language }.toSet()
        assertEquals(languages, SystemLabels.LANGUAGES)
    }
}
