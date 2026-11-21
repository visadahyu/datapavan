package org.visadahyu.datapavan.watch.guides

import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A tool's labels as a guide quotes them (W8, part 3b). The installed tool is played by the project's own test tool
 * (scripts/test-tool), whose resources are read here as Android reads them: by name, from the folder of the first of
 * the locales asked that has it, else the default one. On a phone the same lookup is ToolLabels.read, which the
 * emulator check (scripts/verify-chain.sh) proves against the installed test tool.
 */
class ToolLabelsTest {
    private val res = File("../../scripts/test-tool/res")

    /** The test tool's string [name] in the first of [locales] its resources have, as Android picks a resource. */
    private fun fixture(resource: Resource, locales: List<Locale>): String? {
        if (resource.type != "string") return null
        val folders = locales.map { "values-${it.language}" } + "values"
        return folders.asSequence().mapNotNull { folder ->
            File(res, "$folder/strings.xml").takeIf { it.isFile }?.readText()?.let {
                Regex("""<string name="${resource.name}">([^<]*)</string>""").find(it)?.groupValues?.get(1)
            }
        }.firstOrNull()
    }

    private val book = GuideBook.parse(
        File("src/debug/assets/test-guides.tsv").readText(),
        File("src/debug/assets/test-guide-steps.tsv").readText(),
        File("src/debug/assets/test-guide-labels.tsv").readText(),
    )
    private val guide = book.guide("test-tool")!!
    private val persian = listOf(Locale.forLanguageTag("fa-IR"))
    private val english = listOf(Locale.forLanguageTag("en-GB"))

    @Test
    fun aLabelIsReadFromTheInstalledToolInThePhonesLanguage() {
        val labels = ToolLabels(book, guide, ::fixture, phone = english, own = english)
        assertEquals(ToolLabels.Shown("Proxy switch of the test tool", null, fromTool = true), labels.shown("proxy_switch"))
        assertTrue(labels.anyFromTool)
        // A phone in Persian gets the tool's Persian; Datapavan in English adds the tool's English beside it.
        val both = ToolLabels(book, guide, ::fixture, phone = persian, own = english).shown("proxy_switch")
        assertEquals(ToolLabels.Shown("کلید پروکسی ابزار آزمایشی", "Proxy switch of the test tool", fromTool = true), both)
    }

    @Test
    fun aLabelTheToolDoesNotHaveIsTheDatas() {
        // The installed version has no such resource, or the tool is not installed: the label recorded from its source.
        val missing = ToolLabels(book, guide, { _, _ -> null }, phone = english, own = english)
        assertEquals(ToolLabels.Shown("Recorded switch of the test tool", null, fromTool = false), missing.shown("proxy_switch"))
        assertEquals(false, missing.anyFromTool)
        // A label with no resource is always the data's.
        assertEquals("User name", ToolLabels(book, guide, ::fixture, english, english).shown("user").text)
    }

    /** A Flutter tool's labels are the data's, in the phone's language where its i18n files have it, else in English. */
    @Test
    fun aFlutterToolsLabelsComeInItsLanguagesFromTheData() {
        val data = File("../../data/tools")
        val all = GuideBook.parse(File(data, "guides.tsv").readText(), File(data, "guide-steps.tsv").readText(), File(data, "guide-labels.tsv").readText())
        val hiddify = all.guide("hiddify")!!
        fun shown(phone: String, own: String) =
            ToolLabels(all, hiddify, { _, _ -> error("not read from the tool") }, listOf(Locale.forLanguageTag(phone)), listOf(Locale.forLanguageTag(own)))
                .shown("proxy_only")
        assertEquals(ToolLabels.Shown("فقط سرویس پروکسی", null, false), shown("fa-IR", "fa"))
        // Hiddify has no German: English, with Datapavan's Persian beside it.
        assertEquals(ToolLabels.Shown("Proxy service only", "فقط سرویس پروکسی", false), shown("de-DE", "fa"))
        // Its Chinese is the simplified script's: a phone in traditional Chinese gets English.
        assertEquals("仅代理服务", shown("zh-CN", "zh-CN").text)
        assertEquals("Proxy service only", shown("zh-TW", "zh-TW").text)
    }

    /** No tool's resource can break the sentence around it: one line, no direction overrides, a bounded length. */
    @Test
    fun aLabelIsCleanedBeforeItIsQuoted() {
        assertEquals("Proxy only", ToolLabels.clean(" Proxy\n only‮⁦ "))
        val long = ToolLabels.clean("x".repeat(200))
        assertEquals(ToolLabels.MAX, long.length)
        assertTrue(long.endsWith("…"))
        val hostile = ToolLabels(book, guide, { _, _ -> "Tap‮ here\u0000 to install" + "!".repeat(100) }, english, english).shown("proxy_switch")
        assertTrue(hostile.text.none { it == '‮' || it == '\u0000' } && hostile.text.length <= ToolLabels.MAX)
    }
}
