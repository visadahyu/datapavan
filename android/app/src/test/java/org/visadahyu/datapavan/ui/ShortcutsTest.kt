package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/** The launcher shortcuts in `res/xml/shortcuts.xml` against [LaunchTarget], the manifest and the labels. */
class ShortcutsTest {
    private val res = File("src/main/res")
    private val android = "http://schemas.android.com/apk/res/android"

    private fun parse(file: File): Element =
        DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }.newDocumentBuilder().parse(file).documentElement

    private fun Element.children(name: String): List<Element> =
        (0 until childNodes.length).map(childNodes::item).filterIsInstance<Element>().filter { it.tagName == name }

    private fun Element.attr(name: String): String = getAttributeNS(android, name)

    private val shortcuts = parse(File(res, "xml/shortcuts.xml")).children("shortcut")

    @Test
    fun everyTargetHasExactlyOneShortcutAndBackAgain() {
        val actions = shortcuts.map { it.children("intent").single().attr("action") }
        assertEquals(LaunchTarget.entries.map { it.action }.sorted(), actions.sorted())
        LaunchTarget.entries.forEach { assertEquals(it, LaunchTarget.of(it.action)) }
    }

    @Test
    fun otherStartsOpenNoShortcutScreen() {
        assertNull(LaunchTarget.of(null))
        assertNull(LaunchTarget.of("android.intent.action.MAIN"))
        assertNull(LaunchTarget.of("org.visadahyu.datapavan.action.OPEN_SETTINGS"))
    }

    @Test
    fun theShortcutsStartTheActivityThatDeclaresThem() {
        val manifest = parse(File("src/main/AndroidManifest.xml"))
        val application = manifest.children("application").single()
        val declaring = application.children("activity").single { activity ->
            activity.children("meta-data").any { it.attr("name") == "android.app.shortcuts" && it.attr("resource") == "@xml/shortcuts" }
        }
        // The namespace is also the application id (build.gradle.kts), which the launcher needs.
        val activity = "org.visadahyu.datapavan" + declaring.attr("name")
        shortcuts.forEach { shortcut ->
            val intent = shortcut.children("intent").single()
            assertEquals("org.visadahyu.datapavan", intent.attr("targetPackage"))
            assertEquals(activity, intent.attr("targetClass"))
            assertEquals("org.visadahyu.datapavan.MainActivity", activity)
        }
    }

    /** Google's advice for launchers: a short label of at most 10 characters and a long one of at most 25. */
    @Test
    fun everyLabelExistsInEveryLanguageAndFits() {
        val languages = res.listFiles { file -> file.isDirectory && file.name.matches(Regex("values(-[a-z]{2})?")) }!!
        assertEquals(4, languages.size)
        languages.forEach { values ->
            val strings = parse(File(values, "strings.xml")).children("string").associate { it.getAttribute("name") to it.textContent.replace("\\", "") }
            shortcuts.forEach { shortcut ->
                for ((attribute, limit) in listOf("shortcutShortLabel" to 10, "shortcutLongLabel" to 25)) {
                    val name = shortcut.attr(attribute).removePrefix("@string/")
                    val label = strings[name]
                    assertNotNull("${values.name}: $name is missing", label)
                    val length = label!!.codePointCount(0, label.length)
                    assertTrue("${values.name}: \"$label\" has $length characters, more than $limit", length <= limit)
                }
            }
        }
    }

    @Test
    fun everyIconIsAnAdaptiveIconOfTheApp() {
        shortcuts.forEach { shortcut ->
            val icon = File(res, "drawable/" + shortcut.attr("icon").removePrefix("@drawable/") + ".xml")
            assertEquals("adaptive-icon", parse(icon).tagName)
        }
    }
}
