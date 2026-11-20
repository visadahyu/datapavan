package org.visadahyu.datapavan.watch.tunnel

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.tunnel.qr.QrDecode

/**
 * Every refusal the engine can give has words on the screen (W7, part 2): the codes are read from the parser's own
 * source (core/net's `Refusal::code`) and the bridge's (core/watch-jni), so that a code added there without words
 * here fails this test; and each string they name is in Watch's strings.
 */
class RefusalsTest {
    private val root = File("../..")

    /** The codes `Refusal::code` returns, read from its match arms. */
    private fun parserCodes(): List<String> {
        val source = File(root, "core/net/src/wireguard/config.rs").readText()
        val body = source.substringAfter("pub fn code(&self) -> &'static str {").substringBefore("\n    }\n")
        return Regex("=> \"([a-z-]+)\"").findAll(body).map { it.groupValues[1] }.toList()
    }

    /** The answers of `nativeTunnelSet` that are not the parser's: the engine's bound. */
    private fun bridgeCodes(): List<String> {
        val source = File(root, "core/watch-jni/src/lib.rs").readText()
        return Regex("\"(too-many)\"\\.clone_into").findAll(source).map { it.groupValues[1] }.toList()
    }

    /** The string resources' names and their ids, by reflection on R.string and R.plurals. */
    private fun stringName(id: Int): String? =
        (R.string::class.java.fields + R.plurals::class.java.fields).firstOrNull { it.getInt(null) == id }?.name

    private fun strings(): String = listOf("strings.xml", "strings_untranslated.xml")
        .joinToString("\n") { File("src/main/res/values/$it").readText() }

    @Test
    fun every_code_the_engine_gives_has_words() {
        val codes = parserCodes() + bridgeCodes()
        assertEquals("the parser's codes were read: ${parserCodes()}", 23, parserCodes().size)
        assertEquals(listOf("too-many"), bridgeCodes())
        val xml = strings()
        for (code in codes) {
            val id = Refusals.of(code)
            assertNotNull("no words for $code", id)
            val name = stringName(id!!)
            assertNotNull("no string for $code", name)
            // Each code's own words, by the strings' names, so that two codes' words cannot change places unseen.
            assertEquals("refused_" + code.replace('-', '_'), name)
            assertTrue("$name is not in Watch's strings", xml.contains("name=\"$name\""))
        }
        assertNull(Refusals.of("never-given"))
    }

    @Test
    fun every_failure_of_a_picture_has_words() {
        val xml = strings()
        for (failure in QrDecode.Failure.entries) {
            val name = stringName(Refusals.of(failure))
            assertTrue("$failure: $name", name != null && xml.contains("name=\"$name\""))
        }
    }

    /** Every reason a change was not saved has words of its own (fix round, security review M3). */
    @Test
    fun every_reason_a_change_was_not_saved_has_words() {
        val xml = strings()
        val names = Changes.NotSaved.entries.map { stringName(Refusals.of(it)) }
        for ((why, name) in Changes.NotSaved.entries.zip(names)) assertTrue("$why: $name", name != null && xml.contains("name=\"$name\""))
        assertEquals("each its own", names.size, names.toSet().size)
    }

    /** The engine's bound is said with the number Watch keeps, in a plural, never written into the words (m8). */
    @Test
    fun the_bound_is_said_with_the_stores_number() {
        assertEquals(R.plurals.refused_too_many, Refusals.of("too-many"))
        val plural = Regex("<plurals name=\"refused_too_many\">(.*?)</plurals>", RegexOption.DOT_MATCHES_ALL).find(strings())?.groupValues?.get(1)
        assertTrue("a plural", plural != null && "%d" in plural && plural.none { it.isDigit() && it != '1' })
    }

    @Test
    fun a_refusal_reads_its_code_line_and_key() {
        assertEquals(Import.Refused("bad-value", 3, "Endpoint"), Import.refusal("bad-value line 3 Endpoint"))
        assertEquals(Import.Refused("unsupported", 5, null), Import.refusal("unsupported line 5"))
        assertEquals(Import.Refused("no-dns", null, null), Import.refusal("no-dns"))
        assertEquals(Import.Refused("too-many", null, null), Import.read("refused too-many") ?: Import.refusal("too-many"))
        assertEquals(Import.Refused("repeated", 2, "PrivateKey"), Import.read("refused repeated line 2 PrivateKey"))
    }
}
