package org.visadahyu.datapavan.watch.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.watch.tunnel.TunnelStates.Shown

/** Each configuration's state as the screen says it (W7, part 2), from the engine's lines and what Watch knows. */
class TunnelStatesTest {
    @Test
    fun the_engines_lines_read_and_nothing_else() {
        val lines = TunnelStates.read("1 4200 300 - 0 0 1 2 1 0\n2 - - resolve 1 1 0 0 1 3\n3 - - - 0 0 0 0 0 0\nnonsense\n4 x")
        assertEquals(setOf(1, 2, 3), lines.keys)
        assertEquals(4_200L, lines[1]?.handshakeMs)
        assertEquals("resolve", lines[2]?.error)
        assertTrue(lines[2]?.plainDns == true && lines[2]?.notAnswering == true)
        assertEquals(false, lines[3]?.configured)
    }

    @Test
    fun what_the_screen_says() {
        val lines = TunnelStates.read("1 65000 300 - 0 0 1 2 1 0\n2 - - - 1 0 0 0 1 0\n3 - - - 0 0 0 0 0 0\n4 - - - 0 0 0 0 1 0")
        val known = TunnelStore.Name.Known("x")
        assertEquals(Shown.Connected(65), TunnelStates.shown(true, known, lines[1]))
        assertEquals(Shown.NotAnswering, TunnelStates.shown(true, known, lines[2]))
        assertEquals(Shown.Missing, TunnelStates.shown(true, known, lines[3]))
        assertEquals(Shown.Missing, TunnelStates.shown(true, known, null))
        assertEquals(Shown.Idle, TunnelStates.shown(true, known, lines[4]))
        assertEquals(Shown.Off, TunnelStates.shown(false, known, lines[1]))
        assertEquals("a lost key is said even while Watch is off", Shown.Lost, TunnelStates.shown(false, TunnelStore.Name.Lost, null))
        assertEquals(Shown.Locked, TunnelStates.shown(true, TunnelStore.Name.Locked, lines[1]))
    }

    /**
     * TalkBack announces a state's kind alone (fix round, screens review M3): a connected configuration's kind, and the
     * words of its live region, stay the same from one second to the next, and no kind's words hold a number.
     */
    @Test
    fun the_live_region_says_the_kind_alone() {
        assertEquals(TunnelStates.kind(Shown.Connected(37)), TunnelStates.kind(Shown.Connected(38)))
        assertEquals(TunnelStates.Kind.CONNECTED, TunnelStates.kind(Shown.Connected(3_600)))
        val xml = listOf("strings.xml", "strings_untranslated.xml").map { java.io.File("src/main/res/values/$it") }
            .filter { it.isFile }.joinToString("\n") { it.readText() }
        for (kind in TunnelStates.Kind.entries) {
            val name = org.visadahyu.datapavan.watch.R.string::class.java.fields.firstOrNull { it.getInt(null) == org.visadahyu.datapavan.watch.ui.kindWords(kind) }?.name
            val words = Regex("<string name=\"$name\">([^<]*)</string>").find(xml)?.groupValues?.get(1)
            assertTrue("$kind has words of its own: $name", words != null)
            assertTrue("$kind's words hold no number: $words", words!!.none { it.isDigit() } && "%" !in words)
        }
        assertEquals(Shown.Unavailable, TunnelStates.shown(true, TunnelStore.Name.Unavailable, null))
    }
}
