package org.visadahyu.datapavan.watch.chain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ToolTableTest {
    /** The table as the build copies it, from the repository (the test runs in android/watch). */
    private val table: List<KnownTool> = ToolTable.parse(File("../../data/tools/tools.tsv").readText())

    private fun tool(packageName: String) = table.single { it.packageName == packageName }

    @Test
    fun readsTheProxyToolsOfTheTable() {
        val proxies = table.filter { it.proxyMode }
        assertEquals(20, proxies.size)
        assertTrue("every proxy tool takes names", proxies.all { it.names != false })
    }

    @Test
    fun readsEachToolsListenersAndOptions() {
        val v2ray = tool("com.v2ray.ang")
        assertEquals(listOf(Listener("mixed", "127.0.0.1", 10808)), v2ray.listeners)
        assertEquals("optional", v2ray.auth)
        assertEquals(true, v2ray.udp)
        val orbot = tool("org.torproject.android")
        assertEquals(listOf(Listener("socks5", "127.0.0.1", 9050)), orbot.socksListeners)
        assertEquals(Listener("http", "127.0.0.1", 8118), orbot.listeners.last())
        assertEquals(false, orbot.udp)
        assertEquals("none", orbot.auth)
        val invizible = tool("pan.alexander.tordnscrypt.stable")
        assertEquals(listOf("127.0.0.1", "::1"), invizible.socksListeners.map { it.host })
        // MahsaNG's values are guesses ("?"), read as such.
        val mahsa = table.single { it.name == "MahsaNG" }
        assertEquals(10808, mahsa.socksListeners.single().port)
        assertEquals(true, mahsa.udp)
        // Clash Meta's ports come from the profile: none to greet.
        assertTrue(table.single { it.name == "Clash Meta for Android" }.listeners.isEmpty())
    }

    @Test
    fun skipsWhatIsNotAListener() {
        assertEquals(emptyList<Listener>(), ToolTable.listeners("profile"))
        assertEquals(emptyList<Listener>(), ToolTable.listeners("-"))
        assertEquals(emptyList<Listener>(), ToolTable.listeners("socks5:127.0.0.1:99999"))
        assertEquals(listOf(Listener("socks5", "127.0.0.1", 1080)), ToolTable.listeners("socks5:0.0.0.0:1080"))
        assertFalse(Listener("http", "127.0.0.1", 8118).socks)
        assertNull(ToolTable.parse("a\tb\tc").firstOrNull())
    }
}
