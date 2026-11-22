package org.visadahyu.datapavan.watch.ui

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.activity.History
import org.visadahyu.datapavan.watch.activity.ProxyFacts
import org.visadahyu.datapavan.watch.log.LogRecord

/** What a row of "Now" and the history says of a proxy (fix round of W8 part 2a, screens review M3, m3 and M4). */
class ProxyRowTest {
    private val hetzner = InetAddress.getByName("203.0.113.5")
    private val zeros = InetAddress.getByName("0.0.0.0")

    private fun texts(row: ProxyRow) = listOfNotNull(row.header?.text) + row.lines.map { it.text }

    /**
     * With the switch off, an inferred proxy still says how Watch knows, and the facts that name nothing: never stated
     * as a fact, never "its own". The header stands for the destination, and the row links to the switch.
     */
    @Test
    fun aProxyLeftOutSaysHowWatchKnowsAndLinksToTheSwitch() {
        val telegram = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, leftOut = true), zeros, 0)
        val now = proxyRow(telegram, past = false)
        assertEquals(ProxyLine(R.string.now_proxy_hidden, ProxyFacts.Kind.MTPROTO), now.header)
        assertEquals(
            listOf(ProxyLine(R.string.proxy_how_inferred), ProxyLine(R.string.proxy_not_maker, args = listOf(isolate("Telegram")))),
            now.lines,
        )
        assertTrue(now.toSwitch)
        assertEquals(R.string.history_proxy_hidden, proxyRow(telegram, past = true).header?.text)
        // A SOCKS5 proxy read from the connection says so; a password crossed unencrypted is said, never its value.
        val socks = proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS5, password = true, leftOut = true), zeros, 0), past = false)
        assertEquals(listOf(R.string.now_proxy_hidden, R.string.proxy_how_read, R.string.proxy_password), texts(socks))
    }

    /** Android's proxy setting, left out, has its own words, which never call it the app's: no second line contradicts them. */
    @Test
    fun androidsSettingLeftOutHasItsOwnWords() {
        val setting = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT, setting = true, leftOut = true), zeros, 0)
        assertEquals(listOf(R.string.now_proxy_setting_hidden, R.string.proxy_how_read), texts(proxyRow(setting, past = false)))
        assertEquals(R.string.history_proxy_setting_hidden, proxyRow(setting, past = true).header?.text)
        // Kept, the setting's line follows where the proxy is.
        val kept = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_CONNECT, setting = true, asked = "example.org", askedPort = 443), hetzner, 3128)
        assertEquals(listOf(R.string.proxy_asked, R.string.proxy_network_unknown, R.string.proxy_setting), texts(proxyRow(kept, past = false)))
    }

    /** With the switch on, a declared proxy and an inferred one say how Watch knows in their first line. */
    @Test
    fun aProxyKeptSaysWhereAndHowWatchKnows() {
        val socks = ProxyFacts.of(
            LogRecord.Proxy(LogRecord.PROXY_SOCKS5, asked = "example.org", askedPort = 443, organisation = "Hetzner Online GmbH"), hetzner, 1080,
        )
        val row = proxyRow(socks, past = false)
        assertEquals(null to false, row.header to row.toSwitch)
        assertEquals(
            listOf(
                ProxyLine(R.string.proxy_asked, ProxyFacts.Kind.SOCKS5, listOf(isolateLtr("203.0.113.5:1080"), isolateLtr("example.org:443"))),
                ProxyLine(R.string.proxy_network, args = listOf(isolate("Hetzner Online GmbH"))),
            ),
            row.lines,
        )
        // A declared proxy with no destination asked for read is never called inferred.
        val bare = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_SOCKS4), hetzner, 1080)
        assertEquals(listOf(R.string.proxy_declared, R.string.proxy_network_unknown), texts(proxyRow(bare, past = false)))
        val mtproto = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, cover = "www.google.com", organisation = "Example Net"), hetzner, 443)
        assertEquals(
            listOf(R.string.proxy_inferred, R.string.proxy_network, R.string.proxy_cover),
            texts(proxyRow(mtproto, past = false)),
        )
    }

    /**
     * Screens review m3: where Watch cannot name the network, the maker's network the address is not in is still said
     * (ADR 0052, decision 6: "always"), and where it can, the one line says both.
     */
    @Test
    fun theMakersNetworkIsSaidWhenTheNetworkIsUnknown() {
        val unknown = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_WHATSAPP, outsideMaker = true), hetzner, 5222)
        assertEquals(ProxyFacts.Where.UNKNOWN, unknown.where)
        assertEquals(
            listOf(
                ProxyLine(R.string.proxy_inferred, ProxyFacts.Kind.WHATSAPP, listOf(isolateLtr("203.0.113.5:5222"))),
                ProxyLine(R.string.proxy_network_unknown),
                ProxyLine(R.string.proxy_not_maker, args = listOf(isolate("WhatsApp"))),
            ),
            proxyRow(unknown, past = false).lines,
        )
        val named = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_WHATSAPP, outsideMaker = true, organisation = "Example Net"), hetzner, 5222)
        assertEquals(listOf(R.string.proxy_inferred, R.string.proxy_network_not_maker), texts(proxyRow(named, past = false)))
        // On the local network, no company's: nothing of a maker.
        val local = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true), InetAddress.getByName("192.168.1.2"), 443)
        assertEquals(listOf(R.string.proxy_inferred, R.string.proxy_local), texts(proxyRow(local, past = false)))
    }

    /**
     * A plain request in a proxy's form is never called a proxy: its line says what it asked for and how Watch knows,
     * and with the switch off that what it asked for is not shown, linking to the switch.
     */
    @Test
    fun aPlainRequestSaysWhatItAskedForNeverThatItsServerIsAProxy() {
        val on = ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD, password = true, asked = "example.org", askedPort = 80), hetzner, 8080)
        val row = proxyRow(on, past = false)
        assertEquals(
            listOf(ProxyLine(R.string.proxy_request_asked, args = listOf(isolateLtr("example.org:80"))), ProxyLine(R.string.proxy_request_password)),
            row.lines,
        )
        assertEquals(null to false, row.header to row.toSwitch)
        val off = proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080), past = false)
        assertEquals(listOf(R.string.now_proxy_request_hidden, R.string.proxy_how_read), texts(off))
        assertTrue(off.toSwitch)
        assertEquals(R.string.history_proxy_request_hidden, proxyRow(ProxyFacts.of(LogRecord.Proxy(LogRecord.PROXY_FORWARD), hetzner, 8080), past = true).lines[0].text)
        // No line of either sets a proxy's kind in or says where a proxy is.
        val proxyWords = setOf(R.string.proxy_asked, R.string.proxy_declared, R.string.proxy_inferred, R.string.proxy_network, R.string.proxy_password)
        assertTrue((row.lines + off.lines).none { it.kind != null || it.text in proxyWords })
    }

    /**
     * Fix brief point 2: the history never says a flow went through the user's tool unless its recorded route says so;
     * a direct one, the tool's own and one of a record with no route have words of their own.
     */
    @Test
    fun onlyARouteThroughTheToolSaysSo() {
        assertEquals(R.string.history_through_tool_off, leftOutWords(History.LeftOut.THROUGH_TOOL))
        assertEquals(R.string.history_direct_off, leftOutWords(History.LeftOut.DIRECT))
        assertEquals(R.string.history_through_tunnel_off, leftOutWords(History.LeftOut.TUNNEL))
        for (why in History.LeftOut.entries - History.LeftOut.THROUGH_TOOL) {
            assertTrue(why.name, leftOutWords(why) != R.string.history_through_tool_off)
        }
    }
}
