package org.visadahyu.datapavan.network.proxy

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.dns.NetworkProxy
import org.visadahyu.datapavan.network.ui.ProxyLine
import org.visadahyu.datapavan.network.ui.androidProxyLines
import org.visadahyu.datapavan.ui.isolate
import org.visadahyu.datapavan.ui.isolateLtr

/** Android's own proxy settings, as the network part reads them and "Now" says them (the proxy record's unit B, B7). */
class AndroidProxyTest {
    private fun read(host: String, port: Int, pac: Boolean = false) = NetworkProxy.Setting(host, port, pac, emptyList())

    private val server = AndroidProxy.Setting.Server("proxy.example.net", 3128)

    /** A `ProxyInfo` read: a PAC file whatever its host and port, a server with both, or none; brackets taken off. */
    @Test
    fun readsEachSettingAsAndroidGivesIt() {
        assertNull(AndroidProxy.setting(null))
        assertEquals(AndroidProxy.Setting.Pac, AndroidProxy.setting(read("localhost", 41_235, pac = true)))
        assertEquals(AndroidProxy.Setting.Pac, AndroidProxy.setting(read("", 0, pac = true)))
        assertEquals(server, AndroidProxy.setting(read("proxy.example.net", 3128)))
        assertEquals(AndroidProxy.Setting.Server("2001:db8::7", 8080), AndroidProxy.setting(read("[2001:db8::7]", 8080)))
        assertNull(AndroidProxy.setting(read("", 3128)))
        assertNull(AndroidProxy.setting(read("proxy.example.net", 0)))
        assertNull(AndroidProxy.setting(read("proxy.example.net", 65_536)))
        assertEquals(false, AndroidProxy().any)
        assertEquals(true, AndroidProxy(network = AndroidProxy.Setting.Pac).any)
    }

    /**
     * B7's lines: the whole phone's proxy first, as Android puts it first; the network's own beside it (the proxy record's
     * unit S2), since the engine uses it whatever the whole phone's is, here as the engine not using it yet; a PAC file's
     * own sentences, the network's only where the whole phone has none; and nothing while none is set.
     */
    @Test
    fun nowSaysWhichSettingIsSetAndNothingWhileNoneIs() {
        val at = listOf(isolateLtr("proxy.example.net:3128"))
        assertEquals(listOf(ProxyLine(R.string.now_proxy_global, args = at)), androidProxyLines(AndroidProxy(global = server)))
        assertEquals(listOf(ProxyLine(R.string.now_proxy_global_pac)), androidProxyLines(AndroidProxy(global = AndroidProxy.Setting.Pac)))
        assertEquals(listOf(ProxyLine(R.string.now_proxy_network_unused, args = at)), androidProxyLines(AndroidProxy(network = server)))
        assertEquals(listOf(ProxyLine(R.string.now_proxy_network_pac)), androidProxyLines(AndroidProxy(network = AndroidProxy.Setting.Pac)))
        // Both set: the whole phone's first; the network's PAC file is not said, its proxy is.
        assertEquals(listOf(R.string.now_proxy_global), androidProxyLines(AndroidProxy(global = server, network = AndroidProxy.Setting.Pac)).map { it.text })
        assertEquals(
            listOf(R.string.now_proxy_global_pac, R.string.now_proxy_network_unused),
            androidProxyLines(AndroidProxy(AndroidProxy.Setting.Pac, server)).map { it.text },
        )
        // An IPv6 address in brackets, as people write one with its port.
        val v6 = AndroidProxy.Setting.Server("2001:db8::7", 8080)
        assertEquals(listOf(isolateLtr("[2001:db8::7]:8080")), androidProxyLines(AndroidProxy(network = v6)).single().args)
        assertEquals(emptyList<ProxyLine>(), androidProxyLines(AndroidProxy()))
    }

    /**
     * S2: the network's own proxy's line says what the engine does with it: carries apps through it where a direct
     * connection fails, with where it is, or always with the switch on, also beside the whole phone's; then, in lines of
     * their own after the line and its switch, a password asked for (S2's review, M1) and the local-network grant as
     * advice (M2); on the phone itself, at a tool's known port or another; else not used, with the switch where it was
     * left on (m2).
     */
    @Test
    fun theNetworksProxyLineSaysWhatTheEngineDoesWithIt() {
        val at = listOf(isolateLtr("proxy.example.net:3128"))
        val network = AndroidProxy(network = server)
        fun lines(beneath: ProxyContext.Beneath, password: Boolean = false) = androidProxyLines(network, beneath, password)
        fun line(beneath: ProxyContext.Beneath, password: Boolean = false) = lines(beneath, password).single()
        val through = ProxyLine.Tap.THROUGH
        val used = ProxyContext.Beneath(NetworkProxy.Why.NETWORK, key = "1 proxy.example.net 3128")
        assertEquals(ProxyLine(R.string.now_proxy_network, args = at, place = R.string.now_proxy_network_remote, tap = through), line(used))
        assertEquals(ProxyLine(R.string.now_proxy_network, args = at, place = R.string.proxy_local, tap = through), line(used.copy(local = true)))
        assertEquals(ProxyLine(R.string.now_proxy_network_always, args = at, place = R.string.now_proxy_network_remote, tap = through), line(used.copy(always = true)))
        // No key, no switch.
        assertEquals(null, line(ProxyContext.Beneath(NetworkProxy.Why.NETWORK)).tap)
        // A password asked for keeps the line and its switch, the switch on or off, and says so after them (M1).
        assertEquals(
            listOf(
                ProxyLine(R.string.now_proxy_network, args = at, place = R.string.now_proxy_network_remote, tap = through),
                ProxyLine(R.string.now_proxy_network_password),
            ),
            lines(used, password = true),
        )
        assertEquals(
            listOf(
                ProxyLine(R.string.now_proxy_network_always, args = at, place = R.string.now_proxy_network_remote, tap = through),
                ProxyLine(R.string.now_proxy_network_password_always),
            ),
            lines(used.copy(always = true), password = true),
        )
        // Without the local-network grant: the proxy used all the same, the grant as advice with its button (M2).
        assertEquals(
            listOf(
                ProxyLine(R.string.now_proxy_network, args = at, place = R.string.proxy_local, tap = through),
                ProxyLine(R.string.now_proxy_network_password),
                ProxyLine(R.string.now_proxy_network_no_grant, tap = ProxyLine.Tap.ALLOW_LOCAL),
            ),
            lines(used.copy(local = true, noGrant = true), password = true),
        )
        assertEquals(
            listOf(R.string.now_proxy_global, R.string.now_proxy_network),
            androidProxyLines(AndroidProxy(global = server, network = server), used).map { it.text },
        )
        assertEquals(ProxyLine(R.string.now_proxy_network_phone, args = at), line(ProxyContext.Beneath(NetworkProxy.Why.LOOPBACK)))
        assertEquals(
            ProxyLine(R.string.now_proxy_network_tool, args = listOf(isolate("Orbot")), tap = ProxyLine.Tap.CHAIN),
            line(ProxyContext.Beneath(NetworkProxy.Why.LOOPBACK, tool = "Orbot")),
        )
        for (why in listOf(NetworkProxy.Why.UNRESOLVED, NetworkProxy.Why.OWN, NetworkProxy.Why.LINK_LOCAL, NetworkProxy.Why.NONE)) {
            assertEquals(why.word, ProxyLine(R.string.now_proxy_network_unused, args = at), line(ProxyContext.Beneath(why)))
            // The switch left on where the engine cannot use the proxy: a line of its own, since its connections then fail
            // (the switch's hold), with the switch drawn so that it can be turned off (m2).
            assertEquals(
                why.word,
                listOf(ProxyLine(R.string.now_proxy_network_unused_on, args = at, tap = through)),
                lines(ProxyContext.Beneath(why, key = "1 proxy.example.net 3128", always = true)),
            )
            assertEquals(why.word, 1, lines(ProxyContext.Beneath(why, key = "1 proxy.example.net 3128")).size)
        }
    }

    /**
     * B5: the engine is handed the servers Android's settings name, never a PAC file, whose `localhost` and handler's port
     * are not an address, and never a server on the loopback, which never enters the tunnel; each once.
     */
    @Test
    fun aPacFileAndTheLoopbackAreNotHandedToTheEngine() {
        val lines = AndroidProxy.engineLines(
            listOf(
                read("proxy.example.net", 3128),
                null,
                read("localhost", 41_235, pac = true),
                read("10.0.2.2", 8080, pac = true),
                read("localhost", 3128),
                read("LOCALHOST", 3128),
                read("127.0.0.1", 8118),
                read("[::1]", 9050),
                read("203.0.113.5", 8080),
                read("proxy.example.net", 3128),
                read("", 3128),
            ),
        )
        assertEquals(listOf("proxy.example.net 3128", "203.0.113.5 8080"), lines)
    }

    /**
     * B5 (audit-B 17): the PAC proxy's UID counts only for Android's own app of that name with a UID of its own, a system
     * app of an application UID with no shared user ID; then its row, and its row alone, carries the fact.
     */
    @Test
    fun onlyAndroidsOwnPacProxyCarriesItsFact() {
        val system = android.content.pm.ApplicationInfo.FLAG_SYSTEM
        val updated = system or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        // UID 10092 on Android 15 and 10122 on 17 (measurements 7.2).
        assertTrue(PacHandler.owns(system, 10_092, null))
        assertTrue(PacHandler.owns(updated, 10_122, null))
        assertTrue("a package of that name installed later", !PacHandler.owns(0, 10_300, null))
        assertTrue("a shared system UID", !PacHandler.owns(system, 1000, "android.uid.system"))
        assertTrue("below the apps' UIDs", !PacHandler.owns(system, 9_999, null))
        assertTrue("a shared user ID", !PacHandler.owns(system, 10_092, "android.uid.shared"))
        assertEquals(ProxyLine(R.string.proxy_pac_handler), org.visadahyu.datapavan.network.ui.pacHandlerLine(10_092, 10_092))
        assertNull(org.visadahyu.datapavan.network.ui.pacHandlerLine(10_092, 10_093))
        assertNull(org.visadahyu.datapavan.network.ui.pacHandlerLine(10_092, null))
        assertNull(org.visadahyu.datapavan.network.ui.pacHandlerLine(null, 10_092))
        assertNull(org.visadahyu.datapavan.network.ui.pacHandlerLine(null, null))
    }

    /** The holder the service publishes to: each part kept apart, and everything forgotten when the tunnel stops. */
    @Test
    fun theHolderKeepsWhatTheServicePublished() {
        ProxyContext.clear()
        ProxyContext.publish(AndroidProxy(global = server), pacHandler = 10_092)
        ProxyContext.publishTools(mapOf(10_200 to "Orbot", 10_201 to "Psiphon"), mapOf(10_200 to "Orbot"))
        assertEquals(
            ProxyContext.State(AndroidProxy(global = server), 10_092, mapOf(10_200 to "Orbot", 10_201 to "Psiphon"), mapOf(10_200 to "Orbot")),
            ProxyContext.state.value,
        )
        ProxyContext.publish(AndroidProxy(), pacHandler = null)
        assertEquals(mapOf(10_200 to "Orbot", 10_201 to "Psiphon"), ProxyContext.state.value.tools)
        assertEquals(mapOf(10_200 to "Orbot"), ProxyContext.state.value.carriers)
        assertEquals(false, ProxyContext.state.value.android.any)
        ProxyContext.clear()
        assertEquals(ProxyContext.State(), ProxyContext.state.value)
    }

    /**
     * The words (audit-B 14): the network's line names this network, not a Wi-Fi network, and the apps left out, which
     * use its proxy unseen; the whole phone's says "most apps", not every app; none says who set a proxy.
     */
    @Test
    fun theLinesSayWhichSettingWithoutJudging() {
        val strings = File("src/main/res/values/strings_untranslated.xml").readText()
        fun text(name: String) = checkNotNull(Regex("""<string name="$name">([^<]*)</string>""").find(strings)).groupValues[1]
        assertTrue(text("now_proxy_global").contains("for the whole phone in Android\\'s settings"))
        assertTrue(text("now_proxy_global").contains("Most apps go through it."))
        assertTrue(text("now_proxy_network").startsWith("This network\\'s settings name a proxy"))
        assertTrue(text("now_proxy_network_unused").contains("and so do the apps you left out"))
        // S2: what the engine does with it, and what the proxy then sees.
        assertTrue(text("now_proxy_network").contains("Where an app cannot connect directly, Datapavan connects it through this proxy"))
        assertTrue(text("now_proxy_network").endsWith("and the proxy then sees where it connects."))
        assertTrue(text("now_proxy_network_password").contains("which Android does not keep for a network"))
        // M1: only what was seen, some connections; M2: advice, never that nothing connects.
        assertTrue(text("now_proxy_network_password").contains("for some connections"))
        assertTrue(text("now_proxy_network_password_always").startsWith(text("now_proxy_network_password")))
        assertTrue(text("now_proxy_network_no_grant").endsWith("allow the local network."))
        assertTrue(!text("now_proxy_network_no_grant").contains("cannot connect at all"))
        // m1: the history in the past tense, with no "this network".
        for (name in listOf("history_destination_network_proxy", "history_network_proxy_off")) {
            assertTrue(name, text(name).startsWith("Went through the proxy of the network it was on"))
            assertTrue(name, !text(name).contains("this network", ignoreCase = true))
        }
        assertTrue(text("now_proxy_network_pac").startsWith("This network\\'s settings give a PAC file."))
        // m2's hold: with the switch on and no address to use, the line says the connections fail, never that apps go
        // directly, and how to let them.
        assertTrue(text("now_proxy_network_unused_on").startsWith(text("now_proxy_network_unused").removeSuffix(" Others connect directly.")))
        assertTrue(text("now_proxy_network_unused_on").endsWith("fail. Turn the switch off to let them go directly."))
        val names = listOf("now_proxy_global", "now_proxy_global_pac", "now_proxy_network", "now_proxy_network_pac") +
            listOf("always", "remote", "unused", "unused_on", "no_grant", "phone", "tool", "password", "password_always")
                .map { "now_proxy_network_$it" }
        for (name in names) {
            for (word in listOf("Wi-Fi", "every app", "you set", "your proxy", "chose", "admin", "owner")) {
                assertTrue("$name: $word", !text(name).contains(word, ignoreCase = true))
            }
        }
        // B5: the PAC proxy connects for others, never "its own"; and the left-out list says the exception (audit-B 15),
        // in this file alone until its translations come back.
        assertTrue(text("proxy_pac_handler").contains("connects for other apps, including apps you left out"))
        assertTrue(!Regex("\\bown\\b").containsMatchIn(text("proxy_pac_handler")))
        assertTrue(text("left_out_body").contains("One exception: where Android\\'s settings give a PAC file"))
        for (values in File("src/main/res").listFiles().orEmpty().filter { it.name.startsWith("values") }) {
            assertTrue(values.name, File(values, "strings.xml").takeIf { it.isFile }?.readText()?.contains("\"left_out_body\"") != true)
        }
    }

    /**
     * The proxy record's unit S2, decision 1: the choice "Send apps through this proxy" is kept by the proxy setting it
     * was made for, the network's transport, the host as names compare (brackets off, ASCII letters folded) and the port,
     * so that it never covers another kind of network's proxy, or another port; two saved networks of one kind whose
     * proxies have the same host and port share it. A choice whose setting was not seen for 90 days is forgotten (S2's
     * review, m3).
     */
    @Test
    fun theChoiceToSendAppsThroughAProxyIsKeptByItsSetting() {
        assertEquals("1 proxy.example 3128", ThroughProxy.key(1, "Proxy.EXAMPLE", 3128))
        assertEquals("2 2001:db8::7 8080", ThroughProxy.key(2, "[2001:db8::7]", 8080))
        assertTrue(ThroughProxy.key(1, "p.example", 3128) != ThroughProxy.key(3, "p.example", 3128))
        assertTrue(ThroughProxy.key(1, "p.example", 3128) != ThroughProxy.key(1, "p.example", 3129))
        val today = 20_000L
        assertEquals(
            setOf("today", "89 days ago"),
            ThroughProxy.kept(mapOf("today" to today, "89 days ago" to today - 89, "90 days ago" to today - 90, "a year ago" to today - 365), today),
        )
        assertEquals(20_419L, ThroughProxy.today(1_764_201_600_000L + 86_399_999L))
        assertEquals(20_419L, ThroughProxy.today(1_764_201_600_000L))
        assertEquals(20_418L, ThroughProxy.today(1_764_201_599_999L))
    }
}
