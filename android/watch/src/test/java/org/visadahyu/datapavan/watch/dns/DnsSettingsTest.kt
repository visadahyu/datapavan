package org.visadahyu.datapavan.watch.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The user's DNS setting as kept and as the engine reads it, and the engine's catalogue and state as the screen reads them. */
class DnsSettingsTest {
    @Test
    fun aChoiceIsKeptAndReadBack() {
        for (choice in listOf(
            DnsSettings.Choice.Odoh,
            DnsSettings.Choice.Preset("quad9-unsecured-doh"),
            DnsSettings.Choice.Custom(dot = false, at = "https://dns.example/dns-query", addresses = listOf("192.0.2.1", "2001:db8::1")),
            DnsSettings.Choice.Custom(dot = true, at = "dot.example:8853", addresses = listOf("192.0.2.2")),
        )) {
            assertEquals(choice, DnsSettings.Choice.read(choice.written))
        }
        assertEquals(DnsSettings.Choice.Odoh, DnsSettings.Choice.read(null))
        assertEquals(DnsSettings.Choice.Odoh, DnsSettings.Choice.read("nonsense here now too"))
    }

    @Test
    fun aResolverTheUserTypesNeedsAddressesAndNeverAName() {
        assertNull("no address", DnsSettings.Choice.custom("https://dns.example/dns-query", ""))
        assertNull("a name is no address", DnsSettings.Choice.custom("https://dns.example/dns-query", "dns.example"))
        assertNull("not https", DnsSettings.Choice.custom("http://dns.example/dns-query", "192.0.2.1"))
        assertNull("a space in the host", DnsSettings.Choice.custom("dot example", "192.0.2.1"))
        assertEquals(
            DnsSettings.Choice.Custom(false, "https://dns.example/dns-query", listOf("192.0.2.1", "192.0.2.2")),
            DnsSettings.Choice.custom(" https://dns.example/dns-query ", "192.0.2.1, 192.0.2.2"),
        )
        assertEquals(DnsSettings.Choice.Custom(true, "dot.example:853", listOf("2001:db8::53")), DnsSettings.Choice.custom("dot.example:853", "2001:db8::53"))
    }

    @Test
    fun theCatalogueReadsTheEnginesLines() {
        val text = "relay\tnuma\tNuma\tRazvan Dimescu\tDE,RO\n" +
            "target\tcloudflare\tCloudflare\tCloudflare Inc.\tUS,CR\t0\n" +
            "pair\tnuma\tcloudflare\n" +
            "allowed\tnuma\tcloudflare\n" +
            "preset\tq\tQuad9 Unsecured\tQuad9\tCH\tdoh\tno IP addresses logged\t\tnone\thttps://quad9.net/privacy/policy\n" +
            "garbage line"
        val catalogue = DnsCatalogue.parse(text)
        assertEquals("Numa", catalogue.relays["numa"]?.operator)
        assertEquals("US,CR", catalogue.targets["cloudflare"]?.jurisdictions)
        assertEquals(listOf("numa" to "cloudflare"), catalogue.defaults)
        assertEquals(listOf("numa" to "cloudflare"), catalogue.allowed)
        assertEquals(1, catalogue.presets.size)
        assertEquals("", catalogue.presets[0].audit)
        assertTrue(!catalogue.presets[0].dot)
    }

    @Test
    fun theStateReadsTheFallbackAndFailing() {
        val fallback = DnsStatus.parse("way fallback 12\nstrict 0\nvalidated 1\nheld 7\nanswers odoh 0\n")
        assertEquals(12L, fallback.fallbackSeconds)
        assertNull(fallback.failingSeconds)
        assertEquals(7, fallback.held)
        val failing = DnsStatus.parse("way failing 3\nstrict 1\nvalidated 0\nheld 9\n")
        assertEquals(3L, failing.failingSeconds)
        assertTrue(failing.strict && !failing.validated)
        val odoh = DnsStatus.parse("way odoh numa cloudflare\nstrict 0\nvalidated 1\nheld 0\n")
        assertEquals("odoh numa cloudflare", odoh.way)
        assertNull(odoh.fallbackSeconds)
    }
}
