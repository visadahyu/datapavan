package org.visadahyu.datapavan.watch.dns

import java.io.File
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The user's DNS setting as kept and as the engine reads it, and the engine's catalogue and state as the screen reads them. */
class DnsSettingsTest {
    /**
     * ADR 0055: the project's own relay, `debug` in its status column, reaches a debuggable build's tables alone, and a
     * release build keeps only rows whose status is `-` (review m7: fail closed).
     */
    @Test
    fun aReleaseBuildKeepsOnlyTheRelaysForEveryBuild() {
        val relays = File("../../data/odoh/relays.tsv").readText()
        fun ids(table: String) = table.lines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.split('\t')[0] }
        assertEquals(listOf("numa", "crypto-sx-fastly", "datapavan"), ids(DnsSettings.forBuild(relays, debuggable = true)))
        val release = DnsSettings.forBuild(relays, debuggable = false)
        assertEquals(listOf("numa", "crypto-sx-fastly"), ids(release))
        assertFalse(release.contains("datapavan.org"))
        // Every other line, comments included, as it was.
        assertEquals(relays.lines().filterNot { it.startsWith("datapavan\t") }, release.lines())
        // The shipped table holds no status but these two.
        for (row in relays.lines().filter { it.isNotBlank() && !it.startsWith("#") }) {
            assertTrue(row, row.split('\t').getOrNull(11) in setOf("-", "debug"))
        }
        // Any other status, or none, stays out of a release build.
        val row = relays.lines().first { it.startsWith("numa\t") }
        val fields = row.split('\t')
        for (other in listOf("Debug", "beta", "", " debug")) {
            val changed = (fields.take(11) + other).joinToString("\t")
            assertEquals(other, listOf<String>(), ids(DnsSettings.forBuild(changed, debuggable = false)))
        }
        assertEquals("no status column", listOf<String>(), ids(DnsSettings.forBuild(fields.take(11).joinToString("\t"), debuggable = false)))
        assertEquals("the column moved", listOf<String>(), ids(DnsSettings.forBuild((fields.take(10) + "-").joinToString("\t"), debuggable = false)))
        assertEquals(listOf("numa"), ids(DnsSettings.forBuild(row, debuggable = false)))
    }

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

    /**
     * Review S-M2: every form the address field may meet that is not an address reads as none, without a lookup and
     * without throwing (a port, brackets, a zone, a mask, a name, too many or too few parts, other digits).
     */
    @Test
    fun everyMalformedAddressIsRefusedWithoutALookupOrAThrow() {
        for (typed in listOf(
            "1.1.1.1:853", "[2001:db8::1]", "[::1]:53", "2001:db8::1%wlan0", "fe80::1%1", "1.1.1.1/24", "1.1.1",
            "1.1.1.1.1", "256.1.1.1", "1.1.1.-1", "1..1.1", ".1.1.1", "1.1.1.", "0x1.1.1.1", "1.1.1.1a", "dns.google",
            "localhost", "::1::2", "1::2::3", "12345::", "g::1", ":::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "::ffff:1.2.3",
            "::1.2.3.4:5", "1.2.3.4::", "", " ", "\n", "١.١.١.١", "۱.۱.۱.۱", "1.1.1.1\u0000", "1".repeat(4096), "::".repeat(2048),
            "1.1.1.1 8.8.8.8", "١", "https://1.1.1.1",
        )) {
            assertNull(typed, Exchanger.numeric(typed))
        }
        assertEquals(InetAddress.getByName("192.0.2.1"), Exchanger.numeric(" 192.0.2.1 "))
        assertEquals(InetAddress.getByName("2001:db8::53"), Exchanger.numeric("2001:DB8::53"))
        assertEquals(InetAddress.getByName("::ffff:192.0.2.1"), Exchanger.numeric("::ffff:192.0.2.1"))
        assertEquals(InetAddress.getByName("::"), Exchanger.numeric("::"))
        assertEquals(InetAddress.getByName("1:2:3:4:5:6:7:8"), Exchanger.numeric("1:2:3:4:5:6:7:8"))
        assertEquals(InetAddress.getByName("1::8"), Exchanger.numeric("1::8"))
        // The field's whole check, on what a user may type there: none throws, a port refuses the choice.
        assertNull(DnsSettings.Choice.custom("https://dns.example/dns-query", "1.1.1.1:853"))
        assertNull(DnsSettings.Choice.custom("https://dns.example/dns-query", "[2001:db8::1]:443"))
    }

    /** Review R-m6: a Persian keyboard's digits and comma read as ASCII ones. */
    @Test
    fun persianDigitsReadAsAscii() {
        assertEquals(
            DnsSettings.Choice.Custom(true, "dot.example:853", listOf("192.0.2.1", "192.0.2.2")),
            DnsSettings.Choice.custom("dot.example:۸۵۳", "۱۹۲.۰.۲.۱، ١٩٢.٠.٢.٢"),
        )
    }

    /** The security review's nit and review n2: Watch takes a DoH URL only as the engine reads it. */
    @Test
    fun aDohUrlIsTakenOnlyAsTheEngineReadsIt() {
        for (url in listOf(
            "https://dns.example/dns-query?dns=x", "https://user@dns.example/", "https://user:pw@dns.example/",
            "https://[2001:db8::1]/dns-query", "https://dns.example/dns query", "https://dns.example/dns-query\nchoice odoh",
            "https://dns.example/\u0007", "https://dns.example/#x", "https://dns.example:0/", "https://dns.example:65536/",
            "https://dns.example:/", "https://dns..example/", "https://dns.example/%2e", "https://dns.example/a&targethost=x",
            "https://dnsé.example/", "https://", "https:///dns-query",
        )) {
            assertNull(url, DnsSettings.Choice.custom(url, "192.0.2.1"))
        }
        assertEquals(
            DnsSettings.Choice.Custom(false, "https://dns.example:8443/dns-query/a_b.c~d", listOf("192.0.2.1")),
            DnsSettings.Choice.custom("https://dns.example:8443/dns-query/a_b.c~d", "192.0.2.1"),
        )
        assertNull("a DoT port out of range", DnsSettings.Choice.custom("dot.example:70000", "192.0.2.1"))
        assertNull("seventeen addresses", DnsSettings.Choice.custom("dot.example", List(17) { "192.0.2.$it" }.joinToString(",")))
    }

    /** Review R-M2: the presets' cards come from the table's enumerated columns, grouped by service. */
    @Test
    fun theCatalogueReadsTheEnginesLinesAndTheTablesCards() {
        val text = "relay\tnuma\n" +
            "target\tcloudflare\n" +
            "target\tunknown\n" +
            "pair\tnuma\tcloudflare\n" +
            "allowed\tnuma\tcloudflare\n" +
            "preset\tquad9-unsecured-doh\tdoh\n" +
            "preset\tquad9-unsecured-dot\tdot\n" +
            "preset\tcloudflare-doh\tdoh\n" +
            "garbage line"
        val table = File("../../data/dns-presets/presets.tsv").readText()
        val catalogue = DnsCatalogue.parse(text, File("../../data/odoh/relays.tsv").readText(), File("../../data/odoh/targets.tsv").readText(), table)
        assertEquals("Numa", catalogue.relays["numa"]?.operator)
        assertEquals("US,CR", catalogue.targets["cloudflare"]?.jurisdictions)
        assertNull("no row in the table", catalogue.targets["unknown"])
        assertEquals(listOf("numa" to "cloudflare"), catalogue.defaults)
        assertEquals(listOf("numa" to "cloudflare"), catalogue.allowed)
        assertEquals(3, catalogue.presets.size)
        val quad9 = catalogue.presets[0]
        assertEquals("Quad9", quad9.operator)
        assertEquals("CH", quad9.country)
        assertEquals(listOf("unfiltered", "totals", "none", "no"), listOf(quad9.service, quad9.logs, quad9.blocks, quad9.audited))
        assertEquals("https://quad9.net/privacy/policy/", quad9.policy)
        assertFalse(quad9.dot)
        assertEquals(listOf("quad9-unsecured", "cloudflare"), catalogue.presets.groupBy { it.group }.keys.toList())
        val cloudflare = catalogue.presets[2]
        assertEquals(listOf("standard", "day", "none", "firm"), listOf(cloudflare.service, cloudflare.logs, cloudflare.blocks, cloudflare.audited))
        // Every row of the shipped table has the four values the screen knows.
        val known = listOf(
            setOf("blocking", "unfiltered", "standard"), setOf("totals", "names-day", "day", "months", "none"),
            setOf("none", "harm", "court"), setOf("no", "firm"),
        )
        for (row in table.lines().filter { it.isNotBlank() && !it.startsWith("#") }.map { it.split('\t') }) {
            assertEquals(row[0], 18, row.size)
            for ((i, values) in known.withIndex()) assertTrue("${row[0]} ${row[14 + i]}", row[14 + i] in values)
        }
    }

    /** Review S-C1: the screen shows the network's domains in use. */
    @Test
    fun theStateReadsTheSearchDomains() {
        assertEquals(listOf("corp.example", "lab.example"), DnsStatus.parse("way none\nsearch corp.example lab.example\n").search)
        assertEquals(emptyList<String>(), DnsStatus.parse("way none\nsearch \n").search)
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
