package org.visadahyu.datapavan.network.chain

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.audit.AppSigners
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.audit.SignatureVerdict

/**
 * Which installed apps are circumvention tools, by UID (the proxy record's unit B, B6; audit-B 7 and 18): a row of the
 * table of mode `vpn` or `proxy`, or one of the three `none` rows the maintainer named, judged genuine by its signing
 * key; and the tool the user chose for the chain. Of them, those whose own connections follow R10 (unit D, audit-D
 * M3): the ones that can carry traffic inside Datapavan's VPN. And in a debug build, W6's test tool under this project's
 * own prefix only. The table and the keys as the build copies them, from the repository.
 */
class ToolsTest {
    private val table: List<KnownTool> = ToolTable.parse(File("../../data/tools/tools.tsv").readText())
    private val signers = AppSigners.parse(
        File("../../data/app-signers/apps.tsv").readText(),
        File("../../data/app-signers/signers.tsv").readText(),
    )

    /** Every package of the table installed, each under a UID of its own. */
    private val installed: Map<String, Int> = table.withIndex().associate { (i, tool) -> tool.packageName to 10_100 + i }

    /** The tools when each package is signed as [signing] says, judged by the bundled keys. */
    private fun tools(chosen: String? = null, signing: (String) -> AppSigning?): Map<Int, String> =
        Tools.uids(table, chosen, { signers.judge(it, signing(it), fresh = true) }, installed::get)

    /** Signed with the first key data/app-signers records for the package, or with one it does not record. */
    private fun recorded(packageName: String): AppSigning {
        val key = File("../../data/app-signers/signers.tsv").readLines().firstOrNull { it.startsWith("$packageName\t") }
            ?.split('\t')?.get(1)
        return AppSigning(listOf(key ?: "f".repeat(64)), emptyList(), false)
    }

    private val unrecorded = AppSigning(listOf("0".repeat(64)), emptyList(), false)

    private fun uid(packageName: String) = installed.getValue(packageName)

    /** A genuine copy of a tool, by its recorded key, is a tool, named as the table names it. */
    @Test
    fun aGenuineToolIsATool() {
        val tools = tools(signing = ::recorded)
        assertEquals("v2rayNG", tools[uid("com.v2ray.ang")])
        assertEquals("Orbot", tools[uid("org.torproject.android")])
        // A VPN-only tool counts as well as one with a proxy mode.
        assertEquals("WireGuard", tools[uid("com.wireguard.android")])
    }

    /**
     * A package of a tool's name signed with a key not recorded for it, as a squatter's would be, is an ordinary app;
     * so is one positive evidence says was modified, a disguised build, and one nothing can be said of.
     */
    @Test
    fun aSquattedPackageIsNotATool() {
        assertTrue(signers.judge("com.v2ray.ang", unrecorded, fresh = true) is SignatureVerdict.UnknownKey)
        assertEquals(emptyMap<Int, String>(), tools { unrecorded })
        for (verdict in listOf(
            SignatureVerdict.Modified("v2rayNG", "0".repeat(64), debugKey = false),
            SignatureVerdict.Disguised("v2rayNG"),
            null,
        )) {
            assertEquals(verdict.toString(), emptyMap<Int, String>(), Tools.uids(table, null, { verdict }, installed::get))
        }
    }

    /** A `none` row is no tool, genuine or not: Telegram, Signal, Datapavan Basic and a plugin. */
    @Test
    fun aNoneRowIsNotATool() {
        val tools = tools(signing = ::recorded)
        for (name in listOf(
            "org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram", "org.thoughtcrime.securesms",
            "org.visadahyu.datapavan", "be.mygod.shadowsocks.plugin.masterdnsvpn",
        )) {
            assertTrue(name, uid(name) !in tools)
        }
        assertTrue(signers.judge("org.telegram.messenger", recorded("org.telegram.messenger"), fresh = true) is SignatureVerdict.Genuine)
        // Every row of mode vpn or proxy, a guessed mode ("vpn?") included, and the three named rows, when all are genuine.
        val all = Tools.uids(table, null, { SignatureVerdict.Genuine(it, "developer", pastKeyOnly = false) }, installed::get)
        assertEquals(table.count { it.vpnMode || it.proxyMode } + 3, all.size)
        assertEquals("Psiphon (Google Play build)", all[uid("com.psiphon3.subscription")])
        assertEquals("Karing", all[uid("com.nebula.karing")])
    }

    /**
     * The three `none` rows the maintainer named on 2026-11-24 (Tor Browser, its alpha, Briar) are rows of the table,
     * of mode `none` as it writes them, and tools when genuine.
     */
    @Test
    fun theNamedRowsAreNoneRowsOfTheTableAndTools() {
        val modes = File("../../data/tools/tools.tsv").readLines().filter { !it.startsWith("#") }.map { it.split('\t') }
            .filter { it.size >= 9 }.associate { it[0] to it[2] }
        assertEquals(3, Tools.NAMED_TOOLS.size)
        val tools = tools(signing = ::recorded)
        for (name in Tools.NAMED_TOOLS) {
            assertEquals(name, "none", modes[name])
            val row = table.single { it.packageName == name }
            assertTrue(name, !row.vpnMode && !row.proxyMode)
            assertEquals(name, row.name, tools[uid(name)])
        }
        assertEquals(setOf("Tor Browser", "Tor Browser (alpha)", "Briar"), Tools.NAMED_TOOLS.map { tools[uid(it)] }.toSet())
    }

    /** The tool the user chose for the chain is a tool by that choice, whatever its key; one not installed is not. */
    @Test
    fun theChainsToolIsATool() {
        assertEquals(mapOf(uid("com.v2ray.ang") to "v2rayNG"), tools(chosen = "com.v2ray.ang") { unrecorded })
        // W6's test tool of a debug build has no row in this table: named by its package.
        val test = "org.visadahyu.datapavan.testtool"
        assertEquals(mapOf(42 to test), Tools.uids(table, test, { null }) { if (it == test) 42 else null })
        assertEquals(emptyMap<Int, String>(), Tools.uids(table, "org.example.gone", { null }, installed::get))
    }

    /** A package not installed is not judged at all, and a tool is judged once. */
    @Test
    fun onlyInstalledCandidatesAreJudged() {
        val judged = mutableListOf<String>()
        val only = setOf("com.v2ray.ang", "org.telegram.messenger")
        val verdict = { name: String ->
            judged += name
            SignatureVerdict.Genuine(name, "developer", pastKeyOnly = false)
        }
        val tools = Tools.uids(table, null, verdict) { name -> installed[name]?.takeIf { name in only } }
        assertEquals(listOf("com.v2ray.ang"), judged)
        assertEquals(mapOf(uid("com.v2ray.ang") to "v2rayNG"), tools)
    }

    /**
     * R10 counts only the tools that can carry traffic inside Datapavan's VPN (audit-D M3, the maintainer's decision of
     * 2026-11-25): a row with a proxy mode, a guessed one ("proxy?") included, and the three named rows. A row of mode
     * `vpn` alone is a tool for B6's facts and an ordinary app for R10, genuine or not.
     */
    @Test
    fun onlyAToolThatCanCarryTrafficInsideTheVpnIsACarrier() {
        val carriers = Tools.carriers(table, null, { signers.judge(it, recorded(it), fresh = true) }, installed::get)
        val tools = tools(signing = ::recorded)
        assertEquals("v2rayNG", carriers[uid("com.v2ray.ang")])
        assertEquals("Orbot", carriers[uid("org.torproject.android")])
        for (name in listOf("com.wireguard.android", "com.psiphon3", "org.getlantern.lantern", "com.windscribe.vpn")) {
            assertTrue(name, uid(name) !in carriers)
        }
        assertEquals("WireGuard", tools[uid("com.wireguard.android")])
        // Every carrier is a tool of B6's: the record's set is the facts' set narrowed.
        assertTrue(tools.entries.containsAll(carriers.entries))
        val genuine = { name: String -> SignatureVerdict.Genuine(name, "developer", pastKeyOnly = false) }
        val all = Tools.carriers(table, null, genuine, installed::get)
        assertEquals(table.count { it.proxyMode } + 3, all.size)
        assertEquals("Karing", all[uid("com.nebula.karing")])
        assertEquals("MahsaNG", all[uid("com.MahsaNet.MahsaNG")])
        assertEquals(setOf("Tor Browser", "Tor Browser (alpha)", "Briar"), Tools.NAMED_TOOLS.map { all[uid(it)] }.toSet())
        assertTrue(uid("com.psiphon3.subscription") !in all)
        // A squatted copy is no carrier either.
        assertEquals(emptyMap<Int, String>(), Tools.carriers(table, null, { SignatureVerdict.UnknownKey(it, "0".repeat(64)) }, installed::get))
    }

    /** The chain's tool is a carrier by the user's choice, whatever its key and its mode: a VPN-only row's too. */
    @Test
    fun theChainsToolIsACarrierWhateverItsKeyAndMode() {
        val chosen = Tools.carriers(table, "com.wireguard.android", { null }, installed::get)
        assertEquals(mapOf(uid("com.wireguard.android") to "WireGuard"), chosen)
        assertEquals(chosen, Tools.uids(table, "com.wireguard.android", { null }, installed::get))
    }

    /**
     * Debug builds count W6's test tool as a tool whatever its key (D8), so that the chain shard can check a tool that is
     * not chained: only a row under this project's own prefix, and none in a build that is not debuggable. A test row
     * under another prefix is no tool, so a real tool's package can never be made one by the debug rule.
     */
    @Test
    fun theDebugTestToolIsAToolOnlyUnderTheProjectsPrefix() {
        val rows = ToolTable.parse(File("src/debug/assets/tools-test.tsv").readText())
        val test = "org.visadahyu.datapavan.testtool"
        assertEquals(listOf(test), rows.map { it.packageName })
        assertEquals(setOf(test), Tools.testTools(rows, debuggable = true))
        assertEquals(emptySet<String>(), Tools.testTools(rows, debuggable = false))
        val other = rows.single().copy(packageName = "org.example.testtool")
        val lookalike = rows.single().copy(packageName = "org.visadahyu.datapavanx.testtool")
        assertEquals(emptySet<String>(), Tools.testTools(listOf(other, lookalike), debuggable = true))
        val uids = mapOf(test to 42, "org.example.testtool" to 43, "org.visadahyu.datapavanx.testtool" to 44)
        val withTest = rows + other + lookalike
        val counted = Tools.testTools(withTest, debuggable = true)
        // With no key recorded for any of them, only the project's own row counts, in both sets.
        assertEquals(mapOf(42 to "Datapavan test tool"), Tools.carriers(withTest, null, { null }, counted, uids::get))
        assertEquals(mapOf(42 to "Datapavan test tool"), Tools.uids(withTest, null, { null }, counted, uids::get))
        assertEquals(emptyMap<Int, String>(), Tools.carriers(withTest, null, { null }, Tools.testTools(withTest, debuggable = false), uids::get))
        // The test tool's package is never judged by a key: none is recorded for it.
        val judged = mutableListOf<String>()
        Tools.carriers(rows, null, { judged += it; null }, counted, uids::get)
        assertEquals(emptyList<String>(), judged)
    }

    /**
     * The proxy record's unit S2, decision 3, and its review's m4: the tools installed by the ports the table knows them
     * to listen at, read once with the tools: a tool not installed names no port, and the first row's name holds a port
     * two rows share.
     */
    @Test
    fun theInstalledToolsAreFoundByTheirKnownPorts() {
        fun tool(name: String, vararg ports: Int) = KnownTool(
            packageName = "org.example.$name",
            name = name,
            proxyMode = true,
            listeners = ports.map { Listener("socks5", "127.0.0.1", it) },
            auth = null,
            udp = false,
            names = true,
        )
        val rows = listOf(tool("One", 9050, 8118), tool("Two", 1080, 9050), tool("Three", 10808))
        assertEquals(mapOf(9050 to "One", 8118 to "One", 1080 to "Two"), Tools.portsOf(rows, setOf("One", "Two")))
        assertEquals(emptyMap<Int, String>(), Tools.portsOf(rows, emptySet()))
        // The bundled table: every installed tool's port names a tool of the table.
        val all = Tools.portsOf(table, table.map { it.name }.toSet())
        assertTrue(all.values.all { name -> table.any { it.name == name } })
    }
}
