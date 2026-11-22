package org.visadahyu.datapavan.network.guides

import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.R
import org.visadahyu.datapavan.network.chain.KnownTool
import org.visadahyu.datapavan.network.chain.Listener
import org.visadahyu.datapavan.network.chain.ToolFinder
import org.visadahyu.datapavan.network.chain.ToolSearch
import org.visadahyu.datapavan.network.chain.ToolTable
import org.visadahyu.datapavan.network.ui.chainGuideLinks
import kotlin.concurrent.thread

/** The per-tool guides as Watch reads them (W8, part 3b): the data, its words, the chain section's links and the finder. */
class GuidesTest {
    private val data = File("../../data/tools")
    private val book = GuideBook.parse(
        File(data, GuideBook.GUIDES).readText(), File(data, GuideBook.STEPS).readText(), File(data, GuideBook.LABELS).readText(),
    )
    private val table = ToolTable.parse(File(data, ToolTable.ASSET).readText())
    private val english = File("src/main/res/values/strings_untranslated.xml").let { if (it.isFile) it.readText() else "" }
    private val words: Map<String, String> = Regex("""<string name="([a-z_]+)"[^>]*>([^<]*)</string>""").findAll(
        english + File("src/main/res/values/strings.xml").readText(),
    ).associate { it.groupValues[1] to it.groupValues[2].replace("\\'", "'").replace("\\\"", "\"") }

    @Test
    fun theBookReadsEveryRowOfTheData() {
        fun rows(name: String) = File(data, name).readLines().count { it.isNotBlank() && !it.startsWith("#") }
        assertEquals(rows(GuideBook.GUIDES), book.guides.size)
        assertEquals(rows(GuideBook.STEPS), book.steps.size)
        assertEquals(rows(GuideBook.LABELS), book.labels.size)
        val v2ray = book.guideOf("com.v2ray.ang.fdroid")!!
        assertEquals(Page.PROXY to "2.3.15", v2ray.page to v2ray.version)
        assertEquals(listOf(Listener("mixed", "127.0.0.1", 10808)), v2ray.listeners)
        assertEquals(true, v2ray.checked)
        assertEquals(Resource("array", "mode_entries", 1), book.label("v2rayng", "proxy_only").single().resource)
        // A Flutter tool's labels have no resource, and come in the languages its i18n files have.
        val hiddify = book.label("hiddify", "proxy_only")
        assertTrue(hiddify.all { it.resource == null })
        assertEquals(setOf("en", "fa", "ar", "ru", "zh", "fr", "es"), hiddify.map { it.lang }.toSet())
        assertEquals(Page.WAITING, book.guideOf("com.netmod.syna")!!.page)
        assertEquals(Page.WIREGUARD, book.guideOf("ch.protonvpn.android")!!.page)
        assertEquals(Page.VPN, book.guideOf("org.amnezia.awg")!!.page)
    }

    /** Every string the data or a page names is one of Watch's, in the table the screen looks names up in, with as many places as are filled. */
    @Test
    fun everyStringOfTheDataIsWatchs() {
        for (guide in book.guides) {
            for (block in GuidePage.blocks(book, guide) + GuidePage.Block(GuidePage.Kind.TEXT, "guide_labels_tool", listOf(GuidePage.Fill.Tool)) +
                GuidePage.Block(GuidePage.Kind.TEXT, "guide_labels_recorded") +
                GuidePage.Block(GuidePage.Kind.HEADING, if (guide.page == Page.PROXY) "guide_title_proxy" else "guide_title_other", listOf(GuidePage.Fill.Tool))
            ) {
                assertTrue("${guide.id}: ${block.string}", block.string in GuideStrings.ids)
                val text = words[block.string] ?: error("${guide.id}: no English ${block.string}")
                val places = Regex("%(\\d+)\\$[sd]").findAll(text).map { it.groupValues[1].toInt() }.toSet()
                assertEquals("${guide.id}: ${block.string}", (1..block.fills.size).toSet(), places)
            }
        }
        // The table holds no string the data and the pages leave unused.
        val used = book.steps.map { it.string }.toSet() + book.guides.flatMap { g -> GuidePage.blocks(book, g).map { it.string } } +
            setOf("guide_labels_tool", "guide_labels_recorded", "guide_title_proxy", "guide_title_other")
        assertEquals(emptySet<String>(), GuideStrings.ids.keys - used)
        assertEquals(R.string.guide_step_tap, GuideStrings.ids["guide_step_tap"])
    }

    /**
     * The guides' words keep ADR 0025's list (decision 4: no word that judges), and the brief's: they never recommend a
     * tool or point to a download. The WireGuard page quotes Watch's own heading as it reads.
     */
    @Test
    fun theGuidesWordsNeitherJudgeNorRecommend() {
        val ours = words.filterKeys { it.startsWith("guide_") || it.startsWith("chain_guide") }.mapValues { it.value.lowercase() }
        assertTrue(ours.size >= 85)
        val judging = listOf(
            "suspicious", "unusual", "abnormal", "excessive", "leak", "spying", "secretly", "malicious", "threat", "risk",
            "normal", "expected", "safe", "recommend", "best", "better", "should", "popular", "trusted", "download", "install",
            "store", "play",
        )
        for ((name, text) in ours) {
            // Proton's account page names the section that holds its WireGuard files "Downloads", quoted as its label: a page
            // of the provider's, not a download of a tool.
            val said = if (name == "guide_wireguard_proton") text.replace(Regex("""open \\?"?downloads\\?"?,"""), "") else text
            for (word in judging) assertTrue("$name: $word", !Regex("\\b${Regex.escape(word)}").containsMatchIn(said))
        }
        assertTrue(words.getValue("guide_wireguard_add").contains("\"${words.getValue("tunnels_title")}\""))
    }

    /** The chain section links every installed tool's guide, in the guides' order, once per guide, and nothing else. */
    @Test
    fun theChainSectionLinksEveryInstalledToolsGuide() {
        val installed = setOf("org.telegram.messenger", "com.psiphon3", "org.torproject.android", "com.v2ray.ang", "com.v2ray.ang.fdroid", "dev.hexasoftware.v2box")
        val links = Guides.installed(book, table) { it in installed }
        assertEquals(listOf("v2rayng", "v2rayng", "orbot", "v2box", "psiphon"), links.map { it.guide })
        assertEquals("v2rayNG (F-Droid flavour)", links[1].name)
        val shown = chainGuideLinks(links)
        assertEquals(listOf("v2rayng", "orbot", "v2box", "psiphon"), shown.map { it.first.guide })
        assertEquals(
            listOf(R.string.chain_guide_proxy, R.string.chain_guide_proxy, R.string.chain_guide_other, R.string.chain_guide_other),
            shown.map { it.second },
        )
        assertEquals(emptyList<GuideLink>(), Guides.installed(book, table) { false })
    }

    /** Where tools.tsv says the profile sets the listener, the finder greets the port the guide has the user set, and only there. */
    @Test
    fun aProfilesToolGetsThePortItsGuideNames() {
        val named = Guides.withNamedPorts(table, book).associateBy { it.packageName }
        assertEquals(listOf(Listener("mixed", "127.0.0.1", 7890)), named.getValue("com.github.metacubex.clash.meta").listeners)
        assertEquals(listOf(Listener("mixed", "127.0.0.1", 2080)), named.getValue("io.nekohasekai.sfa").listeners)
        val before = table.associateBy { it.packageName }
        for ((pkg, tool) in named) if (pkg !in setOf("com.github.metacubex.clash.meta", "io.nekohasekai.sfa")) assertEquals(pkg, before[pkg], tool)
    }

    private val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    @After
    fun close() = server.close()

    @Test
    fun theFinderFindsAProfilesToolAtTheNamedPort() {
        thread(isDaemon = true) {
            while (true) {
                val client = try {
                    server.accept()
                } catch (e: SocketException) {
                    break
                }
                thread(isDaemon = true) {
                    client.use {
                        repeat(3) { _ -> it.getInputStream().read() }
                        it.getOutputStream().apply { write(byteArrayOf(5, 0)); flush() }
                        while (it.getInputStream().read() >= 0) Unit
                    }
                }
            }
        }
        val tool = KnownTool("org.example.profile", "Profile tool", proxyMode = true, listeners = emptyList(), auth = "optional", udp = true, names = true)
        val guides = GuideBook(
            listOf(Guide("profile", listOf(tool.packageName), Page.PROXY, "1", listOf(Listener("mixed", "127.0.0.1", server.localPort)), "optional", false)),
            emptyList(),
            emptyList(),
        )
        fun search(table: List<KnownTool>) = ToolFinder(uidOf = { 10_123 }, table = table, ownerOf = { _, _ -> 10_123 }, userId = 0).search()
        assertEquals(ToolSearch.NoneInstalled, search(listOf(tool)))
        val found = search(Guides.withNamedPorts(listOf(tool), guides)) as ToolSearch.Answering
        assertEquals(server.localPort to true, found.found.port to found.found.ownerConfirmed)
    }

    /**
     * Watch's screen says what the website says: each block's English sentence, filled as the site fills it, is on the
     * built page, in the same order (scripts/guides.py writes the pages from the same data and words).
     */
    @Test
    fun theScreenSaysWhatTheSiteSays() {
        for (guide in book.guides) {
            val page = File("../../docs/site/guides/${guide.id}/index.html")
            assertTrue("${guide.id}: no page", page.isFile)
            val site = normalise(page.readText().replace(Regex("<[^>]+>"), " "))
            var at = 0
            for (block in GuidePage.blocks(book, guide)) {
                val sentence = normalise(english(guide, block))
                val found = site.indexOf(sentence, at)
                assertTrue("${guide.id}: \"$sentence\" not on its page after its earlier blocks", found >= 0)
                at = found + sentence.length
            }
        }
    }

    private fun english(guide: Guide, block: GuidePage.Block): String {
        val tool = table.first { it.packageName == guide.packages.first() }.name
        val values = block.fills.map { fill ->
            when (fill) {
                GuidePage.Fill.Tool -> tool
                GuidePage.Fill.Version -> guide.version.orEmpty()
                is GuidePage.Fill.Value -> fill.text
                is GuidePage.Fill.Label -> book.label(guide.id, fill.key).first { it.lang == "en" }.text
            }
        }
        return Regex("%(\\d+)\\$[sd]").replace(words.getValue(block.string)) { values[it.groupValues[1].toInt() - 1] }
    }

    /** Hugo's typographer turns straight quotes curly and escapes entities; spaces are folded. */
    private fun normalise(text: String) = text
        .replace("&ldquo;", "\"").replace("&rdquo;", "\"").replace("&lsquo;", "'").replace("&rsquo;", "'")
        .replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace('“', '"').replace('”', '"').replace('‘', '\'').replace('’', '\'')
        .replace(Regex("\\s+"), " ").replace(" .", ".").replace(" ,", ",").replace("\" ", "\"").replace(" \"", "\"")
}
