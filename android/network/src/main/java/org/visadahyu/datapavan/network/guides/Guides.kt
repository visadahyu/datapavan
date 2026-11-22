package org.visadahyu.datapavan.network.guides

import android.content.Context
import java.io.FileNotFoundException
import org.visadahyu.datapavan.network.chain.KnownTool

/** A link from the chain section to one installed tool's guide (W8, part 3b). */
data class GuideLink(val guide: String, val packageName: String, val name: String, val page: Page)

/**
 * The guides from any part of the network part: the chain section, the guide's screen, the tool's finder and, in W9,
 * onboarding.
 */
object Guides {
    /**
     * The guides as the build put them in the assets, and in debug builds also the test tool's (src/debug/assets),
     * which release builds do not carry.
     */
    fun book(context: Context): GuideBook {
        fun read(prefix: String): GuideBook? = try {
            val assets = context.assets
            fun text(name: String) = assets.open(prefix + name).bufferedReader().use { it.readText() }
            GuideBook.parse(text(GuideBook.GUIDES), text(GuideBook.STEPS), text(GuideBook.LABELS))
        } catch (e: FileNotFoundException) {
            null
        }
        val shipped = read("") ?: GuideBook(emptyList(), emptyList(), emptyList())
        return read(TEST_PREFIX)?.let { shipped + it } ?: shipped
    }

    private const val TEST_PREFIX = "test-"

    /**
     * The guide of each tool of the table installed here, in the guides' order. Android hides a VPN's owner from other
     * apps (FoundTool.ownerConfirmed), so the network part cannot tell which tool runs as the VPN now: it links every
     * installed one, rather than "the tool running as a VPN". Blocking: call it off the main thread.
     */
    fun installed(book: GuideBook, table: List<KnownTool>, isInstalled: (String) -> Boolean): List<GuideLink> {
        val names = table.associate { it.packageName to it.name }
        return book.guides.flatMap { guide ->
            guide.packages.filter(isInstalled).map { GuideLink(guide.id, it, names[it] ?: it, guide.page) }
        }
    }

    /**
     * The table with the listeners the guides name for tools whose profile sets them (tools.tsv's `profile`): the guide
     * has the user set that port in the tool, so the network part's finder greets it there, and only there (ADR 0041).
     * The owner Android names for the port still decides whether it is the tool's.
     */
    fun withNamedPorts(table: List<KnownTool>, book: GuideBook): List<KnownTool> = table.map { tool ->
        val guide = book.guideOf(tool.packageName)
        if (tool.proxyMode && tool.listeners.isEmpty() && guide?.page == Page.PROXY && guide.listeners.isNotEmpty()) {
            tool.copy(listeners = guide.listeners)
        } else {
            tool
        }
    }
}
