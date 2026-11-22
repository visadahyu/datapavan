package org.visadahyu.datapavan.watch.guides

/**
 * A guide as the screen shows it, block by block: the same blocks in the same order as its page on the website
 * (scripts/guides.py, `blocks`), so that the site says what Watch says. Each block names a Watch string; its places
 * are filled by the tool's name, its version, a value, or one of the tool's labels, which the screen reads from the
 * installed tool ([ToolLabels]).
 */
object GuidePage {
    sealed interface Fill {
        data object Tool : Fill

        data object Version : Fill

        data class Value(val text: String) : Fill

        data class Label(val key: String) : Fill
    }

    enum class Kind { HEADING, TEXT, STEP }

    data class Block(val kind: Kind, val string: String, val fills: List<Fill> = emptyList())

    /** Strings whose first place is the tool's name, which the step itself does not fill. */
    val toolNamed = setOf("guide_vpn_only", "guide_wireguard_only")

    fun blocks(book: GuideBook, guide: Guide): List<Block> {
        val out = mutableListOf<Block>()
        fun fills(step: Step) = step.args.map { if (it is Arg.Label) Fill.Label(it.key) else Fill.Value((it as Arg.Value).text) }
        fun text(string: String, vararg fills: Fill) = out.add(Block(Kind.TEXT, string, fills.toList()))
        fun heading(string: String) = out.add(Block(Kind.HEADING, string))
        fun steps(part: Part, kind: Kind = Kind.STEP) = book.steps(guide.id, part).forEach { out.add(Block(kind, it.string, fills(it))) }
        fun notes() = book.steps(guide.id, Part.NOTE).forEach {
            out.add(Block(Kind.TEXT, it.string, (if (it.string in toolNamed) listOf(Fill.Tool) else emptyList()) + fills(it)))
        }
        if (guide.page != Page.PROXY) {
            if (guide.page == Page.WAITING) text("guide_waiting_intro", Fill.Tool)
            notes()
            text(if (guide.page == Page.WIREGUARD) "guide_wireguard_add" else "guide_audit")
            return out
        }
        text("guide_intro", Fill.Tool)
        text("guide_assumes", Fill.Tool)
        heading("guide_heading_on")
        steps(Part.ON)
        guide.listeners.firstOrNull { it.socks }?.let { text("guide_listener", Fill.Value(it.host), Fill.Value(it.port.toString())) }
        notes()
        text("guide_next")
        heading("guide_heading_password")
        if (guide.auth == "none") {
            text("guide_password_none")
        } else {
            text("guide_password_optional")
            steps(Part.PASSWORD)
        }
        heading("guide_heading_asks")
        steps(Part.ASKS, Kind.TEXT)
        heading("guide_heading_back")
        steps(Part.BACK)
        text("guide_back_note", Fill.Tool)
        text("guide_read", Fill.Tool, Fill.Version)
        text(if (guide.checked) "guide_checked" else "guide_not_checked")
        return out
    }
}
