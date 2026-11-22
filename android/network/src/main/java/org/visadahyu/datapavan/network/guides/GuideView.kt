package org.visadahyu.datapavan.network.guides

import org.visadahyu.datapavan.ui.isolate

/**
 * A guide's screen with every place filled (W8, part 3b): the title's string, then [GuidePage]'s blocks, each a Watch
 * string by name and the text of its places, and last the line that says where the quoted labels come from. A label
 * read from the installed tool is shown in the phone's language, followed by Datapavan's where the two differ, set by
 * the translatable pattern [both] (brackets, full-width in Chinese); every tool's word keeps its own direction inside
 * the sentence.
 */
data class GuideView(val title: String, val tool: String, val blocks: List<Shown>) {
    data class Shown(val kind: GuidePage.Kind, val string: String, val args: List<String>)

    companion object {
        fun of(
            book: GuideBook,
            guide: Guide,
            toolName: String,
            labels: ToolLabels,
            both: (String, String) -> String = { first, second -> "$first ($second)" },
        ): GuideView {
            val tool = isolate(toolName)
            val blocks = GuidePage.blocks(book, guide).map { block ->
                Shown(
                    block.kind,
                    block.string,
                    block.fills.map { fill ->
                        when (fill) {
                            GuidePage.Fill.Tool -> tool
                            GuidePage.Fill.Version -> isolate(guide.version.orEmpty())
                            is GuidePage.Fill.Value -> isolate(fill.text)
                            is GuidePage.Fill.Label -> labels.shown(fill.key).let { shown ->
                                shown.also?.let { both(isolate(shown.text), isolate(it)) } ?: isolate(shown.text)
                            }
                        }
                    },
                )
            }
            val source = if (guide.page != Page.PROXY) {
                emptyList()
            } else if (labels.anyFromTool) {
                listOf(Shown(GuidePage.Kind.TEXT, "guide_labels_tool", listOf(tool)))
            } else {
                listOf(Shown(GuidePage.Kind.TEXT, "guide_labels_recorded", emptyList()))
            }
            val title = if (guide.page == Page.PROXY) "guide_title_proxy" else "guide_title_other"
            return GuideView(title, tool, blocks + source)
        }
    }
}
