package org.visadahyu.datapavan.watch.guides

import org.visadahyu.datapavan.watch.chain.Listener
import org.visadahyu.datapavan.watch.chain.ToolTable

/** What a tool's page says (data/tools/guides.tsv, W8 part 3b; ADR 0041, "How the per-tool guides are built"). */
enum class Page {
    /** Steps to run the tool in its proxy mode, read from its source. */
    PROXY,

    /** It runs only as a VPN, and Watch carries a WireGuard configuration instead (W7). */
    WIREGUARD,

    /** It runs only as a VPN: Watch cannot run beside it. */
    VPN,

    /** No steps until a check on a phone: its code is closed, or its source does not settle its proxy mode. */
    WAITING,
}

/** The parts of a guide, in the order its screen shows them. */
enum class Part { ON, PASSWORD, ASKS, BACK, NOTE }

/** One guide of the table. */
data class Guide(
    val id: String,
    val packages: List<String>,
    val page: Page,
    /** The tool's version the steps are read at; null for a page without steps. */
    val version: String?,
    /** The SOCKS5 and HTTP listeners in proxy mode; for a tool whose profile sets them, the one the steps set. */
    val listeners: List<Listener>,
    /** `none`, `optional` or `default`, as tools.tsv. */
    val auth: String?,
    /** Whether it was tried with Watch at [version]. */
    val checked: Boolean,
)

/** What fills a place of a step's words. */
sealed interface Arg {
    /** One of the tool's labels (guide-labels.tsv). */
    data class Label(val key: String) : Arg

    /** A value, such as a port. */
    data class Value(val text: String) : Arg
}

/** One step or note of a guide (guide-steps.tsv): the Watch string that says it, and what fills its places. */
data class Step(val guide: String, val part: Part, val string: String, val args: List<Arg>)

/** A label of the tool's own (guide-labels.tsv): its text as the source has it, and where the installed tool keeps it. */
data class ToolLabel(val guide: String, val key: String, val lang: String, val text: String, val resource: Resource?)

/** An Android resource of another app: a string, or the item [index] of a string array. */
data class Resource(val type: String, val name: String, val index: Int? = null) {
    companion object {
        /** `string/NAME` or `array/NAME/INDEX`; anything else is none. */
        fun parse(cell: String): Resource? {
            val parts = cell.split('/')
            return when {
                parts.size == 2 && parts[0] == "string" && parts[1].isNotEmpty() -> Resource("string", parts[1])
                parts.size == 3 && parts[0] == "array" && parts[1].isNotEmpty() -> parts[2].toIntOrNull()?.let { Resource("array", parts[1], it) }
                else -> null
            }
        }
    }
}

/** The three tables of the guides, as the build copies them into the assets (build.gradle.kts, `ToolTable`). */
class GuideBook(val guides: List<Guide>, val steps: List<Step>, val labels: List<ToolLabel>) {
    fun guide(id: String): Guide? = guides.firstOrNull { it.id == id }

    /** The guide of a tool's package. */
    fun guideOf(packageName: String): Guide? = guides.firstOrNull { packageName in it.packages }

    fun steps(guide: String, part: Part): List<Step> = steps.filter { it.guide == guide && it.part == part }

    /** The rows of one label, one per language the source has it in. */
    fun label(guide: String, key: String): List<ToolLabel> = labels.filter { it.guide == guide && it.key == key }

    /** This book and [other] together: a debug build's test guides beside the shipped ones. */
    operator fun plus(other: GuideBook) = GuideBook(guides + other.guides, steps + other.steps, labels + other.labels)

    companion object {
        const val GUIDES = "guides.tsv"
        const val STEPS = "guide-steps.tsv"
        const val LABELS = "guide-labels.tsv"

        /** The three tables' text; a row that does not read is skipped, as ToolTable skips one. */
        fun parse(guides: String, steps: String, labels: String) = GuideBook(
            rows(guides, 12).mapNotNull { c ->
                val page = Page.entries.firstOrNull { it.name.lowercase() == c[2] } ?: return@mapNotNull null
                Guide(
                    id = c[0],
                    packages = c[1].split(','),
                    page = page,
                    version = c[3].takeIf { it != "-" },
                    listeners = if (c[6] == "-") emptyList() else ToolTable.listeners(c[6]),
                    auth = c[8].takeIf { it != "-" },
                    checked = c[10] != "waiting" && c[10] != "-",
                )
            },
            rows(steps, 5).mapNotNull { c ->
                val part = Part.entries.firstOrNull { it.name.lowercase() == c[1] } ?: return@mapNotNull null
                val args = if (c[3] == "-") emptyList() else c[3].split(',').map { if (it.startsWith("=")) Arg.Value(it.drop(1)) else Arg.Label(it) }
                Step(c[0], part, c[2], args)
            },
            rows(labels, 6).map { c -> ToolLabel(c[0], c[1], c[2], c[3], Resource.parse(c[4])) },
        )

        private fun rows(text: String, columns: Int): List<List<String>> = text.lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { it.split('\t') }
            .filter { it.size >= columns }
            .toList()
    }
}
