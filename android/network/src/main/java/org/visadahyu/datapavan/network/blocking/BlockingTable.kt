package org.visadahyu.datapavan.network.blocking

/**
 * Tracker blocking's graded table as Watch's Kotlin side reads it (W8, part 3a; ADR 0053): `blocking/hosts.tsv` of the
 * data pack the audit verifies, with a debug build's row for the lab's names after it ([LabRow]). The engine reads the
 * same bytes for its decisions (core/net/src/blocking.rs); this reads them for what the engine leaves to Kotlin: each
 * row's SDK, the Java package prefix that joins it to εxodus's tracker of the same SDK ([TrackerCode]), the condition
 * of a grade the app's own code decides ([Grades]), and the function the screens say.
 *
 * Its rules are the engine's, so that the two never read one table two ways: a line that is not nine columns, a host
 * that is not a DNS name, a grade or a condition it does not know, a host twice, or more rows than [MAX_ROWS] refuses
 * the whole table, as the engine refuses it, and then nothing is blocked and nothing is said of blocking.
 */
class BlockingTable private constructor(
    /** The rows, in the table's order. */
    val rows: List<Row>,
) {
    /** What a host does, as the table grades it: never shown as a word on a screen (ADR 0025, decision 4). */
    enum class Grade {
        /** Only tracking, analytics, attribution, ads, or crash or performance reports: blocked in every app covered. */
        BLOCK,

        /** It also serves the app's own function: blocked in none. */
        KEEP,

        /** It serves both, and the app's own code decides ([Grades.ofCode]). */
        CODE,
    }

    /**
     * One row: its [host], the SDK's Maven coordinate [sdk], the package prefix [classes] of the SDK's feature that
     * sends there, its [grade], for a [Grade.CODE] row the prefixes that block it ([blockWith]) and keep it
     * ([keepWith]), and its [function], in the table's English (data, as εxodus's names are).
     */
    data class Row(
        val host: String,
        val sdk: String,
        val classes: String,
        val grade: Grade,
        val blockWith: List<String> = emptyList(),
        val keepWith: List<String> = emptyList(),
        val function: String = "",
    )

    private val byHost: Map<String, Row> = rows.associateBy { it.host }
    private val bySdk: Map<String, List<Row>> = rows.groupBy { it.sdk }

    /** The row whose host is [host], written as the table writes it. */
    fun row(host: String): Row? = byHost[host]

    /** The rows of the SDK [sdk], by its Maven coordinate, as a blocked flow's record names it. */
    fun ofSdk(sdk: String): List<Row> = bySdk[sdk].orEmpty()

    /**
     * The narrowest row that names [name], as the engine's `Table::find` finds it: the row of the name itself, else of
     * the name one label up, and so on, on label boundaries, never as a substring, so that `app-measurement.com` names
     * `x.app-measurement.com` and never `notapp-measurement.com`. Names compare without regard to ASCII case, a trailing
     * dot left out; an address written as text, or an empty name, is named by none.
     */
    fun find(name: String): Row? {
        if (rows.isEmpty()) return null
        val bare = name.removeSuffix(".").lowercase(java.util.Locale.ROOT)
        if (bare.isEmpty() || bare.length > MAX_NAME || isAddress(bare)) return null
        var at = 0
        while (true) {
            byHost[bare.substring(at)]?.let { return it }
            val dot = bare.indexOf('.', at)
            if (dot < 0) return null
            at = dot + 1
        }
    }

    companion object {
        /** The table's place in the data pack. */
        const val PATH = "blocking/hosts.tsv"

        /** The most rows a table may hold, the engine's `MAX_ENTRIES`. */
        const val MAX_ROWS = 16_384

        private const val MAX_NAME = 253
        private const val MAX_LABEL = 63
        private const val COLUMNS = 9

        /** An empty table: nothing read, nothing blocked. */
        val EMPTY = BlockingTable(emptyList())

        /**
         * Reads `hosts.tsv` as the data pack holds it: lines starting with `#` and empty lines are skipped, and every
         * other line is a row of nine tab-separated columns (host, sdk, classes, grade, condition, function, evidence,
         * source, checked). Null for a table the engine refuses.
         */
        fun parse(tsv: String): BlockingTable? {
            val rows = mutableListOf<Row>()
            val seen = HashSet<String>()
            for (line in tsv.lines()) {
                if (line.isEmpty() || line.startsWith("#")) continue
                val columns = line.split('\t')
                if (columns.size != COLUMNS || rows.size == MAX_ROWS) return null
                val (host, sdk, classes, grade, condition) = columns
                if (!isHost(host) || !seen.add(host)) return null
                val row = when {
                    grade == "block" && condition == "-" -> Row(host, sdk, classes, Grade.BLOCK, function = columns[5])
                    grade == "keep" && condition == "-" -> Row(host, sdk, classes, Grade.KEEP, function = columns[5])
                    grade == "code" -> {
                        val (block, keep) = condition(condition) ?: return null
                        Row(host, sdk, classes, Grade.CODE, block, keep, columns[5])
                    }
                    else -> return null
                }
                rows += row
            }
            return BlockingTable(rows)
        }

        /**
         * A code-dependent row's condition, `block-with P|P keep-with P|P`, each prefix a Java package name of three
         * bytes or more ending in `.`, as the engine's `is_condition` holds it: its block-with and keep-with prefixes,
         * or null for a condition that is not one.
         */
        internal fun condition(text: String): Pair<List<String>, List<String>>? {
            val words = text.split(' ')
            if (words.size != 4 || words[0] != "block-with" || words[2] != "keep-with") return null
            val prefixes = { list: String ->
                list.split('|').takeIf { all ->
                    list.isNotEmpty() && all.all { p -> p.length >= 3 && p.endsWith('.') && p.all { it.isLetterOrDigit() && it.code < 128 || it == '.' || it == '_' } }
                }
            }
            return (prefixes(words[1]) ?: return null) to (prefixes(words[3]) ?: return null)
        }

        /**
         * Whether [host] is written as a row's host must be, as the engine's `is_host` holds it: two labels or more of
         * lower-case letters, digits, `-` and `_`, each 1 to 63 bytes and not starting or ending with `-`, at most 253
         * bytes in all, and no address.
         */
        internal fun isHost(host: String): Boolean {
            val labels = host.split('.')
            return host.length <= MAX_NAME && labels.size >= 2 && !isAddress(host) && labels.all { label ->
                label.length in 1..MAX_LABEL && !label.startsWith('-') && !label.endsWith('-') &&
                    label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
            }
        }

        /** Whether [text] is an address as Rust's `IpAddr` reads one: four decimal bytes, or IPv6's colons. */
        private fun isAddress(text: String): Boolean {
            if (':' in text) return true
            val parts = text.split('.')
            return parts.size == 4 && parts.all { part ->
                part.length in 1..3 && part.all { it in '0'..'9' } && part.toInt() <= 255 && (part.length == 1 || part[0] != '0')
            }
        }
    }
}

/**
 * The rows of `blocking/exceptions.tsv` (ADR 0053): an SDK vendor's own app, by its package AND its signing certificate,
 * keeps a host the table grades `block` or `code`, for that app's own function. Granted for function only, never
 * because one company owns both the app and the tracker (decision 2): Watch never adds one by company, and an app whose
 * certificate is not the one written here is blocked as any other.
 */
object Exceptions {
    /** The file's place in the data pack. */
    const val PATH = "blocking/exceptions.tsv"

    /** One exception: the app's [packageName], the SHA-256 of its signing [certificate] in lower-case hex, and the [host] kept. */
    data class Kept(val packageName: String, val certificate: String, val host: String)

    private val SHA256 = Regex("[0-9a-f]{64}")

    /** Reads the file (columns package, certificate, host, reason, source, checked); a line that is not one is skipped. */
    fun parse(tsv: String): List<Kept> = tsv.lineSequence()
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { it.split('\t') }
        .filter { it.size == 6 && it[0].isNotEmpty() && SHA256.matches(it[1]) && BlockingTable.isHost(it[2]) }
        .map { Kept(it[0], it[1], it[2]) }
        .toList()
}
