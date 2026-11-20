package org.visadahyu.datapavan.ui

/**
 * What the licence screen lists (W7, part 2; ADR 0035's release gate), read from the files the APK carries under
 * `assets/licences/`, so that nobody keeps a second list by hand: a crate added to a native library later is on the
 * screen once scripts/licences.py has written it into `licences/`, which scripts/check.sh holds to core/Cargo.lock;
 * a Java or Kotlin library added later fails the build until `licences/jvm-components.tsv` names it
 * (app/build.gradle.kts, `checkJvmComponents`). Pure, so that the unit tests read the repository's own files with it.
 */
internal object LicenceList {
    /** The Apache License 2.0, Datapavan's own licence, under which most of its parts are published too. */
    const val LICENSE = "LICENSE"

    /** The table of the Java and Kotlin libraries: an index the screen reads, not a text it offers. */
    const val JVM_TABLE = "jvm-components.tsv"

    /** One component the APK carries, with the files under `assets/licences/` that hold its licence's text. */
    data class Component(
        val name: String,
        /** Its version, where the list gives one: the native crates'. */
        val version: String?,
        /** Its licence, as an SPDX expression. */
        val licence: String,
        val texts: List<Text>,
    )

    /**
     * A file under `assets/licences/`, and where in it the component's own text begins: [anchor], when not null, is
     * held by the paragraph to scroll to ([anchorIn]).
     */
    data class Text(val file: String, val anchor: String? = null)

    /** A native library's crates as its file lists them, and the lines that did not read, shown as they are. */
    data class Crates(val library: String?, val crates: List<Component>, val unread: List<String>)

    /** A row of `jvm-components.tsv`. */
    data class JvmRow(val pattern: String, val component: Component, val editions: Set<String>)

    /** The editions a row of `jvm-components.tsv` may name; `all` stands for every one. */
    val EDITIONS = setOf("basic", "lite", "advanced")

    private val CRATE = Regex("""^- ([A-Za-z0-9_-]+) ([0-9][0-9A-Za-z.+-]*): (.+)$""")
    private const val NO_TEXT = "; its package carries no licence text: "
    private const val UNDER_APACHE = "taken under Apache-2.0, whose text is LICENSE"
    private val LIBRARY = Regex("""^The crates inside (\S+),""")

    /**
     * The crates of a native library's file (`native-core.txt`, `native-watch.txt`, as scripts/licences.py writes
     * them): each `- NAME VERSION: EXPRESSION` line before the texts, with the text that covers it. A crate whose
     * package carries its own texts is covered by this file, at the block that names it as a carrier; one that
     * carries none names the repository's texts for it, or Apache-2.0's, which is [LICENSE]. A line of the list
     * that does not read is kept in [Crates.unread], for the screen to show as it is and the tests to refuse.
     */
    fun crates(file: String, content: String): Crates {
        val lines = content.lines()
        val list = lines.takeWhile { !it.startsWith("====") }
        val crates = mutableListOf<Component>()
        val unread = mutableListOf<String>()
        for (line in list.filter { it.startsWith("- ") }) {
            val match = CRATE.matchEntire(line)
            if (match == null) {
                unread += line
                continue
            }
            val (name, version, rest) = match.destructured
            val licence = rest.substringBefore(NO_TEXT)
            val texts = when {
                NO_TEXT !in rest -> listOf(Text(file, "$name $version ("))
                rest.substringAfter(NO_TEXT) == UNDER_APACHE -> listOf(Text(LICENSE))
                else -> rest.substringAfter(NO_TEXT).split(", ").map { Text(it.trim().substringAfterLast('/')) }
            }
            if (licence.isBlank() || texts.any { it.file.isBlank() }) unread += line else crates += Component(name, version, licence, texts)
        }
        return Crates(lines.firstOrNull()?.let { LIBRARY.find(it)?.groupValues?.get(1) }, crates, unread)
    }

    /**
     * The rows of `jvm-components.tsv`: a Maven group, `group:artifact` or `group.*` (the group and those under it),
     * the name shown, the licence's SPDX expression, the editions (`all`, or some of [EDITIONS] by commas), and the
     * file under `assets/licences/` that holds the licence's text. Comment lines start with `#`. A row that does not
     * read is refused, as the build's check refuses it.
     */
    fun jvmRows(content: String): List<JvmRow> = content.lines()
        .filter { it.isNotBlank() && !it.startsWith("#") }
        .map { line ->
            val fields = line.split('\t')
            require(fields.size == 5 && fields.all { it.isNotBlank() }) { "not a row of five fields: $line" }
            val (pattern, name, licence, editions, text) = fields
            val named = if (editions == "all") EDITIONS else editions.split(',').toSet()
            require(named.isNotEmpty() && EDITIONS.containsAll(named)) { "unknown editions: $line" }
            JvmRow(pattern, Component(name, null, licence, listOf(Text(text))), named)
        }

    /** The Java and Kotlin libraries of [edition] (`basic`, `lite` or `advanced`), in the table's order. */
    fun jvm(content: String, edition: String): List<Component> =
        jvmRows(content).filter { edition in it.editions }.map { it.component }

    /** A text cut into paragraphs at its empty lines, each kept with its own line breaks. */
    fun paragraphs(content: String): List<String> =
        content.replace("\r\n", "\n").split(Regex("\n[ \t]*\n+")).map { it.trimEnd() }.filter { it.isNotBlank() }

    /**
     * The paragraph of [paragraphs] where a crate's own text begins: the block whose `Carried by:` line names
     * [anchor] (`NAME VERSION (`) as a carrier; 0 when none does, or with no anchor.
     */
    fun anchorIn(paragraphs: List<String>, anchor: String?): Int {
        if (anchor == null) return 0
        val index = paragraphs.indexOfFirst { paragraph ->
            paragraph.lines().any { line ->
                line.startsWith("Carried by: ") && ("Carried by: $anchor" in line || "; $anchor" in line)
            }
        }
        return index.coerceAtLeast(0)
    }

    /** The edition this build is, as `jvm-components.tsv` names it. */
    fun edition(advanced: Boolean, play: Boolean): String = when {
        advanced -> "advanced"
        play -> "lite"
        else -> "basic"
    }
}
