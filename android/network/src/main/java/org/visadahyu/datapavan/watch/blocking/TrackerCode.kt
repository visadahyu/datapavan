package org.visadahyu.datapavan.watch.blocking

/**
 * How a row of the graded table is joined to the εxodus tracker of its SDK (ADR 0046's decision 4 as ADR 0053 amends
 * it: εxodus names the tracker, the graded table gives its hosts), at run time, from the data pack's
 * `exodus/trackers.tsv` (ODbL), whose fifth column is each tracker's code signature: Java package prefixes, `|` between
 * alternatives, with `\.` escapes. The graded table holds no εxodus data (its LICENSE), only a prefix of its own.
 *
 * A tracker is named by a prefix P when one of its alternatives, unescaped, is a prefix of P or P of it: the row's
 * `com.google.android.gms.ads.` names Google AdMob, whose `com.google.android.gms.ads.AdView` it begins, and
 * `com.facebook.ads.` names Facebook Ads, whose `com.facebook.ads` begins it. An empty alternative names nothing.
 */
object TrackerCode {
    /** The table's place in the data pack. */
    const val PATH = "exodus/trackers.tsv"

    /** One εxodus tracker: its [id], [name] and [website], and its code signature's alternatives, unescaped. */
    data class Tracker(val id: Int, val name: String, val website: String, val prefixes: List<String>)

    /** Reads the table's six tab-separated columns (id, name, categories, website, code signature, network signature). */
    fun parse(tsv: String): List<Tracker> = tsv.lineSequence()
        .filter { it.isNotEmpty() && !it.startsWith("#") }
        .map { it.split('\t') }
        .filter { it.size == 6 }
        .mapNotNull { columns ->
            val id = columns[0].toIntOrNull() ?: return@mapNotNull null
            Tracker(id, columns[1], columns[3], columns[4].split('|').map(::unescape).filter { it.isNotEmpty() })
        }
        .toList()

    /** An alternative as written with `\` escapes (`com\.example\.`), read as the text it matches. */
    fun unescape(alternative: String): String = Regex("""\\(.)""").replace(alternative) { it.groupValues[1] }

    /** The trackers [prefix] names, by the rule above. */
    fun named(prefix: String, trackers: List<Tracker>): List<Tracker> =
        if (prefix.isEmpty()) emptyList() else trackers.filter { tracker -> tracker.prefixes.any { prefix.startsWith(it) || it.startsWith(prefix) } }

    /** The ids of the trackers any of [prefixes] names. */
    fun ids(prefixes: List<String>, trackers: List<Tracker>): Set<Int> = prefixes.flatMap { named(it, trackers) }.map { it.id }.toSet()
}
