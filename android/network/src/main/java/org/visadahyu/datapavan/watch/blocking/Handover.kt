package org.visadahyu.datapavan.watch.blocking

/**
 * The setting tracker blocking is handed to the engine in ([org.visadahyu.datapavan.watch.Engine.nativeBlocking]), as a
 * pure function the JVM tests hold: one `key value...` a line, whole each time, so that nothing the engine holds is
 * older than what Watch keeps. The times are what is left now, at most each allowance's length ([Allowances.left]);
 * the engine turns them into deadlines on the time since the phone started, which no clock change moves.
 */
object Handover {
    /**
     * The setting's text: [on], [toolDns], the pause's milliseconds left ([pausedMs], 0 for none), the UIDs [covered],
     * the rows decided for each UID ([decided]: `block` for a code row its code blocks, `keep` for one it keeps and for an
     * exception's), the apps allowed with their milliseconds left ([apps], null for until blocked again; those with none
     * left are not written), and the rows allowed in one app ([entries], as UID and host).
     */
    fun text(
        on: Boolean,
        toolDns: Boolean,
        pausedMs: Long,
        covered: Collection<Int>,
        decided: Map<Int, Map<String, Grades.Decided>>,
        apps: Map<Int, Long?>,
        entries: Collection<Pair<Int, String>>,
    ): String = buildList {
        add("on ${if (on) 1 else 0}")
        add("tool-dns ${if (toolDns) 1 else 0}")
        add("paused ${pausedMs.coerceAtLeast(0)}")
        add((listOf("covered") + covered.sorted().map { it.toString() }).joinToString(" "))
        for ((uid, rows) in decided.toSortedMap()) {
            for ((host, grade) in rows.toSortedMap()) add("graded $uid $host ${if (grade == Grades.Decided.BLOCK) "block" else "keep"}")
        }
        for ((uid, left) in apps.toSortedMap()) {
            if (left == null) add("allowed $uid -") else if (left > 0) add("allowed $uid $left")
        }
        for ((uid, host) in entries.distinct().sortedWith(compareBy({ it.first }, { it.second }))) add("entry $uid $host")
    }.joinToString("\n")
}

/**
 * What blocking counted in the running engine's memory, for "Now" and the app's history
 * ([org.visadahyu.datapavan.watch.Engine.nativeBlocked]): never kept, never shown outside the app (ADR 0046, ADR 0047).
 */
object Tallies {
    /** One app's count for one row: lookups answered with no address apart from connections refused, since [sinceMs]. */
    data class Tally(val uid: Int, val host: String, val lookups: Long, val connections: Long, val sinceMs: Long)

    /** The engine's lines, `uid<TAB>host<TAB>lookups<TAB>connections<TAB>sinceMs`; a line that is not one is skipped. */
    fun parse(text: String): List<Tally> = text.lineSequence().mapNotNull { line ->
        val columns = line.split('\t')
        if (columns.size != 5) return@mapNotNull null
        val uid = columns[0].toIntOrNull() ?: return@mapNotNull null
        val lookups = columns[2].toLongOrNull() ?: return@mapNotNull null
        val connections = columns[3].toLongOrNull() ?: return@mapNotNull null
        val since = columns[4].toLongOrNull() ?: return@mapNotNull null
        Tally(uid, columns[1], lookups, connections, since).takeIf { columns[1].isNotEmpty() }
    }.toList()
}
