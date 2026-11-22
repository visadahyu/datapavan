package org.visadahyu.datapavan.watch.blocking

import org.visadahyu.datapavan.audit.AppSigning

/**
 * What a row is for one app, where the table leaves it to the app (ADR 0053): a `code` row's grade from the app's own
 * code, as the audit's scan found it, and the rows an SDK vendor's exception keeps for its own app. This is function,
 * never owner: no rule here reads who publishes the app, and the same row is decided alike in every app whose code is
 * alike, the tracker's own company's included (decision 2, extending ADR 0020's reasons to blocking).
 */
object Grades {
    /**
     * A row as decided for one app: blocked; kept by its code; kept because the audit never read its code (or it changed
     * since); or kept by an exception for the vendor's own app. Only [BLOCK] blocks.
     */
    enum class Decided { BLOCK, KEEP, NOT_READ, EXCEPTED }

    /**
     * A `code` row's grade for an app whose scan found the εxodus trackers [embedded] (null where it was never scanned,
     * its code could not be read, or it changed since): [Decided.BLOCK] when it holds a tracker one of the row's
     * block-with prefixes names and none that its keep-with prefixes name (`graph.facebook.com` in an app with Facebook's
     * App Events and without its Login, Share or Places), else [Decided.KEEP]; kept too where it was never scanned
     * ([Decided.NOT_READ]), so that a host the app's own function may need is never blocked on a guess.
     */
    fun ofCode(row: BlockingTable.Row, embedded: Set<Int>?, trackers: List<TrackerCode.Tracker>): Decided {
        if (row.grade != BlockingTable.Grade.CODE) return Decided.KEEP
        if (embedded == null) return Decided.NOT_READ
        val block = TrackerCode.ids(row.blockWith, trackers)
        val keep = TrackerCode.ids(row.keepWith, trackers)
        return if (embedded.any { it in block } && embedded.none { it in keep }) Decided.BLOCK else Decided.KEEP
    }

    /**
     * The hosts [exceptions] keep for an app of the [packages] and their signing: those whose package AND signing
     * certificate, the current one or one of its rotation history (as the owners' table matches a publisher), match a
     * row. Never by company.
     */
    fun excepted(exceptions: List<Exceptions.Kept>, packages: List<Pair<String, AppSigning?>>): Set<String> =
        exceptions.filter { kept ->
            packages.any { (name, signing) -> name == kept.packageName && signing != null && kept.certificate in signing.current + signing.history }
        }.map { it.host }.toSet()

    /**
     * The rows decided for one app: each `code` row by its code ([ofCode]), and each host [excepted] keeps, which wins.
     * Rows graded `block` or `keep` are what the table says, and are not in it.
     */
    fun forApp(table: BlockingTable, trackers: List<TrackerCode.Tracker>, embedded: Set<Int>?, excepted: Set<String>): Map<String, Decided> =
        buildMap {
            for (row in table.rows) if (row.grade == BlockingTable.Grade.CODE) put(row.host, ofCode(row, embedded, trackers))
            for (host in excepted) if (table.row(host) != null) put(host, Decided.EXCEPTED)
        }

    /** Whether [row] is blocked in an app whose rows were decided as [decided] ([forApp]). */
    fun blocks(row: BlockingTable.Row, decided: Map<String, Decided>?): Boolean = when (decided?.get(row.host)) {
        Decided.BLOCK -> true
        Decided.KEEP, Decided.NOT_READ, Decided.EXCEPTED -> false
        null -> row.grade == BlockingTable.Grade.BLOCK
    }
}

/**
 * The audit's scan of each app's code, as it keeps it between audits (`noBackupFilesDir/tracker-scan.tsv`, written by
 * the app's `ScanCache`, in the same package and so the same files in Advanced): a first line `data<TAB>version`, the
 * version of the signatures it was made with, then one line per app, `package<TAB>lastUpdate<TAB>unreadable<TAB>
 * embedded<TAB>referenced`, the ids by commas. Read here, in Watch's process, without the audit's classes: Watch only
 * needs the εxodus ids the app's code holds. Under ADR 0047's profile the audit keeps no such file, and every
 * code-dependent row is then kept.
 */
object ScanResults {
    /** The file's name in the app's no-backup files. */
    const val FILE = "tracker-scan.tsv"

    /** One app's scan: the app's version it was made of ([lastUpdate]), whether its code could not be read, and the ids found. */
    data class Scan(val lastUpdate: Long, val unreadable: Boolean, val embedded: Set<Int>)

    /** The file's scans by package; none for a file that does not start as the audit writes it. */
    fun parse(text: String): Map<String, Scan> {
        val lines = text.lines()
        if (lines.firstOrNull()?.startsWith("data\t") != true) return emptyMap()
        return lines.drop(1).mapNotNull { line ->
            val columns = line.split('\t')
            if (columns.size != 5) return@mapNotNull null
            val lastUpdate = columns[1].toLongOrNull() ?: return@mapNotNull null
            columns[0] to Scan(lastUpdate, columns[2] == "1", columns[3].split(',').mapNotNull { it.toIntOrNull() }.toSet())
        }.toMap()
    }

    /**
     * The trackers embedded in the app [packageName] at the version it has now ([lastUpdate], `PackageInfo.lastUpdateTime`),
     * or null where it was never scanned, its code could not be read, or it was updated since its scan.
     */
    fun embedded(scans: Map<String, Scan>, packageName: String, lastUpdate: Long): Set<Int>? =
        scans[packageName]?.takeIf { it.lastUpdate == lastUpdate && !it.unreadable }?.embedded
}
