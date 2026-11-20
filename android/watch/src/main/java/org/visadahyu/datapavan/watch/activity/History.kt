package org.visadahyu.datapavan.watch.activity

import org.visadahyu.datapavan.watch.log.LogRecord

/**
 * Each app's history (ADR 0046, decision 2 (d), last bullet; DESIGN's W5 row: "who did this app talk to?"):
 * its timeline from the connection log, a day at a time, newest first, as a pure function the JVM tests hold.
 * The log is read off the main thread, and only on an unlocked phone (ADR 0037).
 */
object History {
    /** One segment of a connection: its time, destination (both names), bytes and its app's state. */
    data class Entry(
        val start: Long,
        val end: Long,
        val protocol: Int,
        val name: String,
        /** The DNS answer's name, where it differs from [name]; empty otherwise. */
        val dnsName: String,
        val address: String,
        val port: Int,
        val namedBy: Int,
        val sent: Long,
        val received: Long,
        /** The app's state over the segment, an [org.visadahyu.datapavan.watch.log.AppState] code. */
        val state: Int,
        /** Whether the connection went on after this segment. */
        val continues: Boolean,
        /**
         * Whether the log keeps no destination of it: an app chained through the user's tool, or the tool's own
         * servers, while "Log where these apps connect" was off. The engine writes such a segment with no name
         * and an address of zeros (0.0.0.0 or ::), which is no destination (review c1 of W5's third part,
         * screens, M3: the history showed it as one).
         */
        val unlogged: Boolean = false,
        /** Its route, as the log codes it ([LogRecord.VIA_DIRECT] and the others), and for a tunnel its number (W7). */
        val via: Int = LogRecord.VIA_DIRECT,
        val tunnel: Long = 0,
    )

    /**
     * One day of an app's history: its segments, newest first; how many names it looked up through Watch's
     * own DNS address; and how many records under its UID are older than the app (its first install time),
     * which belong to an app since removed that held the same UID, and are not shown as this app's.
     */
    data class Day(val day: Long, val entries: List<Entry>, val lookups: Long, val beforeInstall: Int)

    /**
     * The day [day] of the app [uid] (null for flows Android named no app for) from that day's [records],
     * the app installed at [installedAt] (milliseconds since 1970; null when no app holds the UID now, as
     * for an app since removed, whose every record is shown).
     */
    fun day(day: Long, records: List<LogRecord>, uid: Int?, installedAt: Long?): Day {
        val own = records.filter { it.uid == uid }
        val (kept, before) = own.partition { installedAt == null || it.start >= installedAt }
        val entries = kept.filterIsInstance<LogRecord.Segment>()
            .map {
                Entry(
                    it.start, it.end, it.protocol, it.name, it.dnsName.takeIf { dns -> dns != it.name }.orEmpty(),
                    it.address.hostAddress.orEmpty(), it.port, it.namedBy, it.up, it.down, it.state, it.continues,
                    unlogged = it.address.isAnyLocalAddress && it.name.isEmpty(),
                    via = it.via,
                    tunnel = it.tunnel,
                )
            }
            .sortedWith(compareByDescending<Entry> { it.start }.thenByDescending { it.end })
        val lookups = kept.filterIsInstance<LogRecord.Lookups>().sumOf { it.count }
        return Day(day, entries, lookups, before.size)
    }

    /** The days the log keeps, today first: as many as [retentionDays], none for retention "none". */
    fun days(today: Long, retentionDays: Int): List<Long> = (0 until retentionDays).map { today - it }
}
