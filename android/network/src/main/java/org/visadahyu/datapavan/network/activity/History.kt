package org.visadahyu.datapavan.network.activity

import java.net.InetAddress
import org.visadahyu.datapavan.network.log.LogRecord

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
        /** The app's state over the segment, an [org.visadahyu.datapavan.network.log.AppState] code. */
        val state: Int,
        /** Whether the connection went on after this segment. */
        val continues: Boolean,
        /**
         * Whether the log keeps no destination of it, while the switch "Log where apps connect ..." was off: an app
         * sent through the user's tool or a tunnel, the tool's own servers, or a flow of such an app that went
         * directly ([leftOut] tells them apart). The engine writes such a segment with no name and an address of
         * zeros (0.0.0.0 or ::), which is no destination (review c1 of W5's third part, screens, M3: the history
         * showed it as one); an app's own proxy says so itself ([LogRecord.Proxy.leftOut]).
         */
        val unlogged: Boolean = false,
        /** Its route, as the log codes it ([LogRecord.VIA_DIRECT] and the others), and for a tunnel its number (W7). */
        val via: Int = LogRecord.VIA_DIRECT,
        val tunnel: Long = 0,
        /**
         * The proxy it went through, read from the connection or inferred (ADR 0052), and the AS number of the
         * proxy's network; a proxy with its destination not logged has only its kind, at an address of zeros.
         */
        val proxy: LogRecord.Proxy? = null,
        val asn: Long = 0,
        /** [address] as the record held it, read once here, not while the screen draws (screens review, nit). */
        val ip: InetAddress = ANY,
        /**
         * Whether tracker blocking refused it (version 6 of the log; W8, part 3a, ADR 0053), and the SDK of the row that
         * refused it, kept by the engine even where the switch left the flow's names out ([LogRecord.Segment.blockedSdk]).
         */
        val blocked: Boolean = false,
        val blockedSdk: String = "",
    )

    /**
     * Why a segment shows no destination (fix round of W8 part 2a): an app's own proxy whose flow the engine left out
     * for the switch ([PROXY]); a flow sent through a WireGuard tunnel ([TUNNEL]); the user's tool's own servers
     * ([TOOL_SERVERS]); a flow sent through the tool ([THROUGH_TOOL]), only where its recorded route says so; a flow
     * of an app sent through the tool or a tunnel that went directly all the same ([DIRECT]: one opened before the
     * app was sent through them, its local network, or what the tool does not carry); and a record written before
     * routes were logged ([NO_ROUTE]), which says nothing of the way it went.
     */
    enum class LeftOut { PROXY, TUNNEL, TOOL_SERVERS, THROUGH_TOOL, DIRECT, NO_ROUTE }

    /**
     * Why [entry] shows no destination, or null for one that shows its own; [tool] is whether its app is the user's
     * tool. A proxy's flow is told by its own flag, never by an address of zeros, and a flow is said to have gone
     * through the tool only where its recorded route is the tool's.
     */
    fun leftOut(entry: Entry, tool: Boolean): LeftOut? = when {
        entry.proxy?.leftOut == true -> LeftOut.PROXY
        !entry.unlogged -> null
        entry.via == LogRecord.VIA_TUNNEL -> LeftOut.TUNNEL
        tool -> LeftOut.TOOL_SERVERS
        entry.via == LogRecord.VIA_TOOL -> LeftOut.THROUGH_TOOL
        entry.via == LogRecord.VIA_DIRECT -> LeftOut.DIRECT
        else -> LeftOut.NO_ROUTE
    }

    /** The address of zeros, for an entry made without one. */
    private val ANY: InetAddress = InetAddress.getByAddress(ByteArray(4))

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
                    proxy = it.proxy,
                    asn = it.asn,
                    ip = it.address,
                    blocked = it.blocked,
                    blockedSdk = it.blockedSdk,
                )
            }
            .sortedWith(compareByDescending<Entry> { it.start }.thenByDescending { it.end })
        val lookups = kept.filterIsInstance<LogRecord.Lookups>().sumOf { it.count }
        return Day(day, entries, lookups, before.size)
    }

    /** The days the log keeps, today first: as many as [retentionDays], none for retention "none". */
    fun days(today: Long, retentionDays: Int): List<Long> = (0 until retentionDays).map { today - it }
}
