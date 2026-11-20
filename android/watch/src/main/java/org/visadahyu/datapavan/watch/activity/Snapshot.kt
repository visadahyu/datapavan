package org.visadahyu.datapavan.watch.activity

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.visadahyu.datapavan.watch.log.AppState

/**
 * What the live view "Now" draws (ADR 0046, decision 2 (d)), as the engine hands it over
 * ([org.visadahyu.datapavan.watch.Engine.nativeActivity]; core/net/src/snapshot.rs, version 4): each app
 * that sent or received in a window, with its bytes by state, those in no state by why, the window while
 * the screen was off, the destinations it reached with each one's route and proxy, and the WireGuard tunnel it went
 * through with its destinations not kept (W7). From the engine's memory only; nothing of it is kept. Both
 * sides ship in one build, so earlier versions are refused.
 */
data class Snapshot(
    /** When it was taken, in milliseconds since 1970 (UTC). */
    val taken: Long,
    /** What the latest reading of the states knew: one of [NOTHING_YET], [STATES], [NO_ACCESS], [LOCKED]. */
    val known: Int,
    /** The end of what was told of the states. */
    val toldUntil: Long,
    /** The screen as last told: [SCREEN_OFF], [SCREEN_ON] or [SCREEN_UNKNOWN]. */
    val screen: Int,
    /** When the screen last came on, the start of the window [SINCE_SCREEN_ON]; 0 when not known. */
    val screenOnSince: Long,
    /**
     * The window [WHILE_OFF]: when the screen went off, 0 for no window (it has not gone off since Watch
     * started, or the live memory was cleared since), and when it came on again, 0 while it is still off.
     */
    val offFrom: Long,
    val offUntil: Long,
    val apps: List<App>,
) {
    /** An app, by UID; null for flows Android named no app for. */
    data class App(
        val uid: Int?,
        /** Its state in the last second told, an [AppState] code; [AppState.NOT_YET] while not told. */
        val now: Int,
        /** Whether it is the user's circumvention tool, which carries the chained apps' traffic. */
        val isTool: Boolean,
        /** Whether it went through the tool with its destinations not kept ("Log where these apps connect" off). */
        val throughTool: Boolean,
        /**
         * Its bytes up and down: by window ([TEN_MINUTES], [HOUR], [SINCE_SCREEN_ON], [WHILE_OFF]), then by
         * column ([AppState.NONE], [AppState.IN_USE], [AppState.NOTIFICATION], [AppState.BACKGROUND],
         * [AppState.NOT_YET], then the bytes in no state by why, [reasonColumn]), then up and down: 80
         * numbers.
         */
        val bytes: LongArray,
        val destinations: List<Destination>,
        /**
         * Whether it is the user's tool with its own servers not kept, as while "Log where these apps connect" is
         * off (ADR 0046, decision 3, as decided on 2026-11-19): the engine says so, the view does not guess it.
         */
        val serversHidden: Boolean = false,
        /** The WireGuard tunnel it went through with its destinations not kept, by Watch's number; 0 for none. */
        val throughTunnel: Long = 0,
    ) {
        fun up(window: Int, column: Int): Long = bytes[(window * COLUMNS + column) * 2]
        fun down(window: Int, column: Int): Long = bytes[(window * COLUMNS + column) * 2 + 1]

        override fun equals(other: Any?) = other is App && uid == other.uid && now == other.now &&
            isTool == other.isTool && throughTool == other.throughTool && bytes.contentEquals(other.bytes) &&
            destinations == other.destinations && serversHidden == other.serversHidden &&
            throughTunnel == other.throughTunnel

        override fun hashCode() =
            listOf(uid, now, isTool, throughTool, bytes.contentHashCode(), destinations, serversHidden, throughTunnel).hashCode()
    }

    /** A destination as W3 names it, with its bytes up and down in each window. */
    data class Destination(
        val protocol: Int,
        /** Where the name came from, as the log codes it (LogRecord.Segment.namedBy). */
        val namedBy: Int,
        val ech: Int,
        val dns: Int,
        val cameIn: Boolean,
        val address: InetAddress,
        val port: Int,
        val asn: Long,
        val network: Int,
        val name: String,
        /** The name a DNS answer gave the address, where it differs from [name]; empty otherwise. */
        val dnsName: String,
        val resolver: String,
        /** The organisation behind the address's network, where the organisation table names it. */
        val organisation: String,
        /** Up and down in the windows [TEN_MINUTES], [HOUR] and [SINCE_SCREEN_ON]: 6 numbers. */
        val bytes: List<Long>,
        /** Its route, as the log codes it (LogRecord.Segment.via), and for a tunnel its number. */
        val via: Int = org.visadahyu.datapavan.watch.log.LogRecord.VIA_DIRECT,
        val tunnel: Long = 0,
        /** The proxy it went through, read from the connection or inferred (version 4; ADR 0052); null for none. */
        val proxy: org.visadahyu.datapavan.watch.log.LogRecord.Proxy? = null,
    )

    companion object {
        const val VERSION: Byte = 4

        const val NOTHING_YET = 0
        const val STATES = 1
        const val NO_ACCESS = 2
        const val LOCKED = 3

        const val SCREEN_OFF = 0
        const val SCREEN_ON = 1
        const val SCREEN_UNKNOWN = 2

        const val TEN_MINUTES = 0
        const val HOUR = 1
        const val SINCE_SCREEN_ON = 2

        /** From the screen going off to its coming on again; it holds no destinations. */
        const val WHILE_OFF = 3
        const val WINDOWS = 4
        const val COLUMNS = 10

        /** Why bytes have no state, in the order of their columns after [AppState.NOT_YET]. */
        val REASONS = listOf(AppState.NO_ACCESS, AppState.LOCKED, AppState.LATE, AppState.NO_APP, AppState.NOT_TOLD)

        /** The column of the bytes in no state for [why], one of [REASONS]. */
        fun reasonColumn(why: Int): Int = AppState.NOT_YET + 1 + REASONS.indexOf(why).also { require(it >= 0) }

        /** The snapshot, or null for bytes that are not exactly one of this version, as when no engine runs. */
        fun parse(bytes: ByteArray): Snapshot? = try {
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            if (b.get() != VERSION) {
                null
            } else {
                val taken = b.long
                val known = b.get().toInt() and 0xff
                val toldUntil = b.long
                val screen = b.get().toInt() and 0xff
                val since = b.long
                val offFrom = b.long
                val offUntil = b.long
                val apps = List(count(b.int, b.remaining())) { app(b) }
                // One row per UID: a UID twice would be two rows with one key (review c1 of W5's third part,
                // screens, nit 10).
                require(apps.map { it.uid }.toSet().size == apps.size)
                // A window that came to an end has a start, and does not end before it.
                val off = offUntil == 0L || (offFrom != 0L && offUntil >= offFrom)
                Snapshot(taken, known, toldUntil, screen, since, offFrom, offUntil, apps).takeIf {
                    !b.hasRemaining() && known <= LOCKED && screen <= SCREEN_UNKNOWN && off
                }
            }
        } catch (e: java.nio.BufferUnderflowException) {
            null
        } catch (e: java.net.UnknownHostException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }

        /** A count read, refused where it says more than the bytes left could hold. */
        private fun count(count: Int, remaining: Int): Int {
            require(count in 0..remaining)
            return count
        }

        private fun app(b: ByteBuffer): App {
            val uid = b.int.takeIf { it != -1 }
            val now = b.get().toInt() and 0xff
            require(now == AppState.NOT_YET || AppState.isCode(now))
            val flags = b.get().toInt()
            val bytes = LongArray(WINDOWS * COLUMNS * 2) { b.long }
            // The bytes in no state by why add up to the column of no state, in each window and way.
            for (window in 0 until WINDOWS) {
                for (way in 0..1) {
                    val reasons = REASONS.sumOf { bytes[(window * COLUMNS + reasonColumn(it)) * 2 + way] }
                    require(reasons == bytes[(window * COLUMNS + AppState.NONE) * 2 + way])
                }
            }
            val destinations = List(count(b.short.toInt() and 0xffff, b.remaining())) { destination(b) }
            val throughTunnel = b.int.toLong() and 0xffffffffL
            return App(
                uid, now, flags and 1 != 0, flags and 2 != 0, bytes, destinations, serversHidden = flags and 4 != 0,
                throughTunnel = throughTunnel,
            )
        }

        private fun destination(b: ByteBuffer): Destination {
            val protocol = b.get().toInt() and 0xff
            val namedBy = b.get().toInt() and 0xff
            val ech = b.get().toInt() and 0xff
            val dns = b.get().toInt() and 0xff
            val flags = b.get().toInt()
            val address = InetAddress.getByAddress(ByteArray(b.get().toInt() and 0xff).also { b.get(it) })
            val port = b.short.toInt() and 0xffff
            val asn = b.int.toLong() and 0xffffffffL
            val network = b.get().toInt() and 0xff
            val name = text(b)
            val dnsName = text(b)
            val resolver = text(b)
            val organisation = text(b)
            val bytes = List(6) { b.long }
            val via = b.get().toInt() and 0xff
            val tunnel = b.int.toLong() and 0xffffffffL
            // A code the engine never writes, or a tunnel number beside no tunnel, is refused.
            require(via <= org.visadahyu.datapavan.watch.log.LogRecord.VIA_TUNNEL)
            require((via == org.visadahyu.datapavan.watch.log.LogRecord.VIA_TUNNEL) == (tunnel != 0L))
            val proxy = org.visadahyu.datapavan.watch.log.LogRecord.Proxy.read(b)
            return Destination(
                protocol, namedBy, ech, dns, flags and 1 != 0, address, port, asn, network,
                name, dnsName, resolver, organisation, bytes, via, tunnel, proxy,
            )
        }

        private fun text(b: ByteBuffer): String {
            val bytes = ByteArray(b.get().toInt() and 0xff).also { b.get(it) }
            return String(bytes, Charsets.UTF_8)
        }
    }
}
