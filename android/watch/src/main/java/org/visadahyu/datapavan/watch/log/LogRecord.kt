package org.visadahyu.datapavan.watch.log

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * One record of the connection log, as the engine writes it (core/net/src/log.rs, version 5). The
 * bytes are kept as they are, sealed; this reads them back, and reads versions 1 to 4 too, which debug
 * builds on test phones wrote (version 4 was also W7's), as ADR 0044's decision 4 asked: a day sealed then
 * stays readable until it expires. A record of another version is skipped and counted, never read as
 * this one.
 */
sealed interface LogRecord {
    /** The app's UID, or null when Android did not name it. */
    val uid: Int?

    /** Start and end, in milliseconds since 1970 (UTC). */
    val start: Long
    val end: Long

    /**
     * The state of the app over the record (ADR 0046, decision 1), as one byte ([AppState]): in use, with
     * its notification, in the background, or none and why. It is the state of the seconds its bytes were
     * counted in, a second with a moment of use being in use whole, or for a part with no bytes the state of
     * its end; quiet seconds of another state beyond the 120 that a cut walks back are not cut out (ADR 0037's
     * note). Records of versions 1 and 2, written before Watch told states, have none: "not told".
     */
    val state: Int

    /** A flow, or the part of it from [start] to [end]. */
    data class Segment(
        val flow: Long,
        override val uid: Int?,
        override val start: Long,
        override val end: Long,
        val up: Long,
        val down: Long,
        /** The IP packets' bytes on the tunnel, headers included: what Android counts for the app. */
        val wireUp: Long,
        val wireDown: Long,
        val protocol: Int,
        val outcome: Int,
        val namedBy: Int,
        val ech: Int,
        val dns: Int,
        val continues: Boolean,
        /** Whether the flow came in: datagrams from another port of an address the app had sent to (version 2). */
        val cameIn: Boolean,
        val address: InetAddress,
        val port: Int,
        val asn: Long,
        val network: Int,
        val name: String,
        val resolver: String,
        /**
         * The name a DNS answer gave the address, where the connection's own name, which is [name], differs
         * from it (version 2; finding 20 of the independent review of 2026-11-09); empty otherwise.
         */
        val dnsName: String,
        override val state: Int = AppState.NOT_TOLD,
        /**
         * Its route (version 4, W7): [VIA_DIRECT], [VIA_TOOL] or [VIA_TUNNEL], and for a tunnel its number,
         * which Watch gave the configuration; records before version 4, which went directly or through the
         * tool, say [VIA_UNKNOWN].
         */
        val via: Int = VIA_DIRECT,
        val tunnel: Long = 0,
        /** The proxy it went through, read from the connection or inferred (version 5; W8, part 2a, ADR 0052). */
        val proxy: Proxy? = null,
    ) : LogRecord

    /**
     * A flow's proxy, as the engine writes it (core/net/src/log.rs, `push_proxy`): its [kind], whether Android's
     * proxy [setting] names it, whether a [password] for it crossed the network unencrypted (never the password,
     * which the engine never keeps), whether its address is [outsideMaker]'s network, the destination [asked] for
     * and its port where it was declared and kept, the proxy's own name, the organisation behind its network, and
     * the [cover] name an inferred proxy's hello sent, which names nothing. Empty texts and a port of -1 for none.
     */
    data class Proxy(
        val kind: Int,
        val setting: Boolean = false,
        val password: Boolean = false,
        val outsideMaker: Boolean = false,
        val asked: String = "",
        val askedPort: Int = -1,
        val proxyName: String = "",
        val organisation: String = "",
        val cover: String = "",
    ) {
        /** Whether it was read from the connection: SOCKS or an HTTP proxy; else inferred. */
        val declared: Boolean get() = kind <= PROXY_FORWARD

        /** Whether where it went was kept ("Log where these apps connect" on). */
        val kept: Boolean get() = askedPort >= 0 || proxyName.isNotEmpty() || organisation.isNotEmpty() || cover.isNotEmpty()

        companion object {
            /**
             * A proxy as the engine writes it, or null for its code 0, none; a code or flag it never writes throws
             * [IllegalArgumentException], and the record is read as malformed.
             */
            fun read(b: ByteBuffer): Proxy? {
                val kind = b.get().toInt() and 0xff
                if (kind == 0) return null
                require(kind in PROXY_SOCKS5..PROXY_SIGNAL)
                val flags = b.get().toInt() and 0xff
                require(flags and 0xf0 == 0)
                var asked = ""
                var port = -1
                if (flags and 8 != 0) {
                    val length = b.get().toInt() and 0xff
                    require(length == 0 || length == 4 || length == 16)
                    val address = ByteArray(length).also { b.get(it) }
                    val name = text(b)
                    require((length == 0) != name.isEmpty())
                    asked = if (length == 0) name else InetAddress.getByAddress(address).hostAddress.orEmpty()
                    port = b.short.toInt() and 0xffff
                }
                return Proxy(
                    kind, setting = flags and 1 != 0, password = flags and 2 != 0, outsideMaker = flags and 4 != 0,
                    asked = asked, askedPort = port, proxyName = text(b), organisation = text(b), cover = text(b),
                )
            }

            private fun text(b: ByteBuffer): String {
                val bytes = ByteArray(b.get().toInt() and 0xff).also { b.get(it) }
                return String(bytes, Charsets.UTF_8)
            }
        }
    }

    /** Lookups the app sent to Watch's own DNS address, and their packets' bytes on the tunnel. */
    data class Lookups(
        override val uid: Int?,
        override val start: Long,
        override val end: Long,
        val count: Long,
        val wireUp: Long,
        val wireDown: Long,
        override val state: Int = AppState.NOT_TOLD,
    ) : LogRecord

    companion object {
        /** The version the engine writes. */
        const val VERSION: Byte = 5

        /** A proxy's kind (version 5): SOCKS5, SOCKS4, an HTTP `CONNECT`, a plain request to an HTTP proxy, and inferred, Telegram's MTProto, WhatsApp's and Signal's. */
        const val PROXY_SOCKS5 = 1
        const val PROXY_SOCKS4 = 2
        const val PROXY_CONNECT = 3
        const val PROXY_FORWARD = 4
        const val PROXY_MTPROTO = 5
        const val PROXY_WHATSAPP = 6
        const val PROXY_SIGNAL = 7

        /** A segment's route (version 4). */
        const val VIA_DIRECT = 0
        const val VIA_TOOL = 1
        const val VIA_TUNNEL = 2

        /** A segment of a version before 4, which kept no route. */
        const val VIA_UNKNOWN = -1
        private const val UNKNOWN_UID = -1

        /**
         * The records of a batch, each with its bytes; a batch that does not parse gives what came before.
         * [skipped] is called for each record that is not one this reads: of another version, or malformed;
         * and once for the rest of a batch cut short, whose count, from the engine of this process, says
         * nothing to trust.
         */
        fun batch(bytes: ByteArray, skipped: () -> Unit = {}): List<Pair<LogRecord, ByteArray>> {
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val records = mutableListOf<Pair<LogRecord, ByteArray>>()
            if (buffer.remaining() < 4) return records.also { if (bytes.isNotEmpty()) skipped() }
            repeat(buffer.int.coerceAtLeast(0)) {
                if (buffer.remaining() < 2) return records.also { skipped() }
                val length = buffer.short.toInt() and 0xffff
                if (buffer.remaining() < length) return records.also { skipped() }
                val record = ByteArray(length).also { buffer.get(it) }
                val read = parse(record)
                if (read == null) skipped() else records += read to record
            }
            return records
        }

        /**
         * One record in its stored form, or null if it is not one this reads: of another version, or malformed,
         * bytes left over after it included.
         */
        fun parse(bytes: ByteArray): LogRecord? = try {
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val version = b.get()
            if (version != VERSION && version != VERSION_4 && version != VERSION_3 && version != VERSION_2 && version != VERSION_1) {
                null
            } else {
                when (b.get().toInt()) {
                    1 -> {
                        val flow = b.long
                        val uid = b.int
                        val start = b.long
                        val end = b.long
                        val up = b.long
                        val down = b.long
                        val wireUp = b.long
                        val wireDown = b.long
                        val fields = IntArray(6) { b.get().toInt() and 0xff }
                        val address = ByteArray(b.get().toInt() and 0xff).also { b.get(it) }
                        val port = b.short.toInt() and 0xffff
                        val asn = b.int.toLong() and 0xffffffffL
                        val network = b.get().toInt() and 0xff
                        Segment(
                            flow, uid.takeIf { it != UNKNOWN_UID }, start, end, up, down, wireUp, wireDown,
                            protocol = fields[0], outcome = fields[1], namedBy = fields[2], ech = fields[3],
                            dns = fields[4], continues = fields[5] and 1 != 0, cameIn = fields[5] and 2 != 0,
                            address = InetAddress.getByAddress(address), port = port, asn = asn, network = network,
                            name = text(b), resolver = text(b), dnsName = if (version == VERSION_1) "" else text(b),
                            state = state(b, version),
                        ).let { segment ->
                            if (version < VERSION_4) {
                                segment.copy(via = VIA_UNKNOWN)
                            } else {
                                val via = b.get().toInt() and 0xff
                                val tunnel = b.int.toLong() and 0xffffffffL
                                // A code the engine never writes, or a tunnel number beside no tunnel, is malformed.
                                if (via > VIA_TUNNEL || (via == VIA_TUNNEL) != (tunnel != 0L)) {
                                    null
                                } else {
                                    segment.copy(via = via, tunnel = tunnel, proxy = if (version >= VERSION) Proxy.read(b) else null)
                                }
                            }
                        }
                    }
                    2 -> Lookups(
                        b.int.takeIf { it != UNKNOWN_UID }, b.long, b.long, b.int.toLong() and 0xffffffffL, b.long, b.long,
                        state = state(b, version),
                    )
                    else -> null
                }?.takeIf { it.state >= 0 && !b.hasRemaining() }
            }
        } catch (e: java.nio.BufferUnderflowException) {
            null
        } catch (e: java.net.UnknownHostException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }

        /** The version before the DNS name and the flag of a flow that came in. */
        private const val VERSION_1: Byte = 1

        /** The version before the app's state. */
        private const val VERSION_2: Byte = 2

        /** The version before a segment's route. */
        private const val VERSION_3: Byte = 3

        /** The version before a segment's proxy. */
        private const val VERSION_4: Byte = 4

        /**
         * The app's state, one byte after the segment's counts from version 3 ("not told" before); in a
         * version-4 segment the route's five bytes follow it. A code the engine never writes gives -1, and the
         * record is read as malformed.
         */
        private fun state(b: ByteBuffer, version: Byte): Int {
            if (version < VERSION_3) return AppState.NOT_TOLD
            return (b.get().toInt() and 0xff).takeIf(AppState::isCode) ?: -1
        }

        private fun text(b: ByteBuffer): String {
            val bytes = ByteArray(b.get().toInt() and 0xff).also { b.get(it) }
            return String(bytes, Charsets.UTF_8)
        }
    }
}

/**
 * An app's state as the engine places it, one byte (core/net/src/states.rs, `Placed::code`): the low four
 * bits the state, the high four why there is none. The same byte in the log's records and the live
 * view's snapshot.
 */
object AppState {
    const val NONE = 0
    const val IN_USE = 1
    const val NOTIFICATION = 2
    const val BACKGROUND = 3

    /** Only in the live view: a second its state was not told for yet, which may still come. */
    const val NOT_YET = 4

    /** Why there is none: Watch has no usage access. */
    const val NO_ACCESS = 0x10

    /** Android gave no usage events, as before the first unlock after a restart. */
    const val LOCKED = 0x20

    /** Its state was not told while the engine kept the second. */
    const val LATE = 0x30

    /** Android did not name the flow's app. */
    const val NO_APP = 0x40

    /** Nothing was told for it: before Watch's first reading, in a gap a clock set back left, or when Watch stopped first. */
    const val NOT_TOLD = 0x50

    /** The state of a code: [NONE], [IN_USE], [NOTIFICATION], [BACKGROUND] or [NOT_YET]. */
    fun of(code: Int): Int = code and 0x0f

    /** Why a code has no state: one of the codes above from [NO_ACCESS] to [NOT_TOLD], or 0 for one that has. */
    fun why(code: Int): Int = code and 0xf0

    /** Whether the engine writes this code. */
    fun isCode(code: Int): Boolean = code in IN_USE..BACKGROUND || code in setOf(NO_ACCESS, LOCKED, LATE, NO_APP, NOT_TOLD)

    /** The code as `log-today` and the dump print it. */
    fun name(code: Int): String = when (code) {
        IN_USE -> "in-use"
        NOTIFICATION -> "notification"
        BACKGROUND -> "background"
        NOT_YET -> "not-yet"
        NO_ACCESS -> "none-no-access"
        LOCKED -> "none-locked"
        LATE -> "none-late"
        NO_APP -> "none-no-app"
        NOT_TOLD -> "none-not-told"
        else -> "none"
    }
}
