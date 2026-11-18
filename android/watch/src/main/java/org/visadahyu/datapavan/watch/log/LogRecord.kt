package org.visadahyu.datapavan.watch.log

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * One record of the connection log, as the engine writes it (core/net/src/log.rs, version 2). The
 * bytes are kept as they are, sealed; this reads them back, and reads version 1 too, which no release
 * wrote but debug builds on test phones did, as ADR 0044's decision 4 asked: a day sealed then stays
 * readable until it expires. A record of another version is skipped and counted, never read as this one.
 */
sealed interface LogRecord {
    /** The app's UID, or null when Android did not name it. */
    val uid: Int?

    /** Start and end, in milliseconds since 1970 (UTC). */
    val start: Long
    val end: Long

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
    ) : LogRecord

    /** Lookups the app sent to Watch's own DNS address, and their packets' bytes on the tunnel. */
    data class Lookups(
        override val uid: Int?,
        override val start: Long,
        override val end: Long,
        val count: Long,
        val wireUp: Long,
        val wireDown: Long,
    ) : LogRecord

    companion object {
        /** The version the engine writes. */
        const val VERSION: Byte = 2
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

        /** One record in its stored form, or null if it is not one this reads: of another version, or malformed. */
        fun parse(bytes: ByteArray): LogRecord? = try {
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val version = b.get()
            if (version != VERSION && version != VERSION_1) {
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
                        )
                    }
                    2 -> Lookups(
                        b.int.takeIf { it != UNKNOWN_UID }, b.long, b.long, b.int.toLong() and 0xffffffffL, b.long, b.long,
                    )
                    else -> null
                }
            }
        } catch (e: java.nio.BufferUnderflowException) {
            null
        } catch (e: java.net.UnknownHostException) {
            null
        }

        /** The version before the DNS name and the flag of a flow that came in. */
        private const val VERSION_1: Byte = 1

        private fun text(b: ByteBuffer): String {
            val bytes = ByteArray(b.get().toInt() and 0xff).also { b.get(it) }
            return String(bytes, Charsets.UTF_8)
        }
    }
}
