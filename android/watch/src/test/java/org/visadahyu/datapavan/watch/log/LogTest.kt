package org.visadahyu.datapavan.watch.log

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class LogTest {
    /**
     * A segment of version 1, as debug builds on test phones wrote it before W5 (core/net/src/log.rs's
     * test `encodes_a_segment_field_by_field` then), byte for byte.
     */
    private val segment: ByteArray = ByteBuffer.allocate(200).order(ByteOrder.LITTLE_ENDIAN).apply {
        put(1).put(1).putLong(7).putInt(10_123)
        for (v in longArrayOf(1_000, 2_000, 300, 40_000, 820, 42_900)) putLong(v)
        put(byteArrayOf(6, 0, 3, 1, 0, 1, 4, 157.toByte(), 240.toByte(), 1, 35))
        putShort(443).putInt(32934).put(1)
        put(20).put("Meta Platforms, Inc.".toByteArray()).put(0)
    }.let { it.array().copyOf(it.position()) }

    /** The engine's own records (core/net), read as the engine wrote them. */
    @Test
    fun readsWhatTheEngineWrites() {
        val records = EngineRecords.records.map { it.first }
        assertEquals(11, records.size)
        val day = 1_794_873_600_000L
        fun at(hours: Int, minutes: Int) = day + (hours * 60L + minutes) * 60_000
        val tls = records[0] as LogRecord.Segment
        assertEquals(7L to 10_123, tls.flow to tls.uid)
        assertEquals(at(22, 10) to at(22, 15), tls.start to tls.end)
        assertEquals(listOf(300L, 40_000L, 820L, 42_900L), listOf(tls.up, tls.down, tls.wireUp, tls.wireDown))
        // TCP, opened, named by TLS, ECH offered, no DNS of its own.
        assertEquals(listOf(6, 0, 1, 1, 0), listOf(tls.protocol, tls.outcome, tls.namedBy, tls.ech, tls.dns))
        assertEquals(true to false, tls.continues to tls.cameIn)
        assertEquals("93.184.216.34" to 443, tls.address.hostAddress to tls.port)
        assertEquals(15_133L to 2, tls.asn to tls.network)
        assertEquals(listOf("other.example", "", "www.example.com"), listOf(tls.name, tls.resolver, tls.dnsName))

        val cameIn = records[1] as LogRecord.Segment
        assertEquals(8L to null, cameIn.flow to cameIn.uid)
        // UDP, unreachable, named by QUIC, the ECH public name hidden, encrypted DNS.
        assertEquals(listOf(17, 2, 2, 2, 2), listOf(cameIn.protocol, cameIn.outcome, cameIn.namedBy, cameIn.ech, cameIn.dns))
        assertEquals(false to true, cameIn.continues to cameIn.cameIn)
        assertEquals("2001:db8:0:0:0:0:0:53" to 853, cameIn.address.hostAddress to cameIn.port)
        assertEquals(listOf("quic.example", "sample", ""), listOf(cameIn.name, cameIn.resolver, cameIn.dnsName))

        val organisation = records[2] as LogRecord.Segment
        // Failed, named by the organisation table, plain DNS of its own, a network of an unlisted owner.
        assertEquals(listOf(3, 3, 0, 1), listOf(organisation.outcome, organisation.namedBy, organisation.ech, organisation.dns))
        assertEquals(29_084L to 3, organisation.asn to organisation.network)
        assertEquals("Société Générale" to "", organisation.name to organisation.dnsName)

        assertEquals(LogRecord.Lookups(10_123, at(22, 10), at(22, 15), 3, 210, 540), records[3])
        // The engine's cuts around Kathmandu's midnight: unnamed, opened, the bytes on each side.
        val (before, after) = records[4] as LogRecord.Segment to records[5] as LogRecord.Segment
        assertEquals(listOf(11L, 11L), listOf(before.flow, after.flow))
        assertEquals(listOf(at(18, 5), at(18, 15), at(18, 15), at(18, 25)), listOf(before.start, before.end, after.start, after.end))
        assertEquals(listOf(100L, 0L, 140L, 0L), listOf(before.up, before.down, before.wireUp, before.wireDown))
        assertEquals(listOf(0L, 200L, 0L, 240L), listOf(after.up, after.down, after.wireUp, after.wireDown))
        assertEquals(listOf(4, 4), listOf(before.namedBy, after.namedBy))
        assertEquals(true to false, before.continues to after.continues)
        assertEquals("" to "", before.name to after.dnsName)

        // The codes the others leave out: named by DNS, refused, a network of a known owner, both flags.
        val byDns = records[10] as LogRecord.Segment
        assertEquals(listOf(0, 1), listOf(byDns.namedBy, byDns.outcome))
        assertEquals(32_934L to 1, byDns.asn to byDns.network)
        assertEquals(true to true, byDns.continues to byDns.cameIn)
        assertEquals(listOf(1L, 2L, 3L, 4L), listOf(byDns.up, byDns.down, byDns.wireUp, byDns.wireDown))
        assertEquals("www.example.com" to "", byDns.name to byDns.dnsName)
    }

    /** No record, cut short anywhere or with any byte changed, makes the reader throw: it reads it or skips it. */
    @Test
    fun noRecordCrashesTheReader() {
        for ((_, bytes) in EngineRecords.records) {
            for (length in 0..bytes.size) LogRecord.parse(bytes.copyOf(length))
            for (at in bytes.indices) {
                for (value in listOf(0, 1, 2, 4, 16, 0x7f, 0x80, 0xff)) {
                    LogRecord.parse(bytes.copyOf().also { it[at] = value.toByte() })
                }
            }
        }
    }

    /** A record of a version this does not read is skipped and counted, and the batch read on; version 1 is read. */
    @Test
    fun skipsAndCountsARecordOfAnotherVersion() {
        val (_, engines) = EngineRecords.records[0]
        val newer = engines.copyOf().also { it[0] = 3 }
        val batch = ByteBuffer.allocate(4 + 3 * 2 + newer.size + segment.size + engines.size).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(3).putShort(newer.size.toShort()).put(newer).putShort(segment.size.toShort()).put(segment)
            .putShort(engines.size.toShort()).put(engines).array()
        var skipped = 0
        val records = LogRecord.batch(batch) { skipped++ }
        assertEquals(1, skipped)
        assertEquals(listOf(segment.toList(), engines.toList()), records.map { it.second.toList() })
        assertNull(LogRecord.parse(newer))
        assertNull(LogRecord.parse(engines.copyOf().also { it[0] = 0 }))
    }

    @Test
    fun readsAVersion1Segment() {
        val record = LogRecord.parse(segment) as LogRecord.Segment
        assertEquals(7L, record.flow)
        assertEquals(10_123, record.uid)
        assertEquals(1_000L to 2_000L, record.start to record.end)
        assertEquals(300L to 40_000L, record.up to record.down)
        assertEquals(820L to 42_900L, record.wireUp to record.wireDown)
        assertEquals(listOf(6, 0, 3, 1, 0), listOf(record.protocol, record.outcome, record.namedBy, record.ech, record.dns))
        assertEquals(true, record.continues)
        assertEquals("157.240.1.35", record.address.hostAddress)
        assertEquals(443, record.port)
        assertEquals(32934L to 1, record.asn to record.network)
        assertEquals("Meta Platforms, Inc.", record.name)
        assertEquals("", record.resolver)
        assertEquals("" to false, record.dnsName to record.cameIn)
    }

    @Test
    fun readsABatchAndStopsAtWhatIsCutShort() {
        val lookups = ByteBuffer.allocate(42).order(ByteOrder.LITTLE_ENDIAN)
            .put(1).put(2).putInt(-1).putLong(5).putLong(6).putInt(3).putLong(210).putLong(540).array()
        val batch = ByteBuffer.allocate(4 + 2 + segment.size + 2 + lookups.size).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(2).putShort(segment.size.toShort()).put(segment).putShort(lookups.size.toShort()).put(lookups).array()
        val records = LogRecord.batch(batch)
        assertEquals(2, records.size)
        assertEquals(LogRecord.Lookups(null, 5, 6, 3, 210, 540), records[1].first)
        assertArrayEquals(segment, records[0].second)
        // Cut short: what came before is read, and the rest counted once as skipped.
        var skipped = 0
        assertEquals(1, LogRecord.batch(batch.copyOf(batch.size - 3)) { skipped++ }.size)
        assertEquals(1, skipped)
        assertEquals(0, LogRecord.batch(batch.copyOf(3)) { skipped++ }.size)
        assertEquals(2, skipped)
        assertEquals(2, LogRecord.batch(batch) { skipped++ }.size)
        assertEquals(2, skipped)
        assertNull(LogRecord.parse(segment.copyOf(30)))
        assertNull(LogRecord.parse(byteArrayOf(2, 1)))
    }

    @Test
    fun sealsSoThatOnlyTheSameKeyDayAndAppOpen() {
        val key = Sealer.newDayKey()
        val sealer = Sealer(key, day = 20_400, keyId = 1)
        val app = sealer.token(10_123)
        assertArrayEquals(app, Sealer(key, 20_400, 1).token(10_123))
        assertNotEquals(app.toList(), sealer.token(10_456).toList())
        assertNotEquals(app.toList(), Sealer(Sealer.newDayKey(), 20_400, 1).token(10_123).toList())

        val sealed = sealer.seal(segment, app)
        assertNotEquals(sealed.toList(), sealer.seal(segment, app).toList())
        assertArrayEquals(segment, sealer.open(sealed, app))
        assertNull("another app's token", sealer.open(sealed, sealer.token(10_456)))
        assertNull("another day", Sealer(key, 20_401, 1).open(sealed, app))
        assertNull("another key row", Sealer(key, 20_400, 2).open(sealed, app))
        assertNull("another key", Sealer(Sealer.newDayKey(), 20_400, 1).open(sealed, app))
        val tampered = sealed.copyOf().also { it[20] = (it[20] + 1).toByte() }
        assertNull("changed", sealer.open(tampered, app))
        // Nothing of the record shows in what is stored.
        val text = String(sealed, Charsets.ISO_8859_1)
        assertEquals(-1, text.indexOf("Meta"))
    }
}
