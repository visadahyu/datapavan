package org.visadahyu.datapavan.watch.log

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class LogTest {
    /** The segment of core/net/src/log.rs's test `encodes_a_segment_field_by_field`, byte for byte. */
    private val segment: ByteArray = ByteBuffer.allocate(200).order(ByteOrder.LITTLE_ENDIAN).apply {
        put(1).put(1).putLong(7).putInt(10_123)
        for (v in longArrayOf(1_000, 2_000, 300, 40_000)) putLong(v)
        put(byteArrayOf(6, 0, 3, 1, 0, 1, 4, 157.toByte(), 240.toByte(), 1, 35))
        putShort(443).putInt(32934).put(1)
        put(20).put("Meta Platforms, Inc.".toByteArray()).put(0)
    }.let { it.array().copyOf(it.position()) }

    @Test
    fun readsTheEnginesSegment() {
        val record = LogRecord.parse(segment) as LogRecord.Segment
        assertEquals(7L, record.flow)
        assertEquals(10_123, record.uid)
        assertEquals(1_000L to 2_000L, record.start to record.end)
        assertEquals(300L to 40_000L, record.up to record.down)
        assertEquals(listOf(6, 0, 3, 1, 0), listOf(record.protocol, record.outcome, record.namedBy, record.ech, record.dns))
        assertEquals(true, record.continues)
        assertEquals("157.240.1.35", record.address.hostAddress)
        assertEquals(443, record.port)
        assertEquals(32934L to 1, record.asn to record.network)
        assertEquals("Meta Platforms, Inc.", record.name)
        assertEquals("", record.resolver)
    }

    @Test
    fun readsABatchAndStopsAtWhatIsCutShort() {
        val lookups = ByteBuffer.allocate(26).order(ByteOrder.LITTLE_ENDIAN)
            .put(1).put(2).putInt(-1).putLong(5).putLong(6).putInt(3).array()
        val batch = ByteBuffer.allocate(4 + 2 + segment.size + 2 + lookups.size).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(2).putShort(segment.size.toShort()).put(segment).putShort(lookups.size.toShort()).put(lookups).array()
        val records = LogRecord.batch(batch)
        assertEquals(2, records.size)
        assertEquals(LogRecord.Lookups(null, 5, 6, 3), records[1].first)
        assertArrayEquals(segment, records[0].second)
        assertEquals(1, LogRecord.batch(batch.copyOf(batch.size - 3)).size)
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
