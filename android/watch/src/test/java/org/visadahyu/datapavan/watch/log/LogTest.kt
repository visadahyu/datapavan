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
        assertEquals(16, records.size)
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
        assertEquals(AppState.IN_USE, tls.state)

        val cameIn = records[1] as LogRecord.Segment
        assertEquals(8L to null, cameIn.flow to cameIn.uid)
        // UDP, unreachable, named by QUIC, the ECH public name hidden, encrypted DNS.
        assertEquals(listOf(17, 2, 2, 2, 2), listOf(cameIn.protocol, cameIn.outcome, cameIn.namedBy, cameIn.ech, cameIn.dns))
        assertEquals(false to true, cameIn.continues to cameIn.cameIn)
        assertEquals("2001:db8:0:0:0:0:0:53" to 853, cameIn.address.hostAddress to cameIn.port)
        assertEquals(listOf("quic.example", "sample", ""), listOf(cameIn.name, cameIn.resolver, cameIn.dnsName))
        assertEquals(AppState.NO_APP, cameIn.state)
        assertEquals(AppState.NONE to AppState.NO_APP, AppState.of(cameIn.state) to AppState.why(cameIn.state))

        val organisation = records[2] as LogRecord.Segment
        // Failed, named by the organisation table, plain DNS of its own, a network of an unlisted owner.
        assertEquals(listOf(3, 3, 0, 1), listOf(organisation.outcome, organisation.namedBy, organisation.ech, organisation.dns))
        assertEquals(29_084L to 3, organisation.asn to organisation.network)
        assertEquals("Société Générale" to "", organisation.name to organisation.dnsName)
        assertEquals(AppState.BACKGROUND, organisation.state)

        assertEquals(LogRecord.Lookups(10_123, at(22, 10), at(22, 15), 3, 210, 540, AppState.NOTIFICATION), records[3])
        // The engine's cuts around Kathmandu's midnight: unnamed, opened, the bytes on each side.
        val (before, after) = records[4] as LogRecord.Segment to records[5] as LogRecord.Segment
        assertEquals(listOf(11L, 11L), listOf(before.flow, after.flow))
        assertEquals(listOf(at(18, 5), at(18, 15), at(18, 15), at(18, 25)), listOf(before.start, before.end, after.start, after.end))
        assertEquals(listOf(100L, 0L, 140L, 0L), listOf(before.up, before.down, before.wireUp, before.wireDown))
        assertEquals(listOf(0L, 200L, 0L, 240L), listOf(after.up, after.down, after.wireUp, after.wireDown))
        assertEquals(listOf(4, 4), listOf(before.namedBy, after.namedBy))
        assertEquals(true to false, before.continues to after.continues)
        assertEquals("" to "", before.name to after.dnsName)
        // The engine's own cuts, by a platform that tells no states.
        assertEquals(listOf(AppState.NOT_TOLD, AppState.NOT_TOLD), listOf(before.state, after.state))

        // The codes the others leave out: named by DNS, refused, a network of a known owner, both flags.
        val byDns = records[10] as LogRecord.Segment
        assertEquals(listOf(0, 1), listOf(byDns.namedBy, byDns.outcome))
        assertEquals(32_934L to 1, byDns.asn to byDns.network)
        assertEquals(true to true, byDns.continues to byDns.cameIn)
        assertEquals(listOf(1L, 2L, 3L, 4L), listOf(byDns.up, byDns.down, byDns.wireUp, byDns.wireDown))
        assertEquals("www.example.com" to "", byDns.name to byDns.dnsName)
        assertEquals(AppState.LATE, byDns.state)
        // Version 4: through the WireGuard tunnel numbered 7; the others went directly.
        assertEquals(LogRecord.VIA_TUNNEL to 7L, byDns.via to byDns.tunnel)
        assertEquals(LogRecord.VIA_DIRECT to 0L, before.via to before.tunnel)
        assertEquals(listOf("in-use", "none-late"), listOf(AppState.name(tls.state), AppState.name(byDns.state)))
        // Version 5: no proxy on any of these.
        assertEquals(List(11) { null }, records.take(11).map { (it as? LogRecord.Segment)?.proxy })
        // Version 6: none blocked, and no blocking row's SDK on any segment.
        val segments = records.filterIsInstance<LogRecord.Segment>()
        assertEquals(List(segments.size) { false to "" }, segments.map { it.blocked to it.blockedSdk })
    }

    /**
     * Version 6's addition (W8, part 3a; ADR 0053), as the engine's own test `encodes_a_blocked_flow_and_its_rows_sdk_last`
     * writes it: the outcome 4 of a flow tracker blocking refused, and the SDK of the row that blocked it last, a length
     * byte and UTF-8.
     */
    @Test
    fun readsABlockedFlowAndItsRowsSdk() {
        val (_, engines) = EngineRecords.records[0]
        val sdk = "com.google.firebase:firebase-analytics".toByteArray()
        // Version, kind, number, UID, six counts, protocol: then the outcome.
        val outcome = 1 + 1 + 8 + 4 + 6 * 8 + 1
        val blocked = engines.copyOf(engines.size - 1).also { it[outcome] = LogRecord.OUTCOME_BLOCKED.toByte() } +
            byteArrayOf(sdk.size.toByte()) + sdk
        val record = LogRecord.parse(blocked) as LogRecord.Segment
        assertEquals(true to "com.google.firebase:firebase-analytics", record.blocked to record.blockedSdk)
        assertEquals("other.example" to null, record.name to record.proxy)
        assertNull("an SDK cut short", LogRecord.parse(blocked.copyOf(blocked.size - 1)))
        assertNull("a byte after it", LogRecord.parse(blocked + 0))
    }

    /** A version 5 segment, as W8 part 2a wrote it: the engine's, without the blocking row's SDK, which reads as none. */
    @Test
    fun readsAVersion5SegmentWithNoBlockingRow() {
        val (_, plain) = EngineRecords.records[10]
        val version5 = plain.copyOf(plain.size - 1).also { it[0] = 5 }
        val record = LogRecord.parse(version5) as LogRecord.Segment
        assertEquals(false to "", record.blocked to record.blockedSdk)
        assertEquals(LogRecord.VIA_TUNNEL to null, record.via to record.proxy)
        val (_, hidden) = EngineRecords.records[14]
        val proxied = LogRecord.parse(hidden.copyOf(hidden.size - 1).also { it[0] = 5 }) as LogRecord.Segment
        assertEquals(listOf(49, 312), proxied.proxy?.trackers)
    }

    /**
     * Version 5's proxies (ADR 0052), as the engine writes them: declared, inferred, with the destination left out and
     * its trackers' marks kept, and a plain request that keeps its own name.
     */
    @Test
    fun readsTheProxiesTheEngineWrites() {
        val records = EngineRecords.records.map { it.first }.filterIsInstance<LogRecord.Segment>().takeLast(5)
        val socks5 = records[0]
        assertEquals("example.org" to 5, socks5.name to socks5.namedBy)
        assertEquals("203.0.113.5" to 1080, socks5.address.hostAddress to socks5.port)
        assertEquals(24_940L to 3, socks5.asn to socks5.network)
        assertEquals(
            LogRecord.Proxy(
                LogRecord.PROXY_SOCKS5, setting = true, password = true, asked = "example.org", askedPort = 443,
                proxyName = "proxy.example.net", organisation = "Hetzner Online GmbH",
            ),
            socks5.proxy,
        )
        assertEquals(true to true, socks5.proxy?.declared to socks5.proxy?.kept)
        val connect = records[1]
        assertEquals(LogRecord.Proxy(LogRecord.PROXY_CONNECT, asked = "2001:db8:0:0:0:0:0:7", askedPort = 8443), connect.proxy)
        assertEquals("" to 4, connect.name to connect.namedBy)
        val mtproto = records[2]
        assertEquals(
            LogRecord.Proxy(LogRecord.PROXY_MTPROTO, outsideMaker = true, organisation = "Hetzner Online GmbH", cover = "www.google.com"),
            mtproto.proxy,
        )
        assertEquals(false, mtproto.proxy?.declared)
        // Its destination left out: the kind alone, at an address of zeros, and no name; its trackers' marks stay.
        val hidden = records[3]
        assertEquals(LogRecord.Proxy(LogRecord.PROXY_SOCKS4, leftOut = true, trackers = listOf(49, 312)), hidden.proxy)
        assertEquals(true to "", hidden.address.isAnyLocalAddress to hidden.name)
        assertEquals(false, hidden.proxy?.kept)
        // A plain request: its own name and address, with what it asked for left out, and not left out itself.
        val forward = records[4]
        assertEquals(LogRecord.Proxy(LogRecord.PROXY_FORWARD, password = true), forward.proxy)
        assertEquals("cache.example.net" to "198.51.100.7", forward.name to forward.address.hostAddress)
        assertEquals(true, forward.proxy?.kept)
    }

    /** A version 4 segment reads with no proxy; a proxy's kind or flag the engine never writes is malformed. */
    @Test
    fun readsAVersion4SegmentWithoutAProxyAndRefusesAProxyTheEngineNeverWrites() {
        val (_, plain) = EngineRecords.records[10]
        val version4 = plain.copyOf(plain.size - 2).also { it[0] = 4 }
        assertNull((LogRecord.parse(version4) as LogRecord.Segment).proxy)
        assertEquals(LogRecord.VIA_TUNNEL, (LogRecord.parse(version4) as LogRecord.Segment).via)
        val (_, hidden) = EngineRecords.records[14]
        // The proxy's kind, flags, three empty texts, and two trackers' marks; then no blocking row's SDK.
        val kind = hidden.size - 16
        assertEquals(LogRecord.PROXY_SOCKS4, (LogRecord.parse(hidden) as LogRecord.Segment).proxy?.kind)
        for (code in listOf(8, 0x80, 0xff)) {
            assertNull("no such proxy: $code", LogRecord.parse(hidden.copyOf().also { it[kind] = code.toByte() }))
        }
        assertNull("a flag the engine never writes", LogRecord.parse(hidden.copyOf().also { it[kind + 1] = 0x20 }))
        assertNull("a destination that does not follow", LogRecord.parse(hidden.copyOf().also { it[kind + 1] = 0x18 }))
        assertNull("more trackers than the engine writes", LogRecord.parse(hidden.copyOf().also { it[kind + 5] = 9 }))
    }

    /** Version 3's state is the record's last byte: a code the engine never writes, or a byte after it, is malformed. */
    @Test
    fun refusesAStateTheEngineNeverWritesAndBytesAfterIt() {
        val (_, engines) = EngineRecords.records[3]
        assertEquals(AppState.NOTIFICATION, LogRecord.parse(engines)?.state)
        for (code in listOf(0, 4, 5, 0x11, 0x60, 0xff)) {
            assertNull("code $code", LogRecord.parse(engines.copyOf().also { it[it.size - 1] = code.toByte() }))
        }
        for (code in listOf(1, 2, 3, 0x10, 0x20, 0x30, 0x40, 0x50)) {
            assertEquals(code, LogRecord.parse(engines.copyOf().also { it[it.size - 1] = code.toByte() })?.state)
        }
        assertNull(LogRecord.parse(engines + 0))
        assertNull(LogRecord.parse(engines.copyOf(engines.size - 1)))
    }

    /** A version 2 record, as debug builds wrote them in W5's first part: the engine's, without the state or the route. */
    @Test
    fun readsAVersion2RecordAsNotTold() {
        val (_, engines) = EngineRecords.records[0]
        val version2 = engines.copyOf(engines.size - 8).also { it[0] = 2 }
        val record = LogRecord.parse(version2) as LogRecord.Segment
        assertEquals("other.example" to "www.example.com", record.name to record.dnsName)
        assertEquals(AppState.NOT_TOLD, record.state)
    }

    /**
     * A version 3 segment, as debug builds wrote them before W7: the engine's, without the route, which reads as
     * unknown; and version 4's route refused where it says what the engine never writes.
     */
    @Test
    fun readsAVersion3SegmentsRouteAsUnknownAndRefusesARouteTheEngineNeverWrites() {
        val (_, engines) = EngineRecords.records[10]
        val version3 = engines.copyOf(engines.size - 7).also { it[0] = 3 }
        val record = LogRecord.parse(version3) as LogRecord.Segment
        assertEquals(AppState.LATE to LogRecord.VIA_UNKNOWN, record.state to record.via)
        val route = engines.size - 7
        for (code in listOf(3, 0x80, 0xff)) {
            assertNull("no such route: $code", LogRecord.parse(engines.copyOf().also { it[route] = code.toByte() }))
        }
        assertNull("a tunnel of no number", LogRecord.parse(engines.copyOf().also { it.fill(0, route + 1, route + 5) }))
        assertNull("a number beside no tunnel", LogRecord.parse(engines.copyOf().also { it[route] = 0 }))
        assertEquals(LogRecord.VIA_TOOL, (LogRecord.parse(engines.copyOf().also { it[route] = 1; it.fill(0, route + 1, route + 5) }) as LogRecord.Segment).via)
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
        val newer = engines.copyOf().also { it[0] = 7 }
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
        assertEquals(AppState.NOT_TOLD, record.state)
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
