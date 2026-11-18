package org.visadahyu.datapavan.watch.activity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.visadahyu.datapavan.watch.log.AppState

class SnapshotTest {
    /**
     * The snapshot the engine itself wrote for this test (`snapshot.hex`, beside this class among the test
     * resources): its Rust test `the_kotlin_sides_snapshot_fixture_is_what_the_engine_writes` fails when the
     * engine writes otherwise, so that the reader here and the writer there cannot drift apart unseen.
     */
    private val fixture: ByteArray by lazy {
        val text = checkNotNull(SnapshotTest::class.java.getResource("snapshot.hex")) { "snapshot.hex is missing" }.readText()
        val hex = text.lineSequence().filterNot { it.startsWith("#") }.joinToString("") { it.trim() }
        ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    /** 2026-11-17, 22:10 UTC, the engine's test's start. */
    private val t = 1_794_953_400_000L

    @Test
    fun readsWhatTheEngineWrites() {
        val snapshot = checkNotNull(Snapshot.parse(fixture)) { "the engine's snapshot is not read" }
        assertEquals(t + 4_000, snapshot.taken)
        // The last reading had no usage access; the screen is off, and last came on a second in.
        assertEquals(Snapshot.NO_ACCESS to t + 3_000, snapshot.known to snapshot.toldUntil)
        assertEquals(Snapshot.SCREEN_OFF to t + 1_000, snapshot.screen to snapshot.screenOnSince)
        assertEquals(listOf(null, 10_123), snapshot.apps.map { it.uid })

        val noApp = snapshot.apps[0]
        assertEquals(AppState.NO_APP, noApp.now)
        assertEquals(50L to 0L, noApp.up(Snapshot.TEN_MINUTES, AppState.NONE) to noApp.down(Snapshot.TEN_MINUTES, AppState.NONE))
        // Counted three and a half seconds in, after the screen came on.
        assertEquals(50L, noApp.up(Snapshot.SINCE_SCREEN_ON, AppState.NONE))
        val encrypted = noApp.destinations.single()
        assertEquals(listOf(17, 1, 1, 2), listOf(encrypted.protocol, encrypted.namedBy, encrypted.ech, encrypted.dns))
        assertEquals(true, encrypted.cameIn)
        assertEquals("192.0.2.7" to 853, encrypted.address.hostAddress to encrypted.port)
        assertEquals(listOf("dns.example", "other.example", "sample", ""), listOf(encrypted.name, encrypted.dnsName, encrypted.resolver, encrypted.organisation))
        assertEquals(listOf(50L, 0L, 50L, 0L, 50L, 0L), encrypted.bytes)

        val app = snapshot.apps[1]
        assertEquals(AppState.BACKGROUND, app.now)
        assertEquals(false to false, app.isTool to app.throughTool)
        // Each second in the state told: in use, with its notification, in the background, and the last not told yet.
        val ten = (0 until Snapshot.COLUMNS).map { app.up(Snapshot.TEN_MINUTES, it) to app.down(Snapshot.TEN_MINUTES, it) }
        assertEquals(listOf(0L to 0L, 100L to 0L, 200L to 0L, 300L to 0L, 400L to 1_000L), ten)
        assertEquals(ten, (0 until Snapshot.COLUMNS).map { app.up(Snapshot.HOUR, it) to app.down(Snapshot.HOUR, it) })
        // Since the screen came on, a second in: not the second in use before it.
        val since = (0 until Snapshot.COLUMNS).map { app.up(Snapshot.SINCE_SCREEN_ON, it) }
        assertEquals(listOf(0L, 0L, 200L, 300L, 400L), since)
        val web = app.destinations.single()
        assertEquals(listOf(6, 0, 0, 0), listOf(web.protocol, web.namedBy, web.ech, web.dns))
        assertEquals("198.51.100.9" to 443, web.address.hostAddress to web.port)
        assertEquals("www.example.com" to "", web.name to web.dnsName)
        assertEquals(0L to 0, web.asn to web.network)
        assertEquals(listOf(1_000L, 1_000L, 1_000L, 1_000L, 900L, 1_000L), web.bytes)
    }

    /** No snapshot, cut short anywhere or with any byte changed, makes the reader throw: it reads it or refuses it. */
    @Test
    fun noSnapshotCrashesTheReader() {
        for (length in 0..fixture.size) Snapshot.parse(fixture.copyOf(length))
        for (at in fixture.indices) {
            for (value in listOf(0, 1, 2, 4, 16, 0x7f, 0x80, 0xff)) {
                Snapshot.parse(fixture.copyOf().also { it[at] = value.toByte() })
            }
        }
        assertNull(Snapshot.parse(fixture.copyOf(fixture.size - 1)))
        assertNull(Snapshot.parse(fixture + 0))
        assertNull(Snapshot.parse(fixture.copyOf().also { it[0] = 2 }))
        assertNull("no engine runs", Snapshot.parse(ByteArray(0)))
    }
}
