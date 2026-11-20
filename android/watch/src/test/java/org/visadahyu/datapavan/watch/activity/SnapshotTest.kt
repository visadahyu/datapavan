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
        // The screen was off for a minute before it came on.
        assertEquals(t - 59_000 to t + 1_000, snapshot.offFrom to snapshot.offUntil)
        assertEquals(listOf(null, 10_123, 10_124), snapshot.apps.map { it.uid })

        val noApp = snapshot.apps[0]
        assertEquals(AppState.NO_APP, noApp.now)
        assertEquals(50L to 0L, noApp.up(Snapshot.TEN_MINUTES, AppState.NONE) to noApp.down(Snapshot.TEN_MINUTES, AppState.NONE))
        // Counted three and a half seconds in, after the screen came on.
        assertEquals(50L, noApp.up(Snapshot.SINCE_SCREEN_ON, AppState.NONE))
        // In no state because Android named no app.
        assertEquals(50L, noApp.up(Snapshot.TEN_MINUTES, Snapshot.reasonColumn(AppState.NO_APP)))
        assertEquals(0L, noApp.up(Snapshot.TEN_MINUTES, Snapshot.reasonColumn(AppState.NO_ACCESS)))
        val encrypted = noApp.destinations.single()
        assertEquals(listOf(17, 1, 1, 2), listOf(encrypted.protocol, encrypted.namedBy, encrypted.ech, encrypted.dns))
        assertEquals(true, encrypted.cameIn)
        assertEquals("192.0.2.7" to 853, encrypted.address.hostAddress to encrypted.port)
        assertEquals(listOf("dns.example", "other.example", "sample", ""), listOf(encrypted.name, encrypted.dnsName, encrypted.resolver, encrypted.organisation))
        assertEquals(listOf(50L, 0L, 50L, 0L, 50L, 0L), encrypted.bytes)
        // Version 3: directly, and no app went through a WireGuard tunnel.
        assertEquals(org.visadahyu.datapavan.watch.log.LogRecord.VIA_DIRECT to 0L, encrypted.via to encrypted.tunnel)
        assertEquals(listOf(0L, 0L, 0L), snapshot.apps.map { it.throughTunnel })
        // Version 4: no proxy.
        assertNull(encrypted.proxy)

        val app = snapshot.apps[1]
        assertEquals(AppState.BACKGROUND, app.now)
        assertEquals(false to false, app.isTool to app.throughTool)
        // Each second in the state told: in use, with its notification, in the background, and the last not told yet.
        val ten = (0 until Snapshot.COLUMNS).map { app.up(Snapshot.TEN_MINUTES, it) to app.down(Snapshot.TEN_MINUTES, it) }
        assertEquals(listOf(0L to 0L, 100L to 0L, 200L to 0L, 300L to 0L, 400L to 1_000L) + List(5) { 0L to 0L }, ten)
        assertEquals(ten, (0 until Snapshot.COLUMNS).map { app.up(Snapshot.HOUR, it) to app.down(Snapshot.HOUR, it) })
        // Since the screen came on, a second in: not the second in use before it, which was while it was off.
        val since = (0..AppState.NOT_YET).map { app.up(Snapshot.SINCE_SCREEN_ON, it) }
        assertEquals(listOf(0L, 0L, 200L, 300L, 400L), since)
        val off = (0..AppState.NOT_YET).map { app.up(Snapshot.WHILE_OFF, it) }
        assertEquals(listOf(0L, 100L, 0L, 0L, 0L), off)
        val web = app.destinations.single()
        assertEquals(listOf(6, 0, 0, 0), listOf(web.protocol, web.namedBy, web.ech, web.dns))
        assertEquals("198.51.100.9" to 443, web.address.hostAddress to web.port)
        assertEquals("www.example.com" to "", web.name to web.dnsName)
        assertEquals(0L to 0, web.asn to web.network)
        assertEquals(listOf(1_000L, 1_000L, 1_000L, 1_000L, 900L, 1_000L), web.bytes)
        assertNull(web.proxy)

        // Version 4: a destination through a SOCKS5 proxy its bytes declared (ADR 0052).
        val proxied = snapshot.apps[2].destinations.single()
        assertEquals("example.org" to 5, proxied.name to proxied.namedBy)
        assertEquals("203.0.113.5" to 1080, proxied.address.hostAddress to proxied.port)
        assertEquals(
            org.visadahyu.datapavan.watch.log.LogRecord.Proxy(
                org.visadahyu.datapavan.watch.log.LogRecord.PROXY_SOCKS5, password = true, asked = "example.org",
                askedPort = 443, proxyName = "proxy.example.net", organisation = "Hetzner Online GmbH",
            ),
            proxied.proxy,
        )
    }

    /**
     * A code the engine never writes, for what the last reading knew, the screen or an app's state now, is
     * refused, and the highest of each it writes is read (review b1 of W5's second part, Kotlin, finding 6).
     */
    @Test
    fun refusesACodeTheEngineNeverWrites() {
        // Version, taken (8), known; told until (8), screen; since, off from and until (8 each), the apps' count
        // (4); the first app's UID (4), now.
        val known = 1 + 8
        val screen = known + 1 + 8
        val now = screen + 1 + 3 * 8 + 4 + 4
        val with = { at: Int, value: Int -> Snapshot.parse(fixture.copyOf().also { it[at] = value.toByte() }) }
        assertEquals(Snapshot.LOCKED, with(known, Snapshot.LOCKED)?.known)
        assertNull(with(known, Snapshot.LOCKED + 1))
        assertEquals(Snapshot.SCREEN_UNKNOWN, with(screen, Snapshot.SCREEN_UNKNOWN)?.screen)
        assertNull(with(screen, Snapshot.SCREEN_UNKNOWN + 1))
        assertEquals(AppState.NOT_YET, with(now, AppState.NOT_YET)?.apps?.get(0)?.now)
        assertEquals(AppState.NOT_TOLD, with(now, AppState.NOT_TOLD)?.apps?.get(0)?.now)
        for (code in listOf(AppState.NONE, AppState.NOT_YET + 1, 0x0f, AppState.NO_ACCESS or AppState.IN_USE, 0x60, 0xff)) {
            assertNull("state $code", with(now, code))
        }
    }

    /**
     * Bytes in no state by why that do not add up to the column of no state, and a window while the screen was
     * off that ends before it began, or has an end and no start, are refused (W5's third part).
     */
    @Test
    fun refusesReasonsThatDoNotAddUpAndAWindowBackwards() {
        val buffer = { bytes: ByteArray -> java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN) }
        // The first app's bytes: after the head (1 + 8 + 1 + 8 + 1 + 3 × 8 + 4), its UID, now and flags.
        val firstBytes = 1 + 8 + 1 + 8 + 1 + 3 * 8 + 4 + 4 + 1 + 1
        val noAppWhy = firstBytes + Snapshot.reasonColumn(AppState.NO_APP) * 2 * 8
        assertNull(Snapshot.parse(fixture.copyOf().also { buffer(it).putLong(noAppWhy, 49) }))
        val noAccessWhy = firstBytes + Snapshot.reasonColumn(AppState.NO_ACCESS) * 2 * 8
        assertNull(Snapshot.parse(fixture.copyOf().also { buffer(it).putLong(noAccessWhy, 1) }))
        val offFrom = 1 + 8 + 1 + 8 + 1 + 8
        assertNull(Snapshot.parse(fixture.copyOf().also { buffer(it).putLong(offFrom, t + 1_001) }))
        assertNull(Snapshot.parse(fixture.copyOf().also { buffer(it).putLong(offFrom, 0) }))
        // Still off: an end of 0 with any start.
        val stillOff = Snapshot.parse(fixture.copyOf().also { buffer(it).putLong(offFrom + 8, 0) })
        assertEquals(t - 59_000 to 0L, stillOff?.offFrom to stillOff?.offUntil)
        assertEquals(t + 1_000, Snapshot.parse(fixture.copyOf().also { buffer(it).putLong(offFrom, t + 1_000) })?.offFrom)
    }

    /** A snapshot that lists one UID twice is refused (nit 10): the view keys its rows by UID. */
    @Test
    fun refusesAUidListedTwice() {
        val first = 1 + 8 + 1 + 8 + 1 + 3 * 8 + 4
        val second = first + 4 + 1 + 1 + Snapshot.WINDOWS * Snapshot.COLUMNS * 2 * 8 + 2 + destinationsOf(0) + 4
        val twice = fixture.copyOf().also { java.nio.ByteBuffer.wrap(it).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(second, -1) }
        assertNull(Snapshot.parse(twice))
        // The same place given another UID reads: it is the second app's UID.
        val other = fixture.copyOf().also { java.nio.ByteBuffer.wrap(it).order(java.nio.ByteOrder.LITTLE_ENDIAN).putInt(second, 10_125) }
        assertEquals(listOf(null, 10_125, 10_124), Snapshot.parse(other)?.apps?.map { it.uid })
    }

    /**
     * The flags' third bit says the user's tool's own servers are not kept ("Log where these apps connect" off,
     * decision 3 as decided on 2026-11-19), and only for the app it is set on: the view says so from it.
     */
    @Test
    fun readsTheToolsServersHidden() {
        assertEquals(listOf(false, false, false), checkNotNull(Snapshot.parse(fixture)).apps.map { it.serversHidden })
        val first = 1 + 8 + 1 + 8 + 1 + 3 * 8 + 4
        val second = first + 4 + 1 + 1 + Snapshot.WINDOWS * Snapshot.COLUMNS * 2 * 8 + 2 + destinationsOf(0) + 4
        val hidden = fixture.copyOf().also { it[second + 5] = (it[second + 5].toInt() or 0b101).toByte() }
        val app = checkNotNull(Snapshot.parse(hidden)).apps
        assertEquals(listOf(false, true, false), app.map { it.serversHidden })
        assertEquals(true to false, app[1].isTool to app[1].throughTool)
    }

    /**
     * Version 3: a destination's route and an app's tunnel (W7). The first app's one destination goes through tunnel
     * 5, and the second app through tunnel 9 with its destinations not kept; a route the engine never writes, or a
     * number beside no tunnel, is refused.
     */
    @Test
    fun readsEachDestinationsRouteAndAnAppsTunnel() {
        val buffer = { bytes: ByteArray -> java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.LITTLE_ENDIAN) }
        val first = 1 + 8 + 1 + 8 + 1 + 3 * 8 + 4
        // The route's five bytes, then the destination's proxy, none: one byte.
        val route = first + 4 + 1 + 1 + Snapshot.WINDOWS * Snapshot.COLUMNS * 2 * 8 + 2 + destinationsOf(0) - 6
        val appTunnel = route + 6
        val routed = fixture.copyOf().also {
            it[route] = 2
            buffer(it).putInt(route + 1, 5)
            buffer(it).putInt(fixture.size - 4, 9)
        }
        val snapshot = checkNotNull(Snapshot.parse(routed))
        val destination = snapshot.apps[0].destinations.single()
        assertEquals(org.visadahyu.datapavan.watch.log.LogRecord.VIA_TUNNEL to 5L, destination.via to destination.tunnel)
        assertEquals(listOf(0L, 0L, 9L), snapshot.apps.map { it.throughTunnel })
        assertEquals(0, buffer(fixture).getInt(appTunnel))
        for (code in listOf(3, 0x80, 0xff)) {
            assertNull("no such route: $code", Snapshot.parse(fixture.copyOf().also { it[route] = code.toByte() }))
        }
        assertNull("a tunnel of no number", Snapshot.parse(fixture.copyOf().also { it[route] = 2 }))
        assertNull("a number beside no tunnel", Snapshot.parse(fixture.copyOf().also { buffer(it).putInt(route + 1, 5) }))
    }

    /** The bytes the first app's destinations take in the fixture. */
    private fun destinationsOf(app: Int): Int {
        val snapshot = checkNotNull(Snapshot.parse(fixture))
        return snapshot.apps[app].destinations.sumOf { d ->
            5 + 1 + d.address.address.size + 2 + 4 + 1 +
                listOf(d.name, d.dnsName, d.resolver, d.organisation).sumOf { 1 + it.toByteArray().size } + 6 * 8 + 5 +
                proxyBytes(d.proxy)
        }
    }

    /** The bytes a destination's proxy takes (version 4): one for none. */
    private fun proxyBytes(proxy: org.visadahyu.datapavan.watch.log.LogRecord.Proxy?): Int {
        proxy ?: return 1
        val asked = when {
            proxy.askedPort < 0 -> 0
            proxy.asked.contains(':') -> 1 + 16 + 1 + 2
            proxy.asked.all { it.isDigit() || it == '.' } -> 1 + 4 + 1 + 2
            else -> 1 + 1 + proxy.asked.toByteArray().size + 2
        }
        return 2 + asked + listOf(proxy.proxyName, proxy.organisation, proxy.cover).sumOf { 1 + it.toByteArray().size }
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
        assertNull("version 1", Snapshot.parse(fixture.copyOf().also { it[0] = 1 }))
        assertNull("version 2", Snapshot.parse(fixture.copyOf().also { it[0] = 2 }))
        assertNull("version 3", Snapshot.parse(fixture.copyOf().also { it[0] = 3 }))
        assertNull(Snapshot.parse(fixture.copyOf().also { it[0] = 5 }))
        assertNull("no engine runs", Snapshot.parse(ByteArray(0)))
    }
}
