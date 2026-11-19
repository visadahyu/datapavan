package org.visadahyu.datapavan.watch.activity

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.watch.log.AppState
import org.visadahyu.datapavan.watch.log.LogRecord

class HistoryTest {
    private val t = 1_794_953_400_000L
    private val app = 10_123

    private fun segment(uid: Int?, start: Long, end: Long, name: String = "a.example", dns: String = "", state: Int = AppState.BACKGROUND) =
        LogRecord.Segment(
            flow = 1, uid = uid, start = start, end = end, up = 10, down = 20, wireUp = 0, wireDown = 0, protocol = 6,
            outcome = 0, namedBy = 1, ech = 0, dns = 0, continues = true, cameIn = false,
            address = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1)), port = 443, asn = 0, network = 0,
            name = name, resolver = "", dnsName = dns, state = state,
        )

    /**
     * A day of an app's history: its own segments only, newest first, each with both names and its state; its
     * lookups counted; and records older than the app now holding its UID counted apart, as an app's since removed.
     */
    @Test
    fun aDayHoldsTheAppsOwnSegmentsNewestFirst() {
        val records = listOf(
            segment(app, t + 1_000, t + 2_000, dns = "b.example", state = AppState.IN_USE),
            segment(app, t + 5_000, t + 6_000),
            segment(app, t + 5_000, t + 9_000, dns = "a.example"),
            segment(10_124, t + 7_000, t + 8_000),
            segment(app, t - 50_000, t - 40_000),
            LogRecord.Lookups(app, t + 3_000, t + 4_000, 3, 0, 0),
            LogRecord.Lookups(app, t - 60_000, t - 59_000, 9, 0, 0),
            LogRecord.Lookups(null, t + 3_000, t + 4_000, 7, 0, 0),
        )
        val day = History.day(20_775, records, app, installedAt = t)
        assertEquals(listOf(t + 5_000 to t + 9_000, t + 5_000 to t + 6_000, t + 1_000 to t + 2_000), day.entries.map { it.start to it.end })
        assertEquals(listOf("", "", "b.example"), day.entries.map { it.dnsName })
        assertEquals(AppState.IN_USE, day.entries.last().state)
        assertEquals(listOf(10L to 20L), day.entries.map { it.sent to it.received }.distinct())
        assertEquals("192.0.2.1" to 443, day.entries[0].address to day.entries[0].port)
        assertEquals(3L, day.lookups)
        assertEquals(2, day.beforeInstall)
        // No app holds the UID now: every record is shown; and the flows Android named no app for are one "app".
        assertEquals(4, History.day(20_775, records, app, installedAt = null).entries.size)
        assertEquals(7L, History.day(20_775, records, null, installedAt = null).lookups)
        // A record that starts exactly when the app was installed is the app's.
        assertEquals(0, History.day(20_775, listOf(segment(app, t, t + 1)), app, installedAt = t).beforeInstall)
    }

    /** The days the log keeps, today first; none with retention "none". */
    @Test
    fun theDaysAreThoseTheLogKeeps() {
        assertEquals(listOf(100L, 99L, 98L, 97L, 96L, 95L, 94L), History.days(100, 7))
        assertEquals(listOf(100L), History.days(100, 1))
        assertEquals(emptyList<Long>(), History.days(100, 0))
    }
}
