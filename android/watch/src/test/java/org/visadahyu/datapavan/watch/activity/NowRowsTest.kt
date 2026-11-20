package org.visadahyu.datapavan.watch.activity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.watch.log.AppState

class NowRowsTest {
    /** An app with bytes up and down in the window of ten minutes, by column, and its no-state bytes by why. */
    private fun app(uid: Int?, vararg columns: Pair<Int, Pair<Long, Long>>, window: Int = Snapshot.TEN_MINUTES): Snapshot.App {
        val bytes = LongArray(Snapshot.WINDOWS * Snapshot.COLUMNS * 2)
        for ((column, ways) in columns) {
            bytes[(window * Snapshot.COLUMNS + column) * 2] += ways.first
            bytes[(window * Snapshot.COLUMNS + column) * 2 + 1] += ways.second
            // A why's bytes are in the column of no state too.
            if (column > AppState.NOT_YET) {
                bytes[(window * Snapshot.COLUMNS + AppState.NONE) * 2] += ways.first
                bytes[(window * Snapshot.COLUMNS + AppState.NONE) * 2 + 1] += ways.second
            }
        }
        return Snapshot.App(uid, AppState.BACKGROUND, isTool = false, throughTool = false, bytes = bytes, destinations = emptyList())
    }

    private val ten = Snapshot.TEN_MINUTES
    private fun label(uid: Int?) = mapOf(1 to "Mail", 2 to "Maps", 3 to "Music", 4 to "Notes", 5 to "chat", 11 to "Same", 12 to "Same").getOrDefault(uid, "")

    /**
     * An app is grouped by the bytes it SENT above the floor (the maintainer, 2026-11-19): in the background as
     * soon as it sent there, whatever else it did; received bytes decide no group.
     */
    @Test
    fun anAppIsGroupedByWhatItSentInEachState() {
        assertEquals(0L, NowRows.SENT_FLOOR)
        val messenger = app(1, AppState.IN_USE to (2_000_000L to 0L), AppState.BACKGROUND to (500L to 0L))
        assertEquals(NowRows.BACKGROUND, NowRows.group(messenger, ten))
        // Received in the background only: not "in the background"; it sent with its notification.
        val receivedOnly = app(1, AppState.BACKGROUND to (0L to 10L), AppState.NOTIFICATION to (99L to 0L))
        assertEquals(NowRows.NOTIFICATION, NowRows.group(receivedOnly, ten))
        assertEquals(NowRows.NOTIFICATION, NowRows.group(app(1, AppState.NOTIFICATION to (1L to 0L), AppState.IN_USE to (9L to 0L)), ten))
        assertEquals(NowRows.IN_USE, NowRows.group(app(1, AppState.IN_USE to (1L to 0L), AppState.BACKGROUND to (0L to 50L)), ten))
        assertEquals(NowRows.NO_STATE, NowRows.group(app(1, Snapshot.reasonColumn(AppState.NO_ACCESS) to (5L to 0L)), ten))
        assertEquals(NowRows.NO_STATE, NowRows.group(app(1, AppState.NOT_YET to (5L to 0L)), ten))
        // Sent nothing: after the groups, however much it received, and in whatever state.
        assertEquals(NowRows.RECEIVED, NowRows.group(app(1, AppState.BACKGROUND to (0L to 5_000L)), ten))
        assertEquals(NowRows.RECEIVED, NowRows.group(app(1, AppState.IN_USE to (0L to 1L)), ten))
        // Another window's bytes do not count in this one.
        assertEquals(NowRows.RECEIVED, NowRows.group(app(1, AppState.BACKGROUND to (5L to 0L), window = Snapshot.HOUR), ten))
    }

    /**
     * Rows: in the background, then with the notification, then in use, then no state, then apps that sent
     * nothing; within a group by bytes sent in its state, most first, then received, then by name without
     * regard to case and by UID; apps that sent nothing by bytes received; an app with no traffic is no row.
     */
    @Test
    fun rowsAreSortedByGroupThenBytesSentInItsState() {
        val apps = listOf(
            app(1, AppState.IN_USE to (9_000L to 0L)),
            app(2, AppState.BACKGROUND to (10L to 0L), AppState.IN_USE to (5_000_000L to 0L)),
            app(3, AppState.BACKGROUND to (20L to 0L)),
            app(4, AppState.NOTIFICATION to (100L to 0L)),
            app(5, AppState.BACKGROUND to (20L to 7L)),
            app(6, AppState.NOT_YET to (1L to 0L)),
            app(7, AppState.BACKGROUND to (0L to 0L)),
            app(8, AppState.BACKGROUND to (0L to 900L)),
            app(9, AppState.IN_USE to (0L to 9_000L)),
            app(null, AppState.NOT_YET to (2L to 0L)),
        )
        val order = NowRows.sorted(apps, ten, ::label).map { it.uid }
        assertEquals(listOf(5, 3, 2, 4, 1, null, 6, 9, 8), order)
        // Equal bytes sent: by bytes received, most first, before the name.
        val received = listOf(app(1, AppState.BACKGROUND to (20L to 0L)), app(4, AppState.BACKGROUND to (20L to 9L)))
        assertEquals(listOf(4, 1), NowRows.sorted(received, ten, ::label).map { it.uid })
        // Equal bytes: by name without regard to case ("chat" before "Mail"), then by UID, smallest first.
        val tied = listOf(app(1, AppState.IN_USE to (1L to 1L)), app(5, AppState.IN_USE to (1L to 1L)), app(9, AppState.IN_USE to (1L to 1L)))
        assertEquals(listOf(9, 5, 1), NowRows.sorted(tied, ten, ::label).map { it.uid })
        val sameName = listOf(app(12, AppState.IN_USE to (1L to 1L)), app(11, AppState.IN_USE to (1L to 1L)))
        assertEquals(listOf(11, 12), NowRows.sorted(sameName, ten, ::label).map { it.uid })
        // No state: by the bytes in no state and not told yet together.
        val none = listOf(
            app(1, AppState.NOT_YET to (5L to 0L)),
            app(2, Snapshot.reasonColumn(AppState.LATE) to (3L to 0L), AppState.NOT_YET to (3L to 0L)),
        )
        assertEquals(listOf(2, 1), NowRows.sorted(none, ten, ::label).map { it.uid })
    }

    /**
     * Without usage access every byte has no state: every app is still a row (review c1 of W5's third part,
     * screens, m5: a test that counted only the states left "Now" empty then).
     */
    @Test
    fun appsWithNoStateAreRows() {
        val noAccess = listOf(
            app(1, Snapshot.reasonColumn(AppState.NO_ACCESS) to (5L to 0L)),
            app(2, Snapshot.reasonColumn(AppState.NO_ACCESS) to (0L to 7L)),
        )
        assertEquals(listOf(1, 2), NowRows.sorted(noAccess, ten, ::label).map { it.uid })
        assertTrue(NowRows.hasTraffic(noAccess[1], ten))
    }

    /** Rows keep their order while the view is open: new apps come at the end, gone ones stay; a sort asked for sorts anew. */
    @Test
    fun rowsKeepTheirOrderUntilTheUserSorts() {
        val order = NowRows.Order()
        val first = listOf(app(1, AppState.BACKGROUND to (10L to 0L)), app(2, AppState.IN_USE to (10L to 0L)))
        assertEquals(listOf(1, 2), order.of(first, ten, ::label))
        // App 2 now sends more in the background, app 3 comes, app 1 leaves the window.
        val later = listOf(
            app(1),
            app(2, AppState.BACKGROUND to (99L to 0L)),
            app(3, AppState.BACKGROUND to (500L to 0L)),
        )
        assertEquals(listOf(1, 2, 3), order.of(later, ten, ::label))
        order.sort()
        assertEquals(listOf(3, 2), order.of(later, ten, ::label))
    }

    /**
     * The order outlives the activity: saved and restored, as across a rotation, it keeps its keys, the app
     * with no UID among them, and adds new apps at the end; one never sorted sorts at its first reading
     * (review c1 of W5's third part, screens, M2).
     */
    @Test
    fun theOrderIsKeptAcrossARotation() {
        val order = NowRows.Order()
        val apps = listOf(app(2, AppState.BACKGROUND to (10L to 0L)), app(null, AppState.IN_USE to (5L to 0L)))
        assertEquals(listOf(2, null), order.of(apps, ten, ::label))
        val saved = NowRows.Order.save(order)
        val again = NowRows.Order()
        NowRows.Order.restore(again, saved)
        val later = apps + app(3, AppState.BACKGROUND to (900L to 0L))
        assertEquals(listOf(2, null, 3), again.of(later, ten, ::label))
        assertEquals(null, NowRows.Order.save(NowRows.Order()))
        val fresh = NowRows.Order()
        NowRows.Order.restore(fresh, null)
        assertEquals(listOf(3, 2, null), fresh.of(later, ten, ::label))
    }

    /**
     * The line of the window while the screen was off: the apps that sent above the floor in the background
     * then, and how much, the user's tool not counted (review c1, screens, m2); none before the window ended.
     */
    @Test
    fun theOffLineCountsTheAppsThatSentButNotTheTool() {
        fun off(uid: Int, sent: Long, received: Long = 0, tool: Boolean = false) =
            app(uid, AppState.BACKGROUND to (sent to received), window = Snapshot.WHILE_OFF).copy(isTool = tool)
        val apps = listOf(off(1, 100), off(2, 0, 500), off(3, 40), off(4, 1_000, tool = true))
        val snapshot = Snapshot(0, Snapshot.STATES, 0, Snapshot.SCREEN_ON, 50, 10, 50, apps)
        assertEquals(2 to 140L, NowRows.offLine(snapshot))
        assertEquals(null, NowRows.offLine(snapshot.copy(offUntil = 0)))
        assertEquals(null, NowRows.offLine(snapshot.copy(offFrom = 0)))
        assertEquals(0 to 0L, NowRows.offLine(snapshot.copy(apps = listOf(off(2, 0, 500)))))
    }

    /** Why bytes have no state: each why with its bytes, most first, none for the whys with none. */
    @Test
    fun reasonsSayWhyBytesHaveNoState() {
        val app = app(
            1,
            Snapshot.reasonColumn(AppState.NO_ACCESS) to (10L to 0L),
            Snapshot.reasonColumn(AppState.LATE) to (100L to 5L),
            AppState.BACKGROUND to (7L to 0L),
        )
        assertEquals(
            listOf(NowRows.Reason(AppState.LATE, 100L, 5L), NowRows.Reason(AppState.NO_ACCESS, 10L, 0L)),
            NowRows.reasons(app, ten),
        )
        assertEquals(emptyList<NowRows.Reason>(), NowRows.reasons(app, Snapshot.HOUR))
        assertEquals(listOf(AppState.NO_ACCESS, AppState.LOCKED, AppState.LATE, AppState.NO_APP, AppState.NOT_TOLD), Snapshot.REASONS)
        assertEquals((5..9).toList(), Snapshot.REASONS.map(Snapshot::reasonColumn))
    }

    /** A destination: its name, or its address where it has none, and the DNS name beside it where it differs. */
    @Test
    fun aDestinationIsNamedAsW3NamesIt() {
        assertEquals("a.example" to "b.example", NowRows.destination("a.example", "b.example", "192.0.2.1"))
        assertEquals("a.example" to "", NowRows.destination("a.example", "a.example", "192.0.2.1"))
        assertEquals("a.example" to "", NowRows.destination("a.example", "", "192.0.2.1"))
        assertEquals("192.0.2.1" to "", NowRows.destination("", "", "192.0.2.1"))
        assertEquals(
            listOf(
                NowRows.NamedBy.DNS, NowRows.NamedBy.TLS, NowRows.NamedBy.QUIC, NowRows.NamedBy.ORGANISATION, NowRows.NamedBy.UNKNOWN,
                NowRows.NamedBy.PROXY, NowRows.NamedBy.UNKNOWN,
            ),
            (0..6).map(NowRows::namedBy),
        )
    }
}
