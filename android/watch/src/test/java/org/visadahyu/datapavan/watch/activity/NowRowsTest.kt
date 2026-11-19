package org.visadahyu.datapavan.watch.activity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    private fun label(uid: Int?) = mapOf(1 to "Mail", 2 to "Maps", 3 to "Music", 4 to "Notes", 5 to "chat").getOrDefault(uid, "")

    /** An app is in the background group once it had traffic in the background, whatever else it did. */
    @Test
    fun anAppIsGroupedByTheLeastSeenStateItHadTrafficIn() {
        val messenger = app(1, AppState.IN_USE to (2_000_000L to 0L), AppState.BACKGROUND to (500L to 0L))
        assertEquals(NowRows.BACKGROUND, NowRows.group(messenger, ten))
        val receivedOnly = app(1, AppState.BACKGROUND to (0L to 10L), AppState.NOTIFICATION to (99L to 0L))
        assertEquals(NowRows.BACKGROUND, NowRows.group(receivedOnly, ten))
        assertEquals(NowRows.NOTIFICATION, NowRows.group(app(1, AppState.NOTIFICATION to (1L to 0L), AppState.IN_USE to (9L to 0L)), ten))
        assertEquals(NowRows.IN_USE, NowRows.group(app(1, AppState.IN_USE to (0L to 1L)), ten))
        assertEquals(NowRows.NO_STATE, NowRows.group(app(1, Snapshot.reasonColumn(AppState.NO_ACCESS) to (5L to 0L)), ten))
        assertEquals(NowRows.NO_STATE, NowRows.group(app(1, AppState.NOT_YET to (5L to 0L)), ten))
        // Another window's bytes do not count in this one.
        assertEquals(NowRows.NO_STATE, NowRows.group(app(1, AppState.BACKGROUND to (5L to 0L), window = Snapshot.HOUR), ten))
    }

    /**
     * Rows: in the background first, then with the notification, then in use, then no state; within a group by
     * bytes sent in its state, most first, then received, then by name and UID; an app with no traffic in the
     * window is not a row.
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
            app(null, AppState.NOT_YET to (2L to 0L)),
        )
        val order = NowRows.sorted(apps, ten, ::label).map { it.uid }
        assertEquals(listOf(5, 3, 2, 4, 1, null, 6), order)
        // Equal bytes sent: by bytes received, most first, before the name.
        val received = listOf(app(1, AppState.BACKGROUND to (20L to 0L)), app(4, AppState.BACKGROUND to (20L to 9L)))
        assertEquals(listOf(4, 1), NowRows.sorted(received, ten, ::label).map { it.uid })
        // Equal bytes: by name, then UID.
        val tied = listOf(app(4, AppState.IN_USE to (1L to 1L)), app(1, AppState.IN_USE to (1L to 1L)), app(9, AppState.IN_USE to (1L to 1L)))
        assertEquals(listOf(9, 1, 4), NowRows.sorted(tied, ten, ::label).map { it.uid })
        // No state: by the bytes in no state and not told yet together.
        val none = listOf(
            app(1, AppState.NOT_YET to (5L to 0L)),
            app(2, Snapshot.reasonColumn(AppState.LATE) to (3L to 0L), AppState.NOT_YET to (3L to 0L)),
        )
        assertEquals(listOf(2, 1), NowRows.sorted(none, ten, ::label).map { it.uid })
    }

    /** Rows keep their order while the view is open: new apps come at the end, gone ones stay; a sort asked for sorts anew. */
    @Test
    fun rowsKeepTheirOrderUntilTheUserSorts() {
        val order = NowRows.Order()
        val first = listOf(app(1, AppState.BACKGROUND to (10L to 0L)), app(2, AppState.IN_USE to (10L to 0L)))
        assertEquals(listOf(1, 2), order.of(first, ten, ::label))
        assertFalse(order.outOfOrder(first, ten, ::label))
        // App 2 now sends more in the background, app 3 comes, app 1 leaves the window.
        val later = listOf(
            app(1),
            app(2, AppState.BACKGROUND to (99L to 0L)),
            app(3, AppState.BACKGROUND to (500L to 0L)),
        )
        assertEquals(listOf(1, 2, 3), order.of(later, ten, ::label))
        assertTrue(order.outOfOrder(later, ten, ::label))
        order.sort()
        assertEquals(listOf(3, 2), order.of(later, ten, ::label))
        assertFalse(order.outOfOrder(later, ten, ::label))
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
            listOf(NowRows.NamedBy.DNS, NowRows.NamedBy.TLS, NowRows.NamedBy.QUIC, NowRows.NamedBy.ORGANISATION, NowRows.NamedBy.UNKNOWN, NowRows.NamedBy.UNKNOWN),
            (0..5).map(NowRows::namedBy),
        )
    }
}
