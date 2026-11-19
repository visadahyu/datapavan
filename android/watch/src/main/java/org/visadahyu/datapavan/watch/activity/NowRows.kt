package org.visadahyu.datapavan.watch.activity

import org.visadahyu.datapavan.watch.log.AppState

/**
 * The rules of the view "Now" (ADR 0046, decision 2 (d)), as pure functions the JVM tests hold: which group
 * an app's row is in, the order of rows, why an app's bytes have no state, and how a destination is named.
 * The screen draws what these return.
 */
object NowRows {
    /** The groups of rows, in the order they show. */
    const val BACKGROUND = 0
    const val NOTIFICATION = 1
    const val IN_USE = 2

    /** Bytes in no state only, or not told yet: no state to group the app by. */
    const val NO_STATE = 3

    /**
     * An app's group in [window]: the least seen state it had traffic in, so that an app is "in the background"
     * as soon as it sent or received anything while the user was not using it and its notification did not
     * show, whatever it did in the other states. Ordering by the state with the most bytes instead would hide
     * a messenger that sent 2 MB in use and 500 KB in the background under "in use", the one fact this view
     * exists to show (W5's third part).
     */
    fun group(app: Snapshot.App, window: Int): Int = when {
        traffic(app, window, AppState.BACKGROUND) > 0 -> BACKGROUND
        traffic(app, window, AppState.NOTIFICATION) > 0 -> NOTIFICATION
        traffic(app, window, AppState.IN_USE) > 0 -> IN_USE
        else -> NO_STATE
    }

    /** What decides the order within a group: the bytes sent in the group's state, then those received. */
    private fun weight(app: Snapshot.App, window: Int): Pair<Long, Long> {
        val column = when (group(app, window)) {
            BACKGROUND -> AppState.BACKGROUND
            NOTIFICATION -> AppState.NOTIFICATION
            IN_USE -> AppState.IN_USE
            else -> -1
        }
        return if (column < 0) {
            sent(app, window, AppState.NONE) + sent(app, window, AppState.NOT_YET) to
                received(app, window, AppState.NONE) + received(app, window, AppState.NOT_YET)
        } else {
            sent(app, window, column) to received(app, window, column)
        }
    }

    /**
     * The apps with traffic in [window], sorted: by group, then by bytes sent in the group's state, most
     * first, then by bytes received, then by [label] and UID so that the order is total.
     */
    fun sorted(apps: List<Snapshot.App>, window: Int, label: (Int?) -> String): List<Snapshot.App> =
        apps.filter { hasTraffic(it, window) }.sortedWith(
            compareBy<Snapshot.App> { group(it, window) }
                .thenByDescending { weight(it, window).first }
                .thenByDescending { weight(it, window).second }
                .thenBy { label(it.uid).lowercase() }
                .thenBy { it.uid ?: Int.MIN_VALUE },
        )

    /** Whether an app sent or received anything in [window]. */
    fun hasTraffic(app: Snapshot.App, window: Int): Boolean =
        (AppState.NONE..AppState.NOT_YET).any { traffic(app, window, it) > 0 }

    fun sent(app: Snapshot.App, window: Int, column: Int): Long = app.up(window, column)
    fun received(app: Snapshot.App, window: Int, column: Int): Long = app.down(window, column)
    fun traffic(app: Snapshot.App, window: Int, column: Int): Long = app.up(window, column) + app.down(window, column)

    /** Why an app's bytes in [window] have no state: each reason with its bytes, up and down, most first. */
    fun reasons(app: Snapshot.App, window: Int): List<Reason> = Snapshot.REASONS
        .map { why -> Reason(why, app.up(window, Snapshot.reasonColumn(why)), app.down(window, Snapshot.reasonColumn(why))) }
        .filter { it.sent + it.received > 0 }
        .sortedByDescending { it.sent + it.received }

    /** Bytes in no state, and why ([AppState.NO_ACCESS] to [AppState.NOT_TOLD]). */
    data class Reason(val why: Int, val sent: Long, val received: Long)

    /**
     * The rows' keys in the order they keep while the view is open: the order sorted the last time the user
     * asked (or the view opened, or the window changed), with apps that came since added after, in their
     * own sorted order, and apps that left the window kept where they were, so that nothing moves under a
     * finger or a screen reader's focus (decision 2 (d)). [Order.sort] sorts anew.
     */
    class Order {
        private var keys: List<Int?> = emptyList()
        private var sorted = false

        /** The keys for [apps], [window] and [label], as above. */
        fun of(apps: List<Snapshot.App>, window: Int, label: (Int?) -> String): List<Int?> {
            val now = sorted(apps, window, label).map { it.uid }
            if (!sorted) {
                keys = now
                sorted = true
            } else {
                keys = keys + now.filter { it !in keys }
            }
            return keys
        }

        /** The next [of] sorts anew: the user asked, the view opened again, or the window changed. */
        fun sort() {
            sorted = false
        }

        /** How many rows would move if sorted now: the button to sort says so only when some would. */
        fun outOfOrder(apps: List<Snapshot.App>, window: Int, label: (Int?) -> String): Boolean {
            val now = sorted(apps, window, label).map { it.uid }
            return keys.filter { it in now } != now
        }
    }

    /** Where a destination's name came from, by the log's code (LogRecord.Segment.namedBy). */
    enum class NamedBy { DNS, TLS, QUIC, ORGANISATION, UNKNOWN }

    fun namedBy(code: Int): NamedBy = when (code) {
        0 -> NamedBy.DNS
        1 -> NamedBy.TLS
        2 -> NamedBy.QUIC
        3 -> NamedBy.ORGANISATION
        else -> NamedBy.UNKNOWN
    }

    /**
     * What a destination is called: its name, or its address where it has none, and the DNS name beside it
     * where it differs from the name the connection sent (ADR 0044, decision 4), empty otherwise.
     */
    fun destination(name: String, dnsName: String, address: String): Pair<String, String> =
        (name.ifEmpty { address }) to dnsName.takeIf { it.isNotEmpty() && it != name }.orEmpty()
}
