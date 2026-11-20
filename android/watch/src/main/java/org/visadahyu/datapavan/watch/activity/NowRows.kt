package org.visadahyu.datapavan.watch.activity

import org.visadahyu.datapavan.watch.log.AppState

/**
 * The rules of the view "Now" (ADR 0046, decision 2 (d)), as pure functions the JVM tests hold: which group
 * an app's row is in, the order of rows, why an app's bytes have no state, how a destination is named, and
 * the line of the window while the screen was off. The screen draws what these return.
 */
object NowRows {
    /**
     * What counts as sending: more than this many bytes sent in a state. The lab run of decision 4 sets it
     * (a messenger's keep-alive is not news), as it sets the summary's floor; 0 until then (the maintainer,
     * 2026-11-19).
     */
    const val SENT_FLOOR = 0L

    /** The groups of rows, in the order they show. */
    const val BACKGROUND = 0
    const val NOTIFICATION = 1
    const val IN_USE = 2

    /** Sent above the floor only in no state, or not told yet: no state to group the app by. */
    const val NO_STATE = 3

    /** Sent nothing above the floor: received only. */
    const val RECEIVED = 4

    /**
     * An app's group in [window], by the bytes it SENT (the maintainer, 2026-11-19): "in the background" when it
     * sent more than [SENT_FLOOR] while the user was not using it and no notification could show, whatever it
     * did otherwise; else "with its notification", else "in use", by the same rule. An app that sent above the
     * floor only where its state is not known comes next; one that sent nothing above it, last. Received bytes
     * still show on the row, but decide no group: sending is what this view is about, and an app that only
     * received while the user was not using it (a push, a download it was asked for) sent nothing of the
     * user's. Grouping by the state with the most bytes would hide a messenger that sent 2 MB in use and
     * 500 KB in the background under "in use", the one fact this view exists to show.
     */
    fun group(app: Snapshot.App, window: Int): Int = when {
        sent(app, window, AppState.BACKGROUND) > SENT_FLOOR -> BACKGROUND
        sent(app, window, AppState.NOTIFICATION) > SENT_FLOOR -> NOTIFICATION
        sent(app, window, AppState.IN_USE) > SENT_FLOOR -> IN_USE
        sent(app, window, AppState.NONE) + sent(app, window, AppState.NOT_YET) > SENT_FLOOR -> NO_STATE
        else -> RECEIVED
    }

    /**
     * What orders an app within its group: the bytes sent in the group's state, then received in it; for apps
     * with no state, the bytes sent and received in no state and not told yet; for apps that sent nothing
     * above the floor, the bytes received in every column, most first.
     */
    private fun weight(app: Snapshot.App, window: Int): Pair<Long, Long> = when (group(app, window)) {
        BACKGROUND -> sent(app, window, AppState.BACKGROUND) to received(app, window, AppState.BACKGROUND)
        NOTIFICATION -> sent(app, window, AppState.NOTIFICATION) to received(app, window, AppState.NOTIFICATION)
        IN_USE -> sent(app, window, AppState.IN_USE) to received(app, window, AppState.IN_USE)
        NO_STATE -> sent(app, window, AppState.NONE) + sent(app, window, AppState.NOT_YET) to
            received(app, window, AppState.NONE) + received(app, window, AppState.NOT_YET)
        else -> (AppState.NONE..AppState.NOT_YET).sumOf { received(app, window, it) } to 0L
    }

    /**
     * The apps with traffic in [window], sorted: by group, then by [weight], most first, then by [label]
     * without regard to case and by UID, so that the order is total.
     */
    fun sorted(apps: List<Snapshot.App>, window: Int, label: (Int?) -> String): List<Snapshot.App> =
        apps.filter { hasTraffic(it, window) }.sortedWith(
            compareBy<Snapshot.App> { group(it, window) }
                .thenByDescending { weight(it, window).first }
                .thenByDescending { weight(it, window).second }
                .thenBy { label(it.uid).lowercase() }
                .thenBy { it.uid ?: Int.MIN_VALUE },
        )

    /** Whether an app sent or received anything in [window], in a state or not. */
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
     * The line of the window while the screen was off, once it came on again: how many apps sent more than
     * [SENT_FLOOR] in the background then, and how much. The user's tool is not counted: its bytes hold the
     * chained apps' (decision 5; review c1 of W5's third part, screens, m2). Null for no window that ended.
     */
    fun offLine(snapshot: Snapshot): Pair<Int, Long>? {
        if (snapshot.offFrom == 0L || snapshot.offUntil == 0L || snapshot.offUntil < snapshot.offFrom) return null
        val senders = snapshot.apps.filter { !it.isTool && sent(it, Snapshot.WHILE_OFF, AppState.BACKGROUND) > SENT_FLOOR }
        return senders.size to senders.sumOf { sent(it, Snapshot.WHILE_OFF, AppState.BACKGROUND) }
    }

    /**
     * The rows' keys in the order they keep while the view is open: the order sorted the last time the user
     * asked (or the view opened, or the window changed), with apps that came since added after, in their
     * own sorted order, and apps that left the window kept where they were, so that nothing moves under a
     * finger or a screen reader's focus (decision 2 (d)). [Order.sort] sorts anew. It is kept across an app's
     * history and a rotation ([save], [restore]).
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

        companion object {
            /** A UID in the saved form, where no UID is [NO_APP]; UIDs are never negative. */
            private const val NO_APP = -1

            /** The order in a form a saved state keeps: its keys, or null before it was first sorted. */
            fun save(order: Order): IntArray? = if (order.sorted) order.keys.map { it ?: NO_APP }.toIntArray() else null

            /** Gives [order] the keys [save] kept, as sorted, or leaves it to sort when [saved] is null. */
            fun restore(order: Order, saved: IntArray?) {
                saved ?: return
                order.keys = saved.map { it.takeIf { uid -> uid != NO_APP } }
                order.sorted = true
            }
        }
    }

    /** Where a destination's name came from, by the log's code (LogRecord.Segment.namedBy). */
    enum class NamedBy { DNS, TLS, QUIC, ORGANISATION, PROXY, UNKNOWN }

    fun namedBy(code: Int): NamedBy = when (code) {
        0 -> NamedBy.DNS
        1 -> NamedBy.TLS
        2 -> NamedBy.QUIC
        3 -> NamedBy.ORGANISATION
        // The destination the app asked its proxy for (version 5 of the log, 4 of the snapshot; ADR 0052).
        5 -> NamedBy.PROXY
        else -> NamedBy.UNKNOWN
    }

    /**
     * What a destination is called: its name, or its address where it has none, and the DNS name beside it
     * where it differs from the name the connection sent (ADR 0044, decision 4), empty otherwise.
     */
    fun destination(name: String, dnsName: String, address: String): Pair<String, String> =
        (name.ifEmpty { address }) to dnsName.takeIf { it.isNotEmpty() && it != name }.orEmpty()
}
