package org.visadahyu.datapavan.watch.tunnel

/**
 * Each tunnel's state as the engine gives it ([org.visadahyu.datapavan.watch.Engine.nativeTunnelStates]), read
 * for the screen (W7, part 2): no key, no address, no endpoint. Pure, for the JVM tests.
 */
object TunnelStates {
    /** One tunnel's line: `id handshake received error not-answering plain-dns connected flows configured resolutions`. */
    data class Line(
        val id: Int,
        /** Milliseconds since its last handshake, if it has a session. */
        val handshakeMs: Long?,
        val receivedMs: Long?,
        val error: String?,
        val notAnswering: Boolean,
        /** Its endpoint's name could be resolved only over plain DNS, which the network reads. */
        val plainDns: Boolean,
        val connected: Boolean,
        val flows: Int,
        /** False for a tunnel apps are routed to whose configuration is not set: they wait. */
        val configured: Boolean,
        val resolutions: Long,
    )

    /** The lines that read; a line that does not is left out. */
    fun read(text: String): Map<Int, Line> = text.lines().mapNotNull(::line).associateBy { it.id }

    private fun line(text: String): Line? {
        val w = text.trim().split(' ').filter { it.isNotEmpty() }
        if (w.size != 10) return null
        fun ms(word: String) = if (word == "-") null else word.toLongOrNull()
        fun flag(word: String) = when (word) {
            "1" -> true
            "0" -> false
            else -> null
        }
        return Line(
            id = w[0].toIntOrNull() ?: return null,
            handshakeMs = ms(w[1]),
            receivedMs = ms(w[2]),
            error = w[3].takeIf { it != "-" },
            notAnswering = flag(w[4]) ?: return null,
            plainDns = flag(w[5]) ?: return null,
            connected = flag(w[6]) ?: return null,
            flows = w[7].toIntOrNull() ?: return null,
            configured = flag(w[8]) ?: return null,
            resolutions = w[9].toLongOrNull() ?: return null,
        )
    }

    /** What the screen says of a configuration, from its line and what Watch knows. */
    sealed interface Shown {
        /** Watch is off: it holds no tunnel. */
        data object Off : Shown

        /**
         * Its wrap cannot be opened while the phone is locked, now (the Keystore or the disk erred, tried again), or at
         * all (the key gone): its apps wait.
         */
        data object Locked : Shown
        data object Unavailable : Shown
        data object Lost : Shown

        /** Not set in the engine although apps are routed to it: they wait. */
        data object Missing : Shown

        /** The server does not answer: its apps wait, and nothing of theirs goes out directly. */
        data object NotAnswering : Shown

        /** A session, its last handshake [seconds] ago. */
        data class Connected(val seconds: Long) : Shown

        /** No session yet: it starts when an app sends. */
        data object Idle : Shown
    }

    /**
     * What a state's live region announces (fix round, screens review M3): its kind alone, which stays the same from
     * one second to the next while a configuration stays connected; the handshake's age is said beside it, outside
     * the live region, so that TalkBack does not announce every configuration every second.
     */
    enum class Kind { OFF, LOCKED, UNAVAILABLE, LOST, MISSING, NOT_ANSWERING, CONNECTED, IDLE }

    fun kind(shown: Shown): Kind = when (shown) {
        Shown.Off -> Kind.OFF
        Shown.Locked -> Kind.LOCKED
        Shown.Unavailable -> Kind.UNAVAILABLE
        Shown.Lost -> Kind.LOST
        Shown.Missing -> Kind.MISSING
        Shown.NotAnswering -> Kind.NOT_ANSWERING
        is Shown.Connected -> Kind.CONNECTED
        Shown.Idle -> Kind.IDLE
    }

    fun shown(running: Boolean, opened: TunnelStore.Name?, line: Line?): Shown = when {
        opened == TunnelStore.Name.Lost -> Shown.Lost
        opened == TunnelStore.Name.Locked -> Shown.Locked
        opened == TunnelStore.Name.Unavailable -> Shown.Unavailable
        !running -> Shown.Off
        line == null || !line.configured -> Shown.Missing
        line.notAnswering -> Shown.NotAnswering
        line.handshakeMs != null -> Shown.Connected(line.handshakeMs / 1000)
        else -> Shown.Idle
    }
}
