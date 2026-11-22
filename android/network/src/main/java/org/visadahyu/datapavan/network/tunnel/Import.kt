package org.visadahyu.datapavan.network.tunnel

/**
 * The import of a WireGuard configuration (W7, part 2): what the engine's parser says of it
 * ([org.visadahyu.datapavan.network.Engine.nativeTunnelParse]), read into what the confirmation shows before anything
 * is saved, and the choice of apps it proposes. Pure, for the JVM tests.
 */
object Import {
    /** The longest file read, in bytes: the parser's own bound (core/net's `MAX_TEXT`); a longer one is refused. */
    const val MAX_TEXT = 16 * 1024

    /** What the parser said. */
    sealed interface Reading

    /** Refused, with a code ([Refusals]), the line counting from 1 and the key, where it names them; never a value. */
    data class Refused(val code: String, val line: Int? = null, val key: String? = null) : Reading

    /** Accepted: what it does. No key is ever here. */
    data class Described(
        val host: String,
        val port: Int,
        val addresses: List<String>,
        val dns: List<String>,
        val allowed: List<String>,
        /** Whether `AllowedIPs` carry every destination of each IP version it has an address of. */
        val everything: Boolean,
        val preshared: Boolean,
        val mtu: Int,
        val keepalive: Int?,
        /** `IncludedApplications`: only these apps. */
        val only: List<String>,
        /** `ExcludedApplications`: every app but these. */
        val except: List<String>,
    ) : Reading {
        /** Whether it has an IPv6 address: without one, a chosen app's IPv6 is refused and it falls back to IPv4. */
        val ipv6: Boolean get() = addresses.any { ':' in it }
    }

    /** Reads the parser's answer; null for one it never gives. */
    fun read(answer: String): Reading? {
        val lines = answer.lines().filter { it.isNotEmpty() }
        val first = lines.firstOrNull() ?: return null
        if (first.startsWith("refused ")) return refusal(first.removePrefix("refused "))
        if (first != "ok") return null
        var endpoint: Pair<String, Int>? = null
        val addresses = mutableListOf<String>()
        val dns = mutableListOf<String>()
        val allowed = mutableListOf<String>()
        var everything: Boolean? = null
        var preshared: Boolean? = null
        var mtu: Int? = null
        var keepalive: Int? = null
        val only = mutableListOf<String>()
        val except = mutableListOf<String>()
        for (line in lines.drop(1)) {
            val words = line.split(' ')
            val value = words.getOrNull(1) ?: return null
            when (words[0]) {
                "endpoint" -> endpoint = value to (words.getOrNull(2)?.toIntOrNull() ?: return null)
                "address" -> addresses += value
                "dns" -> dns += value
                "allowed" -> allowed += value
                "everything" -> everything = value == "1"
                "preshared" -> preshared = value == "1"
                "mtu" -> mtu = value.toIntOrNull() ?: return null
                "keepalive" -> keepalive = value.toIntOrNull() ?: return null
                "only" -> only += value
                "except" -> except += value
                else -> return null
            }
        }
        val (host, port) = endpoint ?: return null
        return Described(
            host, port, addresses, dns, allowed,
            everything ?: return null, preshared ?: return null, mtu ?: return null, keepalive, only, except,
        )
    }

    /** A refusal as the engine writes it: `code`, then `line N` and the key where there are. */
    fun refusal(text: String): Refused {
        val words = text.trim().split(' ').filter { it.isNotEmpty() }
        val code = words.firstOrNull().orEmpty()
        return if (words.getOrNull(1) == "line") {
            Refused(code, words.getOrNull(2)?.toIntOrNull(), words.getOrNull(3))
        } else {
            Refused(code, null, words.getOrNull(1))
        }
    }

    /**
     * The choice of apps the configuration proposes, for the user to confirm or change, never applied silently (W7,
     * part 2; fix round, screens review M2 and m2), read once the apps the user can choose are loaded:
     * - [proposed]: the apps the file names in `IncludedApplications` that the user can choose, in the file's order,
     *   or with `ExcludedApplications` every app the user can choose but those, in the list's order; the screen lists
     *   them first, each with its way now;
     * - [ticked]: those of them that go directly now; one that goes through the tool or another configuration, or
     *   waits for a removed one, is not ticked, and the screen says where it moves from if the user ticks it;
     * - [excluded]: with `ExcludedApplications`, the apps it leaves out that the user has, which the screen names;
     * - [notInstalled], [notChoosable] (installed but not among the apps the user can choose, as an app with no icon
     *   to open it, or the user's tool) and [leftOut] (left out of the network part), each said apart.
     * The network part itself is never in any of them.
     */
    data class Proposal(
        val proposed: List<String>,
        val ticked: Set<String>,
        val excluded: List<String>,
        val notInstalled: List<String>,
        val notChoosable: List<String>,
        val leftOut: List<String>,
    )

    /**
     * [choosable]: the apps the user can choose, in the screen's order, the network part and the apps left out of it
     * not among them; [installed] asks Android whether a package is installed at all; [goesDirectly] whether an app
     * goes directly now, neither through the tool nor through a configuration nor waiting for one.
     */
    fun propose(
        described: Described,
        choosable: List<String>,
        self: String,
        leftOut: Set<String>,
        installed: (String) -> Boolean,
        goesDirectly: (String) -> Boolean,
    ): Proposal {
        val choices = choosable.filter { it != self && it !in leftOut }
        val named = (described.only + described.except).distinct().filter { it != self }
        val proposed = when {
            described.only.isNotEmpty() -> described.only.distinct().filter { it in choices }
            described.except.isNotEmpty() -> choices.filter { it !in described.except }
            else -> emptyList()
        }
        val outside = named.filter { it !in choices }
        return Proposal(
            proposed = proposed,
            ticked = proposed.filter(goesDirectly).toSet(),
            excluded = described.except.distinct().filter { it in choices },
            notInstalled = outside.filter { it !in leftOut && !installed(it) },
            notChoosable = outside.filter { it !in leftOut && installed(it) },
            leftOut = outside.filter { it in leftOut },
        )
    }

    /**
     * The name a configuration gets before the user changes it: the file's own, without `.conf`, or else the
     * first "[default] N" no other configuration has.
     */
    fun defaultName(fileName: String?, default: (Int) -> String, taken: Collection<String>): String {
        val fromFile = fileName?.substringAfterLast('/')
            ?.let { if (it.endsWith(".conf", ignoreCase = true)) it.dropLast(5) else it }
            ?.let(TunnelStore::cleanName)
            ?.takeIf { it.isNotEmpty() }
        if (fromFile != null) return fromFile
        return generateSequence(1) { it + 1 }.map(default).first { it !in taken }
    }

    /**
     * A configuration on its way to the store, held by the network process alone, never in a saved state that Android
     * would copy out of the process: its bytes, zeroed by [close] once it is saved or cancelled.
     */
    class Pending(text: ByteArray, val described: Described, val name: String) : AutoCloseable {
        private var held: ByteArray? = text

        /** The text, while it is held. */
        val text: ByteArray? get() = held

        override fun close() {
            held?.fill(0)
            held = null
        }
    }

    /**
     * Where the network screen keeps the configuration on its way while the confirmation is open (fix round, screens
     * review M1): it survives the screen's recreation for a rotation, a dark-mode switch or a font change, and its
     * bytes are zeroed when another takes its place, when it is dropped (cancel, or the screen finishing), and by
     * whoever [take]s it to save it.
     */
    class Held {
        private var pending: Pending? = null

        /** The configuration held, if any. */
        val now: Pending? get() = pending

        /** Holds [next], zeroing the one it replaces. */
        fun hold(next: Pending) {
            if (pending !== next) pending?.close()
            pending = next
        }

        /** Hands the configuration over to be saved, which zeroes it once done; nothing is held after. */
        fun take(): Pending? = pending.also { pending = null }

        /** Zeroes the configuration held, if any. */
        fun drop() {
            pending?.close()
            pending = null
        }
    }
}
