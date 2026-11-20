package org.visadahyu.datapavan.watch.tunnel

/**
 * The import of a WireGuard configuration (W7, part 2): what the engine's parser says of it
 * ([org.visadahyu.datapavan.watch.Engine.nativeTunnelParse]), read into what the confirmation shows before anything
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
     * The choice of apps the configuration proposes, for the user to confirm or change, never applied silently:
     * from `IncludedApplications`, those of them installed; from `ExcludedApplications`, every app the user can
     * choose but those; with neither, none. Watch itself and the apps left out of Watch are never in it. The apps
     * it names that are not installed are listed as such.
     */
    data class Proposal(val apps: Set<String>, val notInstalled: List<String>)

    fun propose(described: Described, choosable: Collection<String>, self: String, leftOut: Set<String>): Proposal {
        val installed = choosable.toSet() - self - leftOut
        return when {
            described.only.isNotEmpty() -> Proposal(
                described.only.filter { it in installed }.toSet(),
                described.only.filter { it !in choosable && it != self },
            )
            described.except.isNotEmpty() -> Proposal(
                installed - described.except.toSet(),
                described.except.filter { it !in choosable && it != self },
            )
            else -> Proposal(emptySet(), emptyList())
        }
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
     * A configuration on its way to the store, held by Watch's process alone, never in a saved state that Android
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
}
