package org.visadahyu.datapavan.watch.chain

/** A local proxy a tool opens with its default settings: `socks5`, `http` or `mixed` (both on one port). */
data class Listener(val protocol: String, val host: String, val port: Int) {
    /** Whether it speaks SOCKS5, which W6 chains through. */
    val socks: Boolean get() = protocol == "socks5" || protocol == "mixed"
}

/**
 * One tool of the table (`data/tools/tools.tsv`, W6): how it runs on Android. A value the research
 * could not settle carries a `?` in the table and is read as the best guess; a value it could not
 * guess at all is null.
 */
data class KnownTool(
    val packageName: String,
    val name: String,
    /** It runs without Android's VPN and serves a local proxy. */
    val proxyMode: Boolean,
    val listeners: List<Listener>,
    /** `none`, `optional` or `default`: whether a SOCKS5 username and password can be set. */
    val auth: String?,
    /** Its SOCKS5 proxy carries UDP (`UDP ASSOCIATE`) with default settings. */
    val udp: Boolean?,
    /** Its SOCKS5 proxy takes host names, which ADR 0038 needs. */
    val names: Boolean?,
) {
    /** The listeners Watch may greet: SOCKS5 ones only, on the loopback. */
    val socksListeners: List<Listener> get() = listeners.filter { it.socks }
}

/** Reads the table of tools as `data/tools/tools.tsv` holds it. */
object ToolTable {
    /** The asset the build copies the table to (build.gradle.kts, `ToolTable`). */
    const val ASSET = "tools.tsv"

    private val protocols = setOf("socks5", "http", "mixed")
    private val authValues = setOf("none", "optional", "default")

    /** Every row with its columns; comments, blank and short lines are skipped. */
    fun parse(text: String): List<KnownTool> = text.lineSequence()
        .filter { it.isNotBlank() && !it.startsWith("#") }
        .map { it.split('\t') }
        .filter { it.size >= 9 }
        .map { c ->
            KnownTool(
                packageName = c[0],
                name = c[1],
                proxyMode = "proxy" in c[2].split(',').map { it.removeSuffix("?") },
                listeners = listeners(c[4]),
                auth = c[6].removeSuffix("?").takeIf { it in authValues },
                udp = flag(c[7]),
                names = flag(c[8]),
            )
        }
        .toList()

    private fun flag(value: String): Boolean? = when (value.removeSuffix("?")) {
        "yes" -> true
        "no" -> false
        else -> null
    }

    /**
     * The `proxy` column: `protocol:address:port` entries, comma separated, the address `127.0.0.1`,
     * `0.0.0.0` (reached here at the loopback) or `[::1]`. `profile`, `unknown` and `-` give none.
     */
    fun listeners(cell: String): List<Listener> = cell.split(',').mapNotNull { entry ->
        val value = entry.trim().removeSuffix("?")
        val protocol = value.substringBefore(':')
        val rest = value.substringAfter(':', "")
        val port = rest.substringAfterLast(':', "").toIntOrNull()
        val host = rest.substringBeforeLast(':', "").removePrefix("[").removeSuffix("]")
        when {
            protocol !in protocols || port == null || port !in 1..65535 || host.isEmpty() -> null
            host == "0.0.0.0" -> Listener(protocol, "127.0.0.1", port)
            else -> Listener(protocol, host, port)
        }
    }
}
