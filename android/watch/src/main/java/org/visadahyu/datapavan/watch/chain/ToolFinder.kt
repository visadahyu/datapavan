package org.visadahyu.datapavan.watch.chain

import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/** A tool whose SOCKS5 proxy answered on the phone. */
data class FoundTool(
    val tool: KnownTool,
    /** The tool's UID: its own traffic goes directly (W6). */
    val uid: Int,
    val host: String,
    val port: Int,
    /** The proxy refused Watch's greeting without a password: the user set one in the tool. */
    val needsPassword: Boolean,
    /**
     * Whether Android named the tool as the owner of the port: true, false (another app listens there,
     * so it is not this tool), or null when Android could not say, as when Watch is not the active VPN.
     */
    val ownerConfirmed: Boolean?,
)

/** What Watch found of the user's tools. */
sealed interface ToolSearch {
    /** No tool of the table with a proxy mode is installed. */
    data object NoneInstalled : ToolSearch

    /** Tools are installed, but none answers on its known ports: none runs in proxy mode now. */
    data class NotAnswering(val installed: List<KnownTool>) : ToolSearch

    /** A tool's proxy answered. */
    data class Answering(val found: FoundTool, val installed: List<KnownTool>) : ToolSearch
}

/**
 * Finds the user's tool by itself (W6): the installed apps of the table that have a proxy mode, a
 * SOCKS5 greeting on their known ports only, and the port's owner asked of Android. A port alone is
 * only a hint, since several tools share one (docs/spikes/2026-11-table-of-tools.md). Blocking: call it
 * off the main thread.
 */
class ToolFinder(
    /** An installed app's UID, or null when it is not installed (Tools.search asks the PackageManager). */
    private val uidOf: (packageName: String) -> Int?,
    private val table: List<KnownTool>,
    /** Android's owner of the TCP connection from `local` to `remote`, or null when it cannot say. */
    private val ownerOf: (local: InetSocketAddress, remote: InetSocketAddress) -> Int?,
    /** The Android user Watch runs in: some tools add its number to their port (0 in the main user). */
    private val userId: Int,
    /**
     * Why a port was passed over, and what the search found, for debug builds' log (Tools.search):
     * the screen's search sometimes missed a tool that answered the service's (CI, 2026-11-11 and 12),
     * and these lines say which step failed. They name tools, ports and UIDs, never a password.
     */
    private val note: (String) -> Unit = {},
) {
    /** Searches once. */
    fun search(): ToolSearch {
        val installed = table.filter { it.proxyMode && it.socksListeners.isNotEmpty() }.mapNotNull { tool ->
            uidOf(tool.packageName)?.let { tool to it }
        }
        if (installed.isEmpty()) return ToolSearch.NoneInstalled.also { note("none installed") }
        val tools = installed.map { it.first }
        for ((tool, uid) in installed) {
            val found = probe(tool, uid) ?: continue
            note("answering ${tool.packageName} ${found.host}:${found.port} owner ${found.ownerConfirmed}")
            return ToolSearch.Answering(found, tools)
        }
        note("not answering: ${tools.joinToString(" ") { it.packageName }}")
        return ToolSearch.NotAnswering(tools)
    }

    /** Greets the tool's known ports, in the main user's numbering and shifted by the user's number. */
    fun probe(tool: KnownTool, uid: Int): FoundTool? {
        for (listener in tool.socksListeners) {
            for (port in listOf(listener.port, listener.port + userId).distinct().filter { it in 1..65535 }) {
                val answer = greet(listener.host, port) ?: continue
                val owner = answer.owner
                // Another app holds the port: it is not this tool's proxy.
                if (owner != null && owner != uid) {
                    note("${tool.packageName} ${listener.host}:$port: held by UID $owner, not the tool's $uid")
                    continue
                }
                return FoundTool(
                    tool = tool,
                    uid = uid,
                    host = listener.host,
                    port = port,
                    needsPassword = answer.needsPassword,
                    ownerConfirmed = owner?.let { it == uid },
                )
            }
        }
        return null
    }

    private class Greeting(val owner: Int?, val needsPassword: Boolean)

    /**
     * A SOCKS5 greeting offering no authentication (RFC 1928): a proxy answers version 5 and the method
     * it chose, or "no acceptable method" when it wants a password. Anything else is not a SOCKS5 proxy.
     * A phone busy starting apps can be slow to answer even on its own loopback (CI, 2026-11-11: the first
     * search sometimes missed a proxy that the next one found), so a greeting that times out is tried
     * once more. A refused connection is not: nothing listens there.
     */
    private fun greet(host: String, port: Int): Greeting? {
        repeat(ATTEMPTS - 1) { attempt ->
            try {
                return greetOnce(host, port)
            } catch (e: SocketTimeoutException) {
                // Slow, not absent: once more.
                note("$host:$port: timed out, attempt ${attempt + 1}")
            } catch (e: IOException) {
                note("$host:$port: ${e.javaClass.simpleName}")
                return null
            }
        }
        return try {
            greetOnce(host, port)
        } catch (e: IOException) {
            note("$host:$port: ${e.javaClass.simpleName}, attempt $ATTEMPTS")
            null
        }
    }

    private fun greetOnce(host: String, port: Int): Greeting? =
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), CONNECT_MS)
            val tool = socket.remoteSocketAddress as InetSocketAddress
            val watch = socket.localSocketAddress as InetSocketAddress
            // Asked at once, while the other end is surely open: a proxy that refuses the greeting
            // closes it, and a closed connection has no owner left to name.
            val early = ownerOf(tool, watch)
            socket.soTimeout = READ_MS
            socket.getOutputStream().apply {
                write(byteArrayOf(5, 1, 0))
                flush()
            }
            val input = socket.getInputStream()
            val version = input.read()
            val method = input.read()
            if (version != 5 || method !in listOf(0, 0xff)) {
                note("$host:$port: not a SOCKS5 answer ($version $method)")
                return null
            }
            // Just after connect() returns, the tool's end may still be half-open in the kernel, and a
            // half-open or closing end names no owner: Android then says root (CI, 2026-11-12: "held by
            // UID 0" for the test tool). Once the tool has answered, its end is surely its own: asked again.
            val owner = known(early) ?: known(ownerOf(tool, watch)).also {
                if (early == ROOT) note("$host:$port: no owner at once (UID 0), then ${it ?: "none"}")
            }
            Greeting(owner = owner, needsPassword = method == 0xff)
        }

    private companion object {
        const val CONNECT_MS = 1_000
        const val READ_MS = 1_500
        const val ATTEMPTS = 2

        /** The UID the kernel's socket lookup (inet_diag) gives a half-open or TIME_WAIT end: root's. */
        const val ROOT = 0

        /**
         * An owner Android named, or null when it could not say. Root is not an owner: no app runs as
         * root, and the lookup gives root for an end that is not, or no longer, a socket of its own.
         */
        fun known(owner: Int?): Int? = owner?.takeIf { it != ROOT }
    }
}
