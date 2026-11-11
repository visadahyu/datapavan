package org.visadahyu.datapavan.watch.chain

import android.content.pm.PackageManager
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

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
    private val packages: PackageManager,
    private val table: List<KnownTool>,
    /** Android's owner of the TCP connection from `local` to `remote`, or null when it cannot say. */
    private val ownerOf: (local: InetSocketAddress, remote: InetSocketAddress) -> Int?,
    /** The Android user Watch runs in: some tools add its number to their port (0 in the main user). */
    private val userId: Int,
) {
    /** Searches once. */
    fun search(): ToolSearch {
        val installed = table.filter { it.proxyMode && it.socksListeners.isNotEmpty() }.mapNotNull { tool ->
            uidOf(tool.packageName)?.let { tool to it }
        }
        if (installed.isEmpty()) return ToolSearch.NoneInstalled
        val tools = installed.map { it.first }
        for ((tool, uid) in installed) {
            val found = probe(tool, uid) ?: continue
            return ToolSearch.Answering(found, tools)
        }
        return ToolSearch.NotAnswering(tools)
    }

    @Suppress("DEPRECATION")
    private fun uidOf(packageName: String): Int? = try {
        packages.getApplicationInfo(packageName, 0).uid
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    /** Greets the tool's known ports, in the main user's numbering and shifted by the user's number. */
    fun probe(tool: KnownTool, uid: Int): FoundTool? {
        for (listener in tool.socksListeners) {
            for (port in listOf(listener.port, listener.port + userId).distinct().filter { it in 1..65535 }) {
                val answer = greet(listener.host, port) ?: continue
                val owner = answer.owner
                // Another app holds the port: it is not this tool's proxy.
                if (owner != null && owner != uid) continue
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
     */
    private fun greet(host: String, port: Int): Greeting? = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(host, port), CONNECT_MS)
            // Asked at once, while the other end is surely open: a proxy that refuses the greeting
            // closes it, and a closed connection has no owner left to name.
            val owner = ownerOf(socket.remoteSocketAddress as InetSocketAddress, socket.localSocketAddress as InetSocketAddress)
            socket.soTimeout = READ_MS
            socket.getOutputStream().apply {
                write(byteArrayOf(5, 1, 0))
                flush()
            }
            val input = socket.getInputStream()
            val version = input.read()
            val method = input.read()
            if (version != 5 || method !in listOf(0, 0xff)) return null
            Greeting(owner = owner, needsPassword = method == 0xff)
        }
    } catch (e: IOException) {
        null
    }

    private companion object {
        const val CONNECT_MS = 300
        const val READ_MS = 500
    }
}
