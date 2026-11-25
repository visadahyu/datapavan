package org.visadahyu.datapavan.network.dns

import java.io.IOException
import java.io.InputStream
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException

/**
 * A socket that reaches its destination through the resolver's HTTP proxy ([NetworkProxy]: the network beneath's own,
 * else Android's global one), by a `CONNECT` to the destination's address (RFC 9110, 9.3.6), as [ToolSocket] does for
 * the tool's SOCKS5: the address the data pack gave, so that the proxy looks no name up and the resolver's pins and
 * addresses hold (ADR 0042). The request carries `Host` and nothing else: no `User-Agent` names the library, as
 * OkHttp's own tunnel would. Any answer but a `2xx`, and a proxy that cannot be reached within [budgetMs], is a
 * [Refused], which the exchanger reads as the proxy's refusal and answers by going directly.
 */
class ProxySocket(private val proxy: InetSocketAddress, private val budgetMs: Int) : Socket() {
    private var destination: InetSocketAddress? = null

    /** The proxy refused the tunnel, or could not be reached: [status] is its answer's code, or 0 for none. */
    class Refused(val proxy: InetSocketAddress, val status: Int, cause: Throwable? = null) :
        IOException("the proxy refused the tunnel: ${if (status == 0) "no answer" else status}", cause)

    override fun connect(endpoint: SocketAddress?, timeout: Int) {
        val target = endpoint as? InetSocketAddress ?: throw SocketException("not an address")
        val address = target.address ?: throw SocketException("no address")
        val within = if (timeout in 1 until budgetMs) timeout else budgetMs
        try {
            super.connect(proxy, within)
            soTimeout = within
            val authority = "${literal(address)}:${target.port}"
            val request = "CONNECT $authority HTTP/1.1\r\nHost: $authority\r\n\r\n"
            super.getOutputStream().apply {
                write(request.toByteArray(Charsets.US_ASCII))
                flush()
            }
            val status = status(head(super.getInputStream()))
            if (status !in 200..299) throw Refused(proxy, status)
            soTimeout = 0
        } catch (e: Refused) {
            closeQuietly()
            throw e
        } catch (e: IOException) {
            closeQuietly()
            throw Refused(proxy, 0, e)
        }
        destination = target
    }

    override fun connect(endpoint: SocketAddress?) = connect(endpoint, 0)

    // OkHttp and TLS read the destination's address, not the proxy's.
    override fun getInetAddress(): InetAddress? = destination?.address ?: super.getInetAddress()

    override fun getPort(): Int = destination?.port ?: super.getPort()

    private fun closeQuietly() {
        try {
            close()
        } catch (e: IOException) {
            // Already gone.
        }
    }

    companion object {
        /** The most bytes of the proxy's answer read before its blank line: a status line and a few headers. */
        const val MAX_HEAD = 8_192

        /** An address as a `CONNECT`'s authority writes it: an IPv6 one in brackets, never with a zone. */
        fun literal(address: InetAddress): String {
            val text = address.hostAddress.orEmpty().substringBefore('%')
            return if (address is Inet6Address) "[$text]" else text
        }

        /**
         * The proxy's answer up to and including its blank line, read a byte at a time so that nothing of the tunnel
         * after it is taken: a proxy that closes first, or sends more than [MAX_HEAD] bytes, is no answer.
         */
        fun head(input: InputStream): String {
            val out = StringBuilder()
            while (out.length < MAX_HEAD) {
                val b = input.read()
                if (b < 0) throw IOException("the proxy closed")
                out.append(b.toChar())
                if (out.endsWith("\r\n\r\n") || out.endsWith("\n\n")) return out.toString()
            }
            throw IOException("the proxy's answer is too long")
        }

        /** The code of an `HTTP/1.x` status line, or 0 when it is not one. */
        fun status(head: String): Int {
            val line = head.substringBefore('\n').trimEnd('\r')
            val parts = line.split(' ')
            if (parts.size < 2 || !parts[0].startsWith("HTTP/1.")) return 0
            return parts[1].takeIf { it.length == 3 && it.all(Char::isDigit) }?.toInt() ?: 0
        }
    }
}
