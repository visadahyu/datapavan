package org.visadahyu.datapavan.watch.dns

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException

/**
 * A socket that reaches its destination through the user's tool's SOCKS5 proxy (RFC 1928, with RFC 1929's password
 * where the tool asks for one): ODoH through the tool, and a chained app's question of another type than A and AAAA
 * (W8, part 1; ADR 0038). OkHttp and the DoT client connect it as any socket; [connect] speaks to the proxy first,
 * then asks it for the destination by its address, so that no name goes to the tool to resolve.
 */
class ToolSocket(private val proxy: InetSocketAddress, private val user: ByteArray?, private val password: ByteArray?) : Socket() {
    private var destination: InetSocketAddress? = null

    override fun connect(endpoint: SocketAddress?, timeout: Int) {
        val target = endpoint as? InetSocketAddress ?: throw SocketException("not an address")
        super.connect(proxy, timeout)
        soTimeout = timeout
        handshake(super.getInputStream(), super.getOutputStream(), target)
        soTimeout = 0
        destination = target
    }

    override fun connect(endpoint: SocketAddress?) = connect(endpoint, 0)

    // OkHttp and TLS read the destination's address, not the proxy's.
    override fun getInetAddress(): InetAddress? = destination?.address ?: super.getInetAddress()

    override fun getPort(): Int = destination?.port ?: super.getPort()

    private fun handshake(input: InputStream, output: OutputStream, target: InetSocketAddress) {
        val withPassword = user != null && password != null && user.isNotEmpty()
        output.write(if (withPassword) byteArrayOf(5, 2, 0, 2) else byteArrayOf(5, 1, 0))
        output.flush()
        val method = readFully(input, 2)
        if (method[0] != 5.toByte()) throw IOException("not a SOCKS5 proxy")
        when (method[1].toInt() and 0xff) {
            0 -> {}
            2 -> {
                if (!withPassword) throw IOException("the proxy wants a password")
                val u = user!!
                val p = password!!
                output.write(byteArrayOf(1, u.size.toByte()) + u + byteArrayOf(p.size.toByte()) + p)
                output.flush()
                val status = readFully(input, 2)
                if (status[1] != 0.toByte()) throw IOException("the proxy refused the password")
            }
            else -> throw IOException("the proxy accepts no method offered")
        }
        val address = target.address ?: throw IOException("no address")
        val raw = address.address
        val type: Byte = if (raw.size == 4) 1 else 4
        output.write(byteArrayOf(5, 1, 0, type) + raw + byteArrayOf((target.port shr 8).toByte(), target.port.toByte()))
        output.flush()
        val head = readFully(input, 4)
        if (head[1] != 0.toByte()) throw SocketException("the proxy answered ${head[1].toInt() and 0xff}")
        val rest = when (head[3].toInt()) {
            1 -> 4
            4 -> 16
            3 -> readFully(input, 1)[0].toInt() and 0xff
            else -> throw IOException("an unknown address type")
        }
        readFully(input, rest + 2)
    }

    private fun readFully(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var at = 0
        while (at < n) {
            val read = input.read(out, at, n - at)
            if (read < 0) throw IOException("the proxy closed")
            at += read
        }
        return out
    }
}
