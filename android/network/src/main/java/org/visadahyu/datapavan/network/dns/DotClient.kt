package org.visadahyu.datapavan.network.dns

import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket

/**
 * DNS over TLS (RFC 7858) for the user's DoT resolver and the presets: one connection per server, kept while
 * queries come and closed after [Exchanger.IDLE_SECONDS] idle, several queries on it at once, each under an ID of
 * its own on that connection, matched back by it and returned with ID 0 as the engine sent it. Android's own TLS
 * ([SSLContext] over [SystemTrust]), the server's name checked as Android checks a web server's, its pins where the
 * dataset gives them.
 */
internal class DotClient(
    private val socketFor: (Exchanger.Through?) -> Socket,
    private val sslFor: () -> SSLContext,
    private val timers: ScheduledExecutorService,
    private val work: ExecutorService,
    private val replies: (Long, Int, ByteArray?) -> Unit,
) {
    private val connections = ConcurrentHashMap<String, Connection>()
    private val random = SecureRandom()

    /**
     * Asks [query] of `server:port` at [addresses], with [pins] (none: Android's roots alone), directly or through
     * [through]; the reply goes to [Engine.nativeExchanged]. A connection serves only exchanges with the same addresses
     * and pins (W8's fix round: a resolver of the user's on a preset's host never takes that preset's pins away).
     */
    fun ask(ticket: Long, server: String, port: Int, addresses: List<InetAddress>, pins: List<String>, through: Exchanger.Through?, query: ByteArray) {
        if (query.size < 12) return reply(ticket, Exchanger.REFUSED, null)
        work.execute {
            val key = "$server $port ${through?.proxy} $addresses $pins"
            val connection = try {
                connections[key]?.takeIf { it.open } ?: open(server, port, addresses, pins, through).also { connections[key] = it }
            } catch (e: IOException) {
                return@execute reply(ticket, Exchanger.outcomeOf(e), null)
            }
            connection.send(ticket, query)
        }
    }

    /** Closes every connection: the network beneath changed. */
    fun closeAll() {
        connections.values.forEach { it.close() }
        connections.clear()
    }

    private fun open(server: String, port: Int, addresses: List<InetAddress>, pins: List<String>, through: Exchanger.Through?): Connection {
        var last: IOException = IOException("no address in the data pack")
        for (address in addresses) {
            val raw = socketFor(through)
            try {
                raw.connect(InetSocketAddress(address, port), Exchanger.CONNECT_MS.toInt())
                val tls = sslFor().socketFactory.createSocket(raw, server, port, true) as SSLSocket
                // The certificate must name the server, as a web server's must (RFC 6125), checked in the handshake.
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                tls.soTimeout = 0
                tls.startHandshake()
                try {
                    SystemTrust.checkPins(tls.session.peerCertificates.filterIsInstance<X509Certificate>(), pins)
                } catch (e: java.security.cert.CertificateException) {
                    throw SSLPeerUnverifiedException(e.message)
                }
                return Connection(tls)
            } catch (e: IOException) {
                last = e
                try {
                    raw.close()
                } catch (_: IOException) {
                }
            }
        }
        throw last
    }

    /** One DoT connection and its reader. */
    private inner class Connection(private val socket: SSLSocket) {
        @Volatile
        var open = true
            private set

        private val output: OutputStream = socket.outputStream
        private val waiting = ConcurrentHashMap<Int, Pair<Long, ScheduledFuture<*>>>()
        private var idle: ScheduledFuture<*>? = null

        init {
            work.execute(::read)
            rearm()
        }

        fun send(ticket: Long, query: ByteArray) {
            var id: Int
            do {
                id = random.nextInt(0x10000)
            } while (waiting.containsKey(id))
            val timer = timers.schedule({
                if (waiting.remove(id) != null) reply(ticket, Exchanger.TIMEOUT, null)
            }, Exchanger.CALL_MS, TimeUnit.MILLISECONDS)
            waiting[id] = ticket to timer
            val framed = ByteArray(query.size + 2)
            framed[0] = (query.size shr 8).toByte()
            framed[1] = query.size.toByte()
            System.arraycopy(query, 0, framed, 2, query.size)
            framed[2] = (id shr 8).toByte()
            framed[3] = id.toByte()
            try {
                synchronized(output) {
                    output.write(framed)
                    output.flush()
                }
                rearm()
            } catch (e: IOException) {
                waiting.remove(id)?.second?.cancel(false)
                reply(ticket, Exchanger.outcomeOf(e), null)
                close()
            }
        }

        private fun read() {
            val input = DataInputStream(socket.inputStream)
            try {
                while (open) {
                    val length = input.readUnsignedShort()
                    val answer = ByteArray(length)
                    input.readFully(answer)
                    if (length < 2) continue
                    val id = ((answer[0].toInt() and 0xff) shl 8) or (answer[1].toInt() and 0xff)
                    val (ticket, timer) = waiting.remove(id) ?: continue
                    timer.cancel(false)
                    answer[0] = 0
                    answer[1] = 0
                    reply(ticket, Exchanger.ANSWER, answer)
                    rearm()
                }
            } catch (e: IOException) {
                val outcome = Exchanger.outcomeOf(e)
                waiting.values.forEach { (ticket, timer) ->
                    timer.cancel(false)
                    reply(ticket, outcome, null)
                }
                waiting.clear()
            } finally {
                close()
            }
        }

        /** Closes the connection after [Exchanger.IDLE_SECONDS] with nothing sent or received. */
        @Synchronized
        private fun rearm() {
            idle?.cancel(false)
            idle = timers.schedule({ if (waiting.isEmpty()) close() else rearm() }, Exchanger.IDLE_SECONDS, TimeUnit.SECONDS)
        }

        fun close() {
            open = false
            try {
                socket.close()
            } catch (_: IOException) {
            }
        }
    }

    private fun reply(ticket: Long, outcome: Int, body: ByteArray?) = replies(ticket, outcome, body)
}
