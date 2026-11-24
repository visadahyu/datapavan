package org.visadahyu.datapavan.network.dns

import java.io.DataInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket

/**
 * DNS over TLS (RFC 7858) for the user's DoT resolver and the presets: one connection per server, kept while
 * queries come and closed after [Exchanger.IDLE_SECONDS] idle, several queries on it at once, each under an ID of
 * its own on that connection, matched back by it and returned with ID 0 as the engine sent it. Android's own TLS
 * ([SSLContext] over [SystemTrust]), the server's name checked as Android checks a web server's, its pins where the
 * dataset gives them.
 *
 * A change of the network beneath ([closeAll]) does no I/O on its caller's thread, the main one, where Android forbids
 * it: a TLS socket's close writes its close_notify. The connections are taken out and marked closed at once, and their
 * sockets closed on [work]. A connection is used only on the network it was opened on ([generation], read before its
 * socket is made): one whose network changed while it was opened is closed unused, and the exchanges that waited for it
 * are asked on the network now. One open at a time per server, each address bounded by [Exchanger.CONNECT_MS] for its
 * TCP connect and [Exchanger.CALL_MS] for its whole TLS handshake: a server, or a censor, that takes TCP and never
 * answers the ClientHello, or trickles its answer, holds one thread for that long per address, never one per lookup for
 * ever. A query that a change (or the idle timer) cut is asked once more on a fresh connection, on the network now:
 * every outcome the engine knows counts in its ladder, so a refusal from the network before, read after the engine
 * started afresh on the new one, would hold DoT there.
 */
internal class DotClient(
    private val socketFor: (Exchanger.Through?) -> Socket,
    private val sslFor: () -> SSLContext,
    private val timers: ScheduledExecutorService,
    private val work: ExecutorService,
    private val replies: (Long, Int, ByteArray?) -> Unit,
    /** The network beneath's generation now ([Exchanger.Host.generation]). */
    private val generation: () -> Int,
) {
    /** The connections that take queries, by [Exchange.key]: only ones opened on the network beneath now. */
    private val connections = ConcurrentHashMap<String, Connection>()

    /** The opens in flight, one per key, each with the exchanges that wait for it. Under [lock] only. */
    private val opens = HashMap<String, Open>()

    /** Every open that runs, those [closeAll] withdrew included: for the debug builds' dump. */
    private val opening = AtomicInteger()

    /** Guards [opens] and what goes into [connections]. Never held across I/O: [closeAll] takes it on the main one. */
    private val lock = Any()
    private val random = SecureRandom()

    /**
     * Asks [query] of `server:port` at [addresses], with [pins] (none: Android's roots alone), directly or through
     * [through]; the reply goes to [Engine.nativeExchanged]. A connection serves only exchanges with the same addresses
     * and pins (W8's fix round: a resolver of the user's on a preset's host never takes that preset's pins away).
     */
    fun ask(ticket: Long, server: String, port: Int, addresses: List<InetAddress>, pins: List<String>, through: Exchanger.Through?, query: ByteArray) {
        if (query.size < 12) return reply(ticket, Exchanger.REFUSED, null)
        val exchange = Exchange(ticket, server, port, addresses, pins, through, query, again = true)
        work.execute { carry(exchange) }
    }

    /**
     * Closes every connection: the network beneath changed, or ([again] false) the service stopped. Nothing here does
     * I/O, since the network's callbacks call it on the main thread: each connection is taken out and marked, key by
     * key, so that no exchange takes it after this, and the sockets are closed on [work]. Their readers then answer the
     * queries they still wait for: with [again], each is asked once more on a fresh connection. An open in flight is
     * withdrawn: the connection it brings is closed unused, and the exchanges that waited for it are asked once more
     * with [again], refused without.
     */
    fun closeAll(again: Boolean = true) {
        val closing = mutableListOf<Connection>()
        synchronized(lock) {
            for (key in connections.keys) {
                connections.remove(key)?.let {
                    it.mark(again)
                    closing += it
                }
            }
            opens.values.forEach { it.again = again }
            opens.clear()
        }
        if (closing.isNotEmpty()) work.execute { closing.forEach { it.shut() } }
    }

    /** The debug builds' dump: the connections that take queries, and the opens in flight. */
    fun counts(): Pair<Int, Int> = connections.values.count { it.open } to opening.get()

    /** [exchange] on the connection for its key, or on the one being opened for it, or on one it opens. On [work]. */
    private fun carry(exchange: Exchange) {
        // Read before any socket is made, which binds to the network beneath now (the service changes that first).
        val now = generation()
        var started: Open? = null
        val kept = synchronized(lock) {
            connections[exchange.key]?.takeIf { it.open } ?: run {
                val inFlight = opens[exchange.key]
                if (inFlight != null) {
                    // One open per server at a time: this exchange goes on what it brings, or fails as it does.
                    inFlight.waiting += exchange
                } else {
                    started = Open(now, exchange).also { opens[exchange.key] = it }
                }
                null
            }
        }
        if (kept != null) return send(kept, exchange)
        started?.let { open(exchange.key, it) }
    }

    /** [exchange] on [connection]: one that closed before the query went out opens a fresh connection, once. */
    private fun send(connection: Connection, exchange: Exchange) {
        if (connection.send(exchange)) return
        if (exchange.again) carry(exchange.once()) else reply(exchange.ticket, Exchanger.REFUSED, null)
    }

    /** Opens [open]'s connection, then hands it every exchange that waited, or how it failed. */
    private fun open(key: String, open: Open) {
        var outcome = Exchanger.REFUSED
        var tls: SSLSocket? = null
        var made: Connection? = null
        opening.incrementAndGet()
        try {
            tls = connect(open.first)
            made = Connection(key, tls)
        } catch (e: IOException) {
            outcome = Exchanger.outcomeOf(e)
        } catch (e: RuntimeException) {
            // Whatever failed, the exchanges that wait get an answer and the key is free for the next open.
        } finally {
            opening.decrementAndGet()
            if (made == null) {
                try {
                    tls?.close()
                } catch (_: IOException) {
                }
            }
        }
        val connection = made
        val now = generation()
        val (waiting, keep) = synchronized(lock) {
            // Kept only if no closeAll() withdrew it and the network is still the one it was opened on.
            val ours = opens[key] === open
            if (ours) opens.remove(key)
            val keep = ours && now == open.generation
            if (keep && connection != null) connections[key] = connection
            open.waiting.toList() to keep
        }
        if (connection != null && keep) {
            waiting.forEach { send(connection, it) }
            return
        }
        // Not kept (withdrawn by a change, or the network changed meanwhile): what it brought is of the network before,
        // so it is closed unused, here on [work], and each exchange that waited is asked once more on the network now.
        // So is each one of an open that failed there. The service's stop withdrew it: nothing is asked again.
        connection?.shut()
        val failed = if (connection != null) Exchanger.REFUSED else outcome
        for (waiter in waiting) {
            if (!keep && open.again && waiter.again) work.execute { carry(waiter.once()) } else reply(waiter.ticket, failed, null)
        }
    }

    private fun connect(exchange: Exchange): SSLSocket {
        var last = IOException("no address in the data pack")
        for (address in exchange.addresses) {
            val raw = socketFor(exchange.through)
            val expired = AtomicBoolean(false)
            var deadline: ScheduledFuture<*>? = null
            try {
                raw.connect(InetSocketAddress(address, exchange.port), Exchanger.CONNECT_MS.toInt())
                // The whole handshake bounded, not only each of its reads: a peer that trickles its flight, each read
                // short of the timeout, is cut too. Closing the plain socket beneath writes no TLS record.
                deadline = timers.schedule({
                    expired.set(true)
                    close(raw)
                }, Exchanger.CALL_MS, TimeUnit.MILLISECONDS)
                val tls = sslFor().socketFactory.createSocket(raw, exchange.server, exchange.port, true) as SSLSocket
                // The certificate must name the server, as a web server's must (RFC 6125), checked in the handshake.
                tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                // Each read bounded as the tool's SOCKS handshake is (ToolSocket), then the connection waits for
                // answers as long as it is kept.
                tls.soTimeout = Exchanger.CALL_MS.toInt()
                tls.startHandshake()
                tls.soTimeout = 0
                try {
                    SystemTrust.checkPins(tls.session.peerCertificates.filterIsInstance<X509Certificate>(), exchange.pins)
                } catch (e: java.security.cert.CertificateException) {
                    throw SSLPeerUnverifiedException(e.message)
                }
                // Too late if the deadline already ran: its close may have cut the socket just now.
                if (!deadline.cancel(false)) throw SocketTimeoutException("TLS handshake over its time")
                return tls
            } catch (e: IOException) {
                deadline?.cancel(false)
                // The deadline's close fails the handshake as a closed socket, which TLS may report as an alert: it
                // reads as what it is, a timeout, never as tampering.
                last = if (expired.get()) SocketTimeoutException("TLS handshake over its time") else e
                close(raw)
            }
        }
        throw last
    }

    private fun close(socket: Socket) {
        try {
            socket.close()
        } catch (_: IOException) {
        }
    }

    /** One exchange of the engine's: where it goes, and whether it may still be asked on a fresh connection. */
    private class Exchange(
        val ticket: Long,
        val server: String,
        val port: Int,
        val addresses: List<InetAddress>,
        val pins: List<String>,
        val through: Exchanger.Through?,
        val query: ByteArray,
        val again: Boolean,
    ) {
        val key = "$server $port ${through?.proxy} $addresses $pins"

        fun once() = Exchange(ticket, server, port, addresses, pins, through, query, again = false)
    }

    /** An open in flight, begun on the network of [generation] for [first], and the exchanges that wait for it. */
    private class Open(val generation: Int, val first: Exchange) {
        val waiting = mutableListOf(first)

        /** False once a closeAll() of the service's stop withdrew it: none of its exchanges is asked again. */
        @Volatile
        var again = true
    }

    /** A query sent on a connection and its timer. */
    private class Waiting(val exchange: Exchange) {
        @Volatile
        var timer: ScheduledFuture<*>? = null
    }

    /** One DoT connection and its reader. */
    private inner class Connection(private val key: String, private val socket: SSLSocket) {
        /** Takes queries. Once false, never again. */
        @Volatile
        var open = true
            private set

        /** Set when this side closed it (a change, the idle timer): the queries it still waits for are asked again. */
        @Volatile
        private var again = false

        private val output: OutputStream = socket.outputStream
        private val waiting = ConcurrentHashMap<Int, Waiting>()
        private var idle: ScheduledFuture<*>? = null

        init {
            work.execute(::read)
            rearm()
        }

        /**
         * Sends [exchange]'s query; false when the connection no longer takes queries and the query did not go out.
         * It is registered before the connection is checked: a close that marks it meanwhile either finds the query
         * waiting and answers it, or this finds the connection closed and takes it back.
         */
        fun send(exchange: Exchange): Boolean {
            val entry = Waiting(exchange)
            var id: Int
            do {
                id = random.nextInt(0x10000)
            } while (waiting.putIfAbsent(id, entry) != null)
            if (!open) return !waiting.remove(id, entry)
            val sent = id
            entry.timer = timers.schedule({
                if (waiting.remove(sent, entry)) reply(exchange.ticket, Exchanger.TIMEOUT, null)
            }, Exchanger.CALL_MS, TimeUnit.MILLISECONDS)
            val query = exchange.query
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
                if (waiting.remove(id, entry)) settle(entry, Exchanger.outcomeOf(e))
                shut()
            }
            return true
        }

        /** Takes no more queries: no I/O, for [closeAll] on the main thread. [again]: what waits is asked again. */
        fun mark(again: Boolean) {
            // Before [open]: whoever sees the connection closed sees why.
            this.again = again
            open = false
            synchronized(this) { idle?.cancel(false) }
        }

        /** Closes the socket, which writes TLS's close_notify: on [work] or the reader's thread, never the main one. */
        fun shut() {
            open = false
            connections.remove(key, this)
            synchronized(this) { idle?.cancel(false) }
            try {
                socket.close()
            } catch (_: IOException) {
            }
        }

        private fun read() {
            var outcome = Exchanger.REFUSED
            try {
                val input = DataInputStream(socket.inputStream)
                while (true) {
                    val length = input.readUnsignedShort()
                    val answer = ByteArray(length)
                    input.readFully(answer)
                    if (length < 2) continue
                    val id = ((answer[0].toInt() and 0xff) shl 8) or (answer[1].toInt() and 0xff)
                    val entry = waiting.remove(id) ?: continue
                    entry.timer?.cancel(false)
                    answer[0] = 0
                    answer[1] = 0
                    reply(entry.exchange.ticket, Exchanger.ANSWER, answer)
                    rearm()
                }
            } catch (e: IOException) {
                outcome = Exchanger.outcomeOf(e)
            } finally {
                // However the loop ended: nothing more is read, and each query still waiting is answered once, taken
                // out one at a time, so that its timer, a send that failed or this never answer it twice or drop it.
                shut()
                for (id in waiting.keys.toList()) waiting.remove(id)?.let { settle(it, outcome) }
            }
        }

        /** Answers [entry] with [outcome], or asks it once more on a fresh connection where this side closed it. */
        private fun settle(entry: Waiting, outcome: Int) {
            entry.timer?.cancel(false)
            val exchange = entry.exchange
            if (again && exchange.again) work.execute { carry(exchange.once()) } else reply(exchange.ticket, outcome, null)
        }

        /** Closes the connection after [Exchanger.IDLE_SECONDS] with nothing sent or received. */
        @Synchronized
        private fun rearm() {
            if (!open) return
            idle?.cancel(false)
            idle = timers.schedule(Runnable { idleOut() }, Exchanger.IDLE_SECONDS, TimeUnit.SECONDS)
        }

        private fun idleOut() {
            if (!open) return
            if (waiting.isNotEmpty()) return rearm()
            // As a change closes it: a query that raced the timer onto it is asked again on a fresh one.
            connections.remove(key, this)
            mark(again = true)
            work.execute(::shut)
        }
    }

    private fun reply(ticket: Long, outcome: Int, body: ByteArray?) = replies(ticket, outcome, body)
}
