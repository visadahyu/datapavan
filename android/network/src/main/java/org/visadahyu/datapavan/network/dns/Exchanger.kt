package org.visadahyu.datapavan.network.dns

import android.net.DnsResolver
import android.net.Network
import android.os.CancellationSignal
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.net.UnknownHostException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.X509TrustManager
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.visadahyu.datapavan.network.Engine

/**
 * Carries the exchanges of Watch's encrypted resolver (W8, part 1, ADR 0042, "How it is built", point 1): the engine
 * holds no TLS, and hands each exchange here; this answers it later with [Engine.nativeExchanged], never on the
 * engine's thread. DoH and ODoH go over OkHttp, pinned, with HTTP/2; DoT over Android's own TLS; both are
 * Conscrypt, whose ClientHello is every Android app's. The network's resolver is asked through Android's own
 * resolver on the network beneath ([DnsResolver]), which keeps the phone's Private DNS as it was.
 *
 * What it sends: no `User-Agent`, no `Accept-Encoding` (compression would undo the padding), no cookie, no cache.
 * Where: every server is reached at the addresses the data pack gives ([Dns] answers only those, never a lookup),
 * from a socket protected from Watch's own tunnel and bound to the network beneath, or through the user's tool
 * ([ToolSocket]). Which certificates: Android's own roots only, never a user's or an administrator's ([SystemTrust]),
 * with the endpoint's pins where the dataset gives them, each exchange with its own addresses and pins (W8's fix
 * round). One client per network beneath, so that TLS sessions are resumed only on the network they began on; no
 * 0-RTT (Conscrypt sends no early data); connections idle for 60 s are closed and opened again on demand. Nothing of
 * an exchange runs on the caller's thread, the engine's only one (review S-m5): the clients, the TLS context and
 * Android's roots are built on [work], and [warm] builds them ahead, when the service starts and the network changes.
 */
class Exchanger(
    private val host: Host,
    /** Where each reply goes: the engine's [Engine.nativeExchanged], or a test's. */
    private val replies: (Long, Int, ByteArray?) -> Unit = { ticket, outcome, body -> Engine.nativeExchanged(ticket, outcome, body) },
    /** The certificates accepted: Android's own roots and [Host.extraRoots] ([SystemTrust]), or a test's. */
    private val given: X509TrustManager? = null,
) {
    /** What the exchanger needs of Watch's VPN service. */
    interface Host {
        /** Keeps [socket] out of Watch's own tunnel. */
        fun protect(socket: Socket): Boolean

        /** Keeps [socket] out of Watch's own tunnel: debug builds' resolver of the network, for the DNS lab. */
        fun protect(socket: java.net.DatagramSocket): Boolean = false

        /** The network beneath the tunnel, or null for none. */
        val network: Network?

        /** A number that changes with the network beneath: each has clients and TLS sessions of its own. */
        val generation: Int

        /** Debug builds: the DNS lab's test root, beside Android's; release builds: none. */
        val extraRoots: List<X509Certificate>
    }

    /** The clients: one per network beneath and tool, and from it one per server's addresses ([KnownOnly]). */
    private val clients = ConcurrentHashMap<String, OkHttpClient>()

    /**
     * Debug builds, for the DNS lab's check on an emulator that was not started on the lab's resolver, as CI's are
     * (W8's fix round, review R-M4): the network's resolver is asked here, in plain DNS over UDP from a protected
     * socket bound to the network beneath, in place of Android's resolver of that network. Null: Android's.
     */
    @Volatile
    var networkResolverForTests: InetSocketAddress? = null

    /** The screen's checks of a resolver ([probe]): their replies, by their tickets, which are negative. */
    private val probes = ConcurrentHashMap<Long, (Int, ByteArray?) -> Unit>()
    private val probeTickets = java.util.concurrent.atomic.AtomicLong(0)
    private val timers: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "watch-dns-timer").apply { isDaemon = true }
    }
    private val work = Executors.newCachedThreadPool { task -> Thread(task, "watch-dns").apply { isDaemon = true } }
    private val trust: X509TrustManager by lazy { given ?: SystemTrust.android(host.extraRoots) }
    private val dot by lazy { DotClient(::socketFor, ::sslFor, timers, work, ::reply) }

    /**
     * One exchange, as the engine hands it ([Engine]'s bridge, `Platform::exchange`): returns at once, and replies
     * later with [Engine.nativeExchanged]. [carry]: 1 ODoH, 2 DoH, 3 DoT, 4 the network, 5 a fetch of a target's
     * configurations. [addresses] by commas; [proxy] empty, or the tool's `address:port`.
     */
    fun exchange(
        ticket: Long,
        carry: Int,
        url: String,
        server: String,
        addresses: String,
        pins: String,
        proxy: String,
        user: ByteArray,
        password: ByteArray,
        body: ByteArray,
    ): Boolean {
        if (carry !in CARRY_ODOH..CARRY_FETCH) return false
        work.execute {
            try {
                val through = proxy.takeIf { it.isNotEmpty() }?.let { parseAddress(it) }?.let { Through(it, user, password) }
                val known = addresses.split(',').filter { it.isNotBlank() }.mapNotNull(::numeric)
                val wanted = pins.split(',').filter { it.startsWith("sha256/") }
                when (carry) {
                    CARRY_ODOH -> http(ticket, url, server, known, wanted, through, body, ODOH_TYPE)
                    CARRY_DOH -> http(ticket, url, server, known, wanted, through, body, DOH_TYPE)
                    CARRY_FETCH -> http(ticket, url, server, known, wanted, through, null, null)
                    CARRY_DOT -> dot.ask(ticket, server, url.substringAfterLast(':').toIntOrNull() ?: DOT_PORT, known, wanted, through, body)
                    else -> network(ticket, body)
                }
            } catch (e: RuntimeException) {
                reply(ticket, REFUSED, null)
            }
        }
        return true
    }

    /**
     * Builds ahead what the first exchange on the network beneath needs: Android's roots and the client with its
     * TLS context, on [work] (review S-m5). The service calls it when it starts and when the network changes.
     */
    fun warm() {
        work.execute {
            try {
                client(null)
            } catch (e: RuntimeException) {
                // The first exchange builds it again and says what failed.
            }
        }
    }

    /**
     * The screen's check of the user's own resolver before it is saved (W8's fix round, review R-M1): one query for
     * `example.com` (RFC 2606) to [choice], directly, as the engine would send it; [done] gets how long the answer
     * took in milliseconds, or null with the [outcome][outcomeOf] when it did not answer.
     */
    fun probe(choice: DnsSettings.Choice.Custom, done: (Long?, Int) -> Unit) {
        val ticket = -probeTickets.incrementAndGet()
        val started = System.nanoTime()
        probes[ticket] = { outcome, body ->
            val answered = body != null && (outcome == OK || outcome == ANSWER) && answers(body)
            done(if (answered) (System.nanoTime() - started) / 1_000_000 else null, if (answered) ANSWER else outcome)
        }
        val server = if (choice.dot) choice.at.substringBeforeLast(':') else choice.at.removePrefix("https://").substringBefore('/').substringBeforeLast(':')
        val carry = if (choice.dot) CARRY_DOT else CARRY_DOH
        val url = if (choice.dot) {
            if (':' in choice.at) choice.at else "${choice.at}:$DOT_PORT"
        } else {
            choice.at
        }
        val sent = exchange(ticket, carry, url, server, choice.addresses.joinToString(","), "", "", ByteArray(0), ByteArray(0), PROBE_QUERY)
        if (!sent) reply(ticket, REFUSED, null)
    }

    /** The network beneath changed: the clients of the one before, their connections and TLS sessions go. */
    fun networkChanged() {
        val old = clients.values.toList()
        clients.clear()
        work.execute { old.forEach { it.connectionPool.evictAll() } }
        dot.closeAll()
    }

    /** A tool, for an exchange through it. */
    data class Through(val proxy: InetSocketAddress, val user: ByteArray, val password: ByteArray) {
        override fun equals(other: Any?) = other is Through && proxy == other.proxy &&
            user.contentEquals(other.user) && password.contentEquals(other.password)

        override fun hashCode() = proxy.hashCode()
    }

    private fun http(ticket: Long, url: String, server: String, known: List<InetAddress>, pins: List<String>, through: Through?, body: ByteArray?, type: String?) {
        val request = Request.Builder().url(url).tag(Pins::class.java, Pins(pins)).apply {
            if (body != null && type != null) {
                header("Accept", type)
                post(body.toRequestBody(type.toMediaType()))
            }
        }.build()
        client(through, server, known).newCall(request).enqueue(
            object : Callback {
                override fun onFailure(call: Call, e: IOException) = reply(ticket, outcomeOf(e), null)

                override fun onResponse(call: Call, response: Response) {
                    response.use {
                        // The whole body, never more than a DNS message can be: a longer one is refused unread.
                        val bytes = try {
                            val source = it.body.source()
                            if (source.request(MAX_BODY + 1)) return reply(ticket, REFUSED, null)
                            source.buffer.readByteArray()
                        } catch (e: IOException) {
                            return reply(ticket, outcomeOf(e), null)
                        }
                        reply(ticket, it.code, if (it.code == OK) bytes else null)
                    }
                }
            },
        )
    }

    /**
     * The client for the network beneath now, directly or through [through], that reaches [server] only at [known]:
     * one per network, tool and set of addresses, all sharing the network's connection pool and TLS context. A
     * connection serves only clients of its own addresses (OkHttp's `Address` holds the [Dns]).
     */
    private fun client(through: Through?, server: String, known: List<InetAddress>): OkHttpClient {
        val base = client(through)
        return clients.getOrPut("${host.generation} ${through?.proxy} $server $known") {
            base.newBuilder().dns(KnownOnly(server, known)).build()
        }
    }

    /** The client for the network beneath now, directly or through [through], that knows no server's address. */
    private fun client(through: Through?): OkHttpClient {
        val key = "${host.generation} ${through?.proxy}"
        return clients.getOrPut(key) {
            OkHttpClient.Builder()
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .dns(KnownOnly("", emptyList()))
                .socketFactory(Sockets(through))
                .sslSocketFactory(sslFor().socketFactory, trust)
                .connectionPool(ConnectionPool(IDLE_CONNECTIONS, IDLE_SECONDS, TimeUnit.SECONDS))
                .connectTimeout(CONNECT_MS, TimeUnit.MILLISECONDS)
                .readTimeout(CALL_MS, TimeUnit.MILLISECONDS)
                .writeTimeout(CALL_MS, TimeUnit.MILLISECONDS)
                .callTimeout(CALL_MS, TimeUnit.MILLISECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .cache(null)
                .addNetworkInterceptor(Bare())
                .build()
        }
    }

    /** One TLS context per client: its session cache lives and dies with the network it began on. */
    private fun sslFor(): SSLContext = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }

    /** A plain socket for [server], protected and bound to the network beneath, or one through the tool. */
    internal fun socketFor(through: Through?): Socket = Sockets(through).createSocket()

    /** The sockets OkHttp and the DoT client open. */
    private inner class Sockets(private val through: Through?) : SocketFactory() {
        override fun createSocket(): Socket {
            // A tool on the loopback is reached as it is; one elsewhere (on the LAN) would loop through Watch's own
            // tunnel, where Watch's UID is: its socket is protected and bound as any other (review S-m2).
            val socket = when {
                through == null -> Socket()
                through.proxy.address.isLoopbackAddress -> return ToolSocket(through.proxy, through.user, through.password)
                else -> ToolSocket(through.proxy, through.user, through.password)
            }
            // A Socket makes its descriptor only when first used: reading an option makes it now, so that it can be
            // protected (as Network.bindSocket does for itself).
            socket.reuseAddress
            if (!host.protect(socket)) throw SocketException("not protected")
            host.network?.bindSocket(socket)
            return socket
        }

        override fun createSocket(host: String?, port: Int) = unsupported()

        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int) = unsupported()

        override fun createSocket(host: InetAddress?, port: Int) = unsupported()

        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int) = unsupported()

        private fun unsupported(): Socket = throw SocketException("unconnected sockets only")
    }

    /** OkHttp's resolver: [known], the addresses the exchange gave for [server], never a lookup. */
    private class KnownOnly(private val server: String, private val known: List<InetAddress>) : Dns {
        override fun lookup(hostname: String): List<InetAddress> =
            known.takeIf { hostname.equals(server, ignoreCase = true) && it.isNotEmpty() } ?: throw UnknownHostException("no address in the data pack")
    }

    /** The pins an HTTP exchange's server must match, carried with its request. */
    private class Pins(val wanted: List<String>)

    /** Takes away what OkHttp adds and checks the server's pins once its handshake is done. */
    private inner class Bare : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val handshake = chain.connection()?.handshake()
            val wanted = chain.request().tag(Pins::class.java)?.wanted.orEmpty()
            if (wanted.isNotEmpty()) {
                try {
                    SystemTrust.checkPins(handshake?.peerCertificates.orEmpty().filterIsInstance<X509Certificate>(), wanted)
                } catch (e: CertificateException) {
                    throw SSLPeerUnverifiedException(e.message)
                }
            }
            return chain.proceed(bare(chain.request()))
        }
    }

    /** Asks the network's resolver through Android's own on the network beneath, at most [CALL_MS]. */
    private fun network(ticket: Long, body: ByteArray) {
        networkResolverForTests?.let { return networkForTests(ticket, body, it) }
        val network = host.network ?: return reply(ticket, REFUSED, null)
        val cancel = CancellationSignal()
        // One reply: the answer, the error or the timeout, whichever comes first; the timer goes with the others.
        val once = firstOnly { outcome, answer -> reply(ticket, outcome, answer) }
        val timeout = timers.schedule({
            cancel.cancel()
            once(TIMEOUT, null)
        }, CALL_MS, TimeUnit.MILLISECONDS)
        DnsResolver.getInstance().rawQuery(
            network,
            body,
            DnsResolver.FLAG_NO_CACHE_STORE,
            work,
            cancel,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(answer: ByteArray, rcode: Int) {
                    timeout.cancel(false)
                    once(ANSWER, answer)
                }

                override fun onError(error: DnsResolver.DnsException) {
                    timeout.cancel(false)
                    once(REFUSED, null)
                }
            },
        )
    }

    /** [networkResolverForTests]'s exchange: one datagram, the first answer with its ID, at most [CALL_MS]. */
    private fun networkForTests(ticket: Long, body: ByteArray, resolver: InetSocketAddress) {
        try {
            java.net.DatagramSocket().use { socket ->
                if (!host.protect(socket)) return reply(ticket, REFUSED, null)
                host.network?.bindSocket(socket)
                socket.soTimeout = CALL_MS.toInt()
                socket.send(java.net.DatagramPacket(body, body.size, resolver))
                val buffer = ByteArray(MAX_BODY.toInt())
                while (true) {
                    val packet = java.net.DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    if (packet.length >= 2 && buffer[0] == body[0] && buffer[1] == body[1]) {
                        return reply(ticket, ANSWER, buffer.copyOf(packet.length))
                    }
                }
            }
        } catch (e: IOException) {
            reply(ticket, outcomeOf(e), null)
        }
    }

    companion object {
        const val CARRY_ODOH = 1
        const val CARRY_DOH = 2
        const val CARRY_DOT = 3
        const val CARRY_NETWORK = 4
        const val CARRY_FETCH = 5
        const val ODOH_TYPE = "application/oblivious-dns-message"
        const val DOH_TYPE = "application/dns-message"
        const val DOT_PORT = 853
        const val OK = 200
        const val ANSWER = 0
        const val TIMEOUT = -1
        const val TAMPERED = -2
        const val REFUSED = -3
        const val CONNECT_MS = 2_500L
        const val CALL_MS = 3_000L
        const val IDLE_SECONDS = 60L
        const val IDLE_CONNECTIONS = 4
        const val MAX_BODY = 65_535L

        /** The engine's code for how [e] failed: a timeout, a reset once the TLS hello was out or a certificate that does not check, or anything else. */
        fun outcomeOf(e: Throwable): Int = when {
            e is InterruptedIOException -> TIMEOUT
            e is SSLHandshakeException || e is SSLPeerUnverifiedException || e.cause is CertificateException -> TAMPERED
            e is SSLException -> TAMPERED
            e is SocketException && e.message.orEmpty().contains("reset", ignoreCase = true) && e !is ConnectException -> TAMPERED
            else -> REFUSED
        }

        /**
         * [request] without what OkHttp's bridge adds on its way to the network: its `User-Agent`, which names OkHttp's
         * version, and `Accept-Encoding: gzip`, since a compressed answer's length would undo the padding.
         */
        fun bare(request: Request): Request = request.newBuilder().removeHeader("User-Agent").removeHeader("Accept-Encoding").build()

        /** [reply], called for the first of several outcomes only (the security review's nit: no timeout after an answer). */
        internal fun firstOnly(reply: (Int, ByteArray?) -> Unit): (Int, ByteArray?) -> Unit {
            val replied = AtomicBoolean(false)
            return { outcome, answer -> if (replied.compareAndSet(false, true)) reply(outcome, answer) }
        }

        /** `example.com`'s A record, the query of a [probe]: ID 0, recursion desired. */
        private val PROBE_QUERY = byteArrayOf(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
            "\u0007example\u0003com\u0000".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 1, 0, 1)

        /** Whether [answer] is a DNS answer to the probe's question: "no error" or "no such name". */
        internal fun answers(answer: ByteArray): Boolean {
            if (answer.size < 12 + PROBE_QUERY.size - 12) return false
            val rcode = answer[3].toInt() and 0x0f
            val question = answer.copyOfRange(12, PROBE_QUERY.size)
            return answer[2].toInt() and 0x80 != 0 && (rcode == 0 || rcode == 3) && question.contentEquals(PROBE_QUERY.copyOfRange(12, PROBE_QUERY.size))
        }

        /**
         * An IPv4 or IPv6 address written as such, read without any lookup (review S-M2): four decimal numbers of 0 to
         * 255 by dots, or eight hexadecimal groups of up to four digits by colons, `::` once for zeros and a last
         * IPv4 part allowed; ASCII digits only, no zone, no port, no brackets. Null for anything else, and it never
         * throws.
         */
        fun numeric(text: String): InetAddress? = try {
            val t = text.trim()
            (ipv4(t) ?: ipv6(t))?.let { InetAddress.getByAddress(it) }
        } catch (e: java.net.UnknownHostException) {
            null
        } catch (e: RuntimeException) {
            null
        }

        private fun ipv4(text: String): ByteArray? {
            val parts = text.split('.')
            if (parts.size != 4) return null
            val out = ByteArray(4)
            for ((i, part) in parts.withIndex()) {
                if (part.isEmpty() || part.length > 3 || part.any { it !in '0'..'9' }) return null
                val value = part.toInt()
                if (value > 255) return null
                out[i] = value.toByte()
            }
            return out
        }

        private fun ipv6(text: String): ByteArray? {
            if (text.length > 45 || ':' !in text || text.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' && it != ':' && it != '.' }) return null
            val halves = text.split("::")
            if (halves.size > 2) return null
            fun groups(half: String): List<String>? = if (half.isEmpty()) emptyList() else half.split(':').takeIf { g -> g.none { it.isEmpty() } }
            val head = groups(halves[0]) ?: return null
            val tail = if (halves.size == 2) groups(halves[1]) ?: return null else emptyList()
            val words = mutableListOf<Int>()
            val all = head + tail
            for ((i, group) in all.withIndex()) {
                if ('.' in group) {
                    // An IPv4 part, the text's last only.
                    if (i != all.size - 1 || text.substringAfterLast(':') != group) return null
                    val v4 = ipv4(group) ?: return null
                    words += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                    words += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
                } else {
                    if (group.length > 4) return null
                    words += group.toInt(16)
                }
            }
            val headWords = head.sumOf { if ('.' in it) 2 else 1 }
            val missing = 8 - words.size
            if (halves.size == 1 && missing != 0 || halves.size == 2 && missing < 1) return null
            val full = if (halves.size == 2) words.take(headWords) + List(missing) { 0 } + words.drop(headWords) else words
            val out = ByteArray(16)
            for ((i, word) in full.withIndex()) {
                out[2 * i] = (word shr 8).toByte()
                out[2 * i + 1] = word.toByte()
            }
            return out
        }

        /** `address:port`, `[v6]:port` included. */
        fun parseAddress(text: String): InetSocketAddress? {
            val port = text.substringAfterLast(':').toIntOrNull() ?: return null
            val address = numeric(text.substringBeforeLast(':').removePrefix("[").removeSuffix("]")) ?: return null
            return InetSocketAddress(address, port)
        }
    }

    private fun reply(ticket: Long, outcome: Int, body: ByteArray?) {
        if (ticket < 0) probes.remove(ticket)?.invoke(outcome, body) else replies(ticket, outcome, body)
    }
}
