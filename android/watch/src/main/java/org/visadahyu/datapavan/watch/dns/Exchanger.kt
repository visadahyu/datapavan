package org.visadahyu.datapavan.watch.dns

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
import org.visadahyu.datapavan.watch.Engine

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
 * with the endpoint's pins where the dataset gives them. One client per network beneath, so that TLS sessions are
 * resumed only on the network they began on; no 0-RTT (Conscrypt sends no early data); connections idle for 60 s are
 * closed and opened again on demand.
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

        /** The network beneath the tunnel, or null for none. */
        val network: Network?

        /** A number that changes with the network beneath: each has clients and TLS sessions of its own. */
        val generation: Int

        /** Debug builds: the DNS lab's test root, beside Android's; release builds: none. */
        val extraRoots: List<X509Certificate>
    }

    /** The addresses of each server, from the data pack, which the clients' [Dns] answers with. */
    private val addresses = ConcurrentHashMap<String, List<InetAddress>>()

    /** The pins of each server, from the data pack. */
    private val pins = ConcurrentHashMap<String, List<String>>()

    private val clients = ConcurrentHashMap<String, OkHttpClient>()
    private val timers: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "watch-dns-timer").apply { isDaemon = true }
    }
    private val work = Executors.newCachedThreadPool { task -> Thread(task, "watch-dns").apply { isDaemon = true } }
    private val trust: X509TrustManager by lazy { given ?: SystemTrust.android(host.extraRoots) }
    private val dot by lazy { DotClient(::socketFor, ::sslFor, { pins[it].orEmpty() }, timers, work, replies) }

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
        val through = proxy.takeIf { it.isNotEmpty() }?.let { parseAddress(it) }?.let { Through(it, user, password) }
        val known = addresses.split(',').filter { it.isNotBlank() }.mapNotNull(::numeric)
        if (server.isNotEmpty() && known.isNotEmpty()) this.addresses[server] = known
        if (server.isNotEmpty()) this.pins[server] = pins.split(',').filter { it.startsWith("sha256/") }
        try {
            when (carry) {
                CARRY_ODOH -> http(ticket, url, through, body, ODOH_TYPE)
                CARRY_DOH -> http(ticket, url, through, body, DOH_TYPE)
                CARRY_FETCH -> http(ticket, url, through, null, null)
                CARRY_DOT -> dot.ask(ticket, server, url.substringAfterLast(':').toIntOrNull() ?: DOT_PORT, known, through, body)
                CARRY_NETWORK -> network(ticket, body)
                else -> return false
            }
        } catch (e: RuntimeException) {
            reply(ticket, REFUSED, null)
        }
        return true
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

    private fun http(ticket: Long, url: String, through: Through?, body: ByteArray?, type: String?) {
        val request = Request.Builder().url(url).apply {
            if (body != null && type != null) {
                header("Accept", type)
                post(body.toRequestBody(type.toMediaType()))
            }
        }.build()
        client(through).newCall(request).enqueue(
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

    /** The client for the network beneath now, directly or through [through]. */
    private fun client(through: Through?): OkHttpClient {
        val key = "${host.generation} ${through?.proxy}"
        return clients.getOrPut(key) {
            OkHttpClient.Builder()
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .dns(KnownOnly())
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
    private fun socketFor(through: Through?): Socket = Sockets(through).createSocket()

    /** The sockets OkHttp and the DoT client open. */
    private inner class Sockets(private val through: Through?) : SocketFactory() {
        override fun createSocket(): Socket {
            if (through != null) return ToolSocket(through.proxy, through.user, through.password)
            val socket = Socket()
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

    /** OkHttp's resolver: the data pack's addresses for a server, never a lookup. */
    private inner class KnownOnly : Dns {
        override fun lookup(hostname: String): List<InetAddress> =
            addresses[hostname] ?: throw UnknownHostException("no address in the data pack")
    }

    /** Takes away what OkHttp adds and checks the server's pins once its handshake is done. */
    private inner class Bare : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val handshake = chain.connection()?.handshake()
            val wanted = pins[chain.request().url.host].orEmpty()
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
        val network = host.network ?: return reply(ticket, REFUSED, null)
        val cancel = CancellationSignal()
        timers.schedule({
            cancel.cancel()
            reply(ticket, TIMEOUT, null)
        }, CALL_MS, TimeUnit.MILLISECONDS)
        DnsResolver.getInstance().rawQuery(
            network,
            body,
            DnsResolver.FLAG_NO_CACHE_STORE,
            work,
            cancel,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(answer: ByteArray, rcode: Int) = reply(ticket, ANSWER, answer)

                override fun onError(error: DnsResolver.DnsException) = reply(ticket, REFUSED, null)
            },
        )
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

        /** An address written as digits only, never a name to look up. */
        fun numeric(text: String): InetAddress? {
            val t = text.trim()
            val looks = t.isNotEmpty() && (t.contains(':') || t.all { it.isDigit() || it == '.' })
            return if (looks) {
                try {
                    InetAddress.getByName(t)
                } catch (e: UnknownHostException) {
                    null
                }
            } else {
                null
            }
        }

        /** `address:port`, `[v6]:port` included. */
        fun parseAddress(text: String): InetSocketAddress? {
            val port = text.substringAfterLast(':').toIntOrNull() ?: return null
            val address = numeric(text.substringBeforeLast(':').removePrefix("[").removeSuffix("]")) ?: return null
            return InetSocketAddress(address, port)
        }
    }

    private fun reply(ticket: Long, outcome: Int, body: ByteArray?) = replies(ticket, outcome, body)
}
