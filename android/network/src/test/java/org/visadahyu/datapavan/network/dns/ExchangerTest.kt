package org.visadahyu.datapavan.network.dns

import android.net.Network
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.Protocol
import okio.Buffer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The encrypted resolver's transport (W8, part 1) against local servers of the DNS lab's test certificates: DoT
 * answers, what goes over HTTP carries no User-Agent and no Accept-Encoding, a pin that matches none of the chain and a
 * certificate for another name are refused as tampering, a root the user added (an `AndroidCAStore` alias that is not
 * `system:`) is not trusted, and the tool's SOCKS5 proxy is asked for the destination by its address, with its
 * password. DoH and ODoH over OkHttp, against OkHttp's own test server with the lab's certificate, over HTTP/2 (W8's
 * fix round, review R-M4; the unit tests run OkHttp's JVM build of the same version, network/build.gradle.kts): the
 * request as it reaches the server, the answer, a 401, a body longer than a DNS message, the pins. Each exchange
 * carries its own pins, and nothing of it runs on the caller's thread.
 */
class ExchangerTest {
    private val certs = File("../../scripts/dnslab/certs")
    private val replies = ArrayBlockingQueue<Triple<Long, Int, ByteArray?>>(16)
    private val servers = mutableListOf<ServerSocket>()

    private val webServers = mutableListOf<MockWebServer>()

    @After
    fun closeServers() {
        servers.forEach { it.close() }
        webServers.forEach { it.close() }
    }

    private fun certificate(name: String): X509Certificate =
        File(certs, "$name.pem").inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate }

    /** A server's TLS context with the lab's certificate and key of [name]. */
    private fun tlsContext(name: String): SSLContext {
        val pem = File(certs, "$name.key").readText().lines().filter { !it.startsWith("-----") }.joinToString("")
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        store.setKeyEntry(name, key, CharArray(0), arrayOf(certificate(name), certificate("ca")))
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
        return SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
    }

    /** A TLS server socket on the loopback with the lab's certificate and key of [name]. */
    private fun tlsServer(name: String): SSLServerSocket =
        (tlsContext(name).serverSocketFactory.createServerSocket(0, 8, InetAddress.getLoopbackAddress()) as SSLServerSocket).also { servers += it }

    /** OkHttp's test server on the loopback, over TLS with the lab's DoH certificate, HTTP/2 first. */
    private fun webServer(): MockWebServer = MockWebServer().also { server ->
        webServers += server
        server.useHttps(tlsContext("doh").socketFactory)
        server.protocols = listOf(Protocol.HTTP_2, Protocol.HTTP_1_1)
        server.start(InetAddress.getLoopbackAddress(), 0)
    }

    private fun http(exchanger: Exchanger, ticket: Long, carry: Int, server: MockWebServer, pins: String = "") = exchanger.exchange(
        ticket, carry, "https://doh.dnslab.test:${server.port}/dns-query", "doh.dnslab.test", "127.0.0.1", pins, "",
        ByteArray(0), ByteArray(0), query,
    )

    private fun reply() = replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")

    private fun exchanger(trust: List<X509Certificate>) = Exchanger(
        object : Exchanger.Host {
            override fun protect(socket: Socket) = true
            override val network: Network? = null
            override val generation = 0
            override val extraRoots = emptyList<X509Certificate>()
        },
        replies = { ticket, outcome, body -> replies.put(Triple(ticket, outcome, body)) },
        given = SystemTrust.manager(trust),
    )

    /** An exchanger whose network beneath has [route] as its proxy, for generation 0. */
    private fun exchanger(trust: List<X509Certificate>, route: ResolverProxy?) = Exchanger(
        object : Exchanger.Host {
            override fun protect(socket: Socket) = true
            override val network: Network? = null
            override val generation = 0
            override val extraRoots = emptyList<X509Certificate>()
            override val resolverProxy = route
        },
        replies = { ticket, outcome, body -> replies.put(Triple(ticket, outcome, body)) },
        given = SystemTrust.manager(trust),
    )

    /**
     * A proxy on the loopback that records each request's head in [seen]: [status] 200 opens a tunnel to the address
     * the `CONNECT` asked for and pipes it both ways; any other is answered and closed.
     */
    private fun connectProxy(seen: ArrayBlockingQueue<String>, status: Int): ServerSocket {
        val proxy = ServerSocket(0, 8, InetAddress.getLoopbackAddress()).also { servers += it }
        Thread {
            while (!proxy.isClosed) {
                val client = try {
                    proxy.accept()
                } catch (_: Exception) {
                    break
                }
                Thread {
                    try {
                        val head = ProxySocket.head(client.getInputStream())
                        seen.offer(head)
                        if (status != 200) {
                            client.getOutputStream().write("HTTP/1.1 $status No\r\n\r\n".toByteArray())
                            client.close()
                            return@Thread
                        }
                        val authority = head.substringAfter("CONNECT ").substringBefore(' ')
                        val target = Socket(authority.substringBeforeLast(':'), authority.substringAfterLast(':').toInt())
                        client.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
                        Thread { runCatching { target.getInputStream().copyTo(client.getOutputStream()) }; runCatching { client.close() } }
                            .apply { isDaemon = true; start() }
                        runCatching { client.getInputStream().copyTo(target.getOutputStream()) }
                        runCatching { target.close() }
                    } catch (_: Exception) {
                        runCatching { client.close() }
                    }
                }.apply { isDaemon = true; start() }
            }
        }.apply { isDaemon = true; start() }
        return proxy
    }

    private fun route(proxy: ServerSocket) = ResolverProxy(
        0,
        NetworkProxy.Setting("127.0.0.1", proxy.localPort, pac = false, exclusions = emptyList()),
        listOf(InetSocketAddress(InetAddress.getLoopbackAddress(), proxy.localPort)),
    )

    private val query = byteArrayOf(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + "\u0005probe\u0006dnslab\u0004test\u0000".toByteArray() + byteArrayOf(0, 1, 0, 1)

    /** Answers each DoT query on [server] with the ID asked and one byte more, [count] times. */
    private fun serveDot(server: SSLServerSocket, count: Int) = Thread {
        try {
            server.accept().use { socket ->
                val input = DataInputStream(socket.getInputStream())
                val out = socket.getOutputStream()
                repeat(count) {
                    val length = input.readUnsignedShort()
                    val asked = ByteArray(length).also(input::readFully)
                    val answer = asked + byteArrayOf(7)
                    out.write(byteArrayOf((answer.size shr 8).toByte(), answer.size.toByte()) + answer)
                    out.flush()
                }
            }
        } catch (_: Exception) {
        }
    }.apply { isDaemon = true; start() }

    private fun dot(exchanger: Exchanger, ticket: Long, server: SSLServerSocket, pins: String = "") = exchanger.exchange(
        ticket, Exchanger.CARRY_DOT, "dot.dnslab.test:${server.localPort}", "dot.dnslab.test", "127.0.0.1", pins, "",
        ByteArray(0), ByteArray(0), query,
    )

    @Test
    fun whatGoesOverHttpCarriesNoUserAgentNorAcceptEncoding() {
        val asked = okhttp3.Request.Builder().url("https://doh.dnslab.test/dns-query")
            .header("User-Agent", "okhttp/5.5.1").header("Accept-Encoding", "gzip").header("Accept", Exchanger.DOH_TYPE).build()
        val bare = Exchanger.bare(asked)
        assertNull(bare.header("User-Agent"))
        assertNull(bare.header("Accept-Encoding"))
        assertEquals(Exchanger.DOH_TYPE, bare.header("Accept"))
    }

    @Test
    fun aPinThatMatchesNothingIsTampering() {
        val server = tlsServer("dot")
        serveDot(server, 1)
        val wrong = "sha256/" + Base64.getEncoder().encodeToString(ByteArray(32))
        dot(exchanger(listOf(certificate("ca"))), 2, server, wrong)
        val (_, outcome, body) = replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")
        assertEquals(Exchanger.TAMPERED, outcome)
        assertNull(body)
        // The right pin, the CA's, passes.
        val again = tlsServer("dot")
        serveDot(again, 1)
        dot(exchanger(listOf(certificate("ca"))), 3, again, SystemTrust.pin(certificate("ca")))
        assertEquals(Exchanger.ANSWER, (replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")).second)
    }

    @Test
    fun aRootTheUserAddedIsNotTrusted() {
        // AndroidCAStore as Android lays it out: the user's roots under `user:`, Android's under `system:`.
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        store.setCertificateEntry("user:lab", certificate("ca"))
        store.setCertificateEntry("system:other", certificate("relay"))
        val roots = SystemTrust.systemRoots(store)
        assertEquals(listOf(certificate("relay")), roots)
        assertFalse(SystemTrust.isSystem("user:lab"))
        assertTrue(SystemTrust.isSystem("system:other"))
        val server = tlsServer("dot")
        serveDot(server, 1)
        dot(exchanger(roots), 4, server)
        assertEquals(Exchanger.TAMPERED, (replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")).second)
        // The same server, the lab's root trusted: it answers.
        val again = tlsServer("dot")
        serveDot(again, 1)
        dot(exchanger(listOf(certificate("ca"))), 5, again)
        assertEquals(Exchanger.ANSWER, (replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")).second)
    }

    @Test
    fun aCertificateForAnotherNameIsRefused() {
        // The DoH server's certificate, offered where the DoT server's name is asked.
        val server = tlsServer("doh")
        serveDot(server, 1)
        dot(exchanger(listOf(certificate("ca"))), 8, server)
        assertEquals(Exchanger.TAMPERED, (replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")).second)
    }

    @Test
    fun aNameIsNeverLookedUp() {
        assertNull(Exchanger.numeric("doh.dnslab.test"))
        assertEquals(InetAddress.getByName("192.0.2.1"), Exchanger.numeric("192.0.2.1"))
        assertEquals(InetSocketAddress(InetAddress.getByName("::1"), 1080), Exchanger.parseAddress("[::1]:1080"))
        // No address in the data pack: refused, nothing asked.
        exchanger(listOf(certificate("ca"))).exchange(5, Exchanger.CARRY_DOT, "nowhere.test:853", "nowhere.test", "", "", "", ByteArray(0), ByteArray(0), query)
        assertEquals(Exchanger.REFUSED, (replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")).second)
    }

    @Test
    fun dotAnswersEachQueryByItsIdAndGivesItBackWithIdZero() {
        val server = tlsServer("dot")
        Thread {
            try {
                server.accept().use { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val out = socket.getOutputStream()
                    repeat(2) {
                        val length = input.readUnsignedShort()
                        val asked = ByteArray(length).also(input::readFully)
                        // Answer with the ID asked, and one byte more to tell it apart.
                        val answer = asked + byteArrayOf(7)
                        out.write(byteArrayOf((answer.size shr 8).toByte(), answer.size.toByte()) + answer)
                        out.flush()
                    }
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true; start() }
        val exchanger = exchanger(listOf(certificate("ca")))
        exchanger.exchange(6, Exchanger.CARRY_DOT, "dot.dnslab.test:${server.localPort}", "dot.dnslab.test", "127.0.0.1", "", "", ByteArray(0), ByteArray(0), query)
        val first = replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")
        assertEquals(6L, first.first)
        assertEquals(Exchanger.ANSWER, first.second)
        val body = first.third ?: error("no body")
        assertEquals(0, body[0].toInt())
        assertEquals(0, body[1].toInt())
        assertEquals(query.size + 1, body.size)
        // The second query on the same connection.
        exchanger.exchange(7, Exchanger.CARRY_DOT, "dot.dnslab.test:${server.localPort}", "dot.dnslab.test", "127.0.0.1", "", "", ByteArray(0), ByteArray(0), query)
        assertEquals(7L, (replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")).first)
    }

    @Test
    fun theToolIsAskedForTheAddressWithItsPassword() {
        val proxy = ServerSocket(0, 8, InetAddress.getLoopbackAddress()).also { servers += it }
        val seen = ArrayBlockingQueue<ByteArray>(4)
        Thread {
            try {
                proxy.accept().use { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val out = socket.getOutputStream()
                    val greeting = ByteArray(4).also(input::readFully)
                    seen.put(greeting)
                    out.write(byteArrayOf(5, 2))
                    val auth = ByteArray(2).also(input::readFully)
                    val user = ByteArray(auth[1].toInt()).also(input::readFully)
                    val passwordLength = input.read()
                    val password = ByteArray(passwordLength).also(input::readFully)
                    seen.put(user + byteArrayOf(0) + password)
                    out.write(byteArrayOf(1, 0))
                    val request = ByteArray(10).also(input::readFully)
                    seen.put(request)
                    out.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                    out.write("hello".toByteArray())
                    out.flush()
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true; start() }
        val socket = ToolSocket(InetSocketAddress(InetAddress.getLoopbackAddress(), proxy.localPort), "u".toByteArray(), "pw".toByteArray())
        socket.connect(InetSocketAddress(InetAddress.getByName("192.0.2.9"), 443), 5_000)
        assertArrayEquals(byteArrayOf(5, 2, 0, 2), seen.poll(5, TimeUnit.SECONDS))
        assertArrayEquals("u".toByteArray() + byteArrayOf(0) + "pw".toByteArray(), seen.poll(5, TimeUnit.SECONDS))
        assertArrayEquals(byteArrayOf(5, 1, 0, 1, 192.toByte(), 0, 2, 9, 1, 187.toByte()), seen.poll(5, TimeUnit.SECONDS))
        assertEquals(InetAddress.getByName("192.0.2.9"), socket.inetAddress)
        assertEquals("hello", String(DataInputStream(socket.getInputStream()).let { ByteArray(5).also(it::readFully) }))
        socket.close()
    }

    /**
     * Review R-M4: DoH and ODoH as they reach the server: a POST over HTTP/2 with the DNS message as it was, its type
     * asked and given, no User-Agent, no Accept-Encoding; the answer back whole.
     */
    @Test
    fun dohAndOdohGoOverHttp2WithNothingOkHttpAdds() {
        val server = webServer()
        val answer = ByteArray(96) { it.toByte() }
        val exchanger = exchanger(listOf(certificate("ca")))
        for ((ticket, carry) in listOf(20L to Exchanger.CARRY_DOH, 21L to Exchanger.CARRY_ODOH)) {
            server.enqueue(MockResponse.Builder().code(200).body(Buffer().write(answer)).build())
            http(exchanger, ticket, carry, server)
            val (got, outcome, body) = reply()
            assertEquals(ticket, got)
            assertEquals(Exchanger.OK, outcome)
            assertArrayEquals(answer, body)
            val request = server.takeRequest(5, TimeUnit.SECONDS) ?: error("no request")
            val type = if (carry == Exchanger.CARRY_DOH) Exchanger.DOH_TYPE else Exchanger.ODOH_TYPE
            assertEquals("POST", request.method)
            assertTrue(request.version, request.version.startsWith("HTTP/2"))
            assertEquals("/dns-query", request.target)
            assertEquals(type, request.headers["Accept"])
            assertEquals(type, request.headers["Content-Type"])
            assertNull(request.headers["User-Agent"])
            assertNull(request.headers["Accept-Encoding"])
            assertNull(request.headers["Cookie"])
            assertArrayEquals(query, request.body?.toByteArray())
        }
    }

    /** Review R-M4: a 401 reaches the engine as 401 (a target's new key), a body longer than any DNS message is refused unread. */
    @Test
    fun a401AndAnOverlongBodyReadAsTheEngineNeeds() {
        val server = webServer()
        val exchanger = exchanger(listOf(certificate("ca")))
        server.enqueue(MockResponse.Builder().code(401).body("key").build())
        http(exchanger, 22, Exchanger.CARRY_ODOH, server)
        val (_, outcome, body) = reply()
        assertEquals(401, outcome)
        assertNull(body)
        server.enqueue(MockResponse.Builder().code(200).body(Buffer().write(ByteArray(Exchanger.MAX_BODY.toInt() + 1))).build())
        http(exchanger, 23, Exchanger.CARRY_DOH, server)
        assertEquals(Exchanger.REFUSED, reply().second)
        server.enqueue(MockResponse.Builder().code(200).body(Buffer().write(ByteArray(Exchanger.MAX_BODY.toInt()))).build())
        http(exchanger, 24, Exchanger.CARRY_DOH, server)
        assertEquals(Exchanger.OK, reply().second)
    }

    /** Review R-M4: a DoH server whose chain matches none of its pins is tampering; the right pin passes. */
    @Test
    fun dohWithAPinThatMatchesNothingIsTampering() {
        val server = webServer()
        server.enqueue(MockResponse.Builder().code(200).body("x").build())
        val wrong = "sha256/" + Base64.getEncoder().encodeToString(ByteArray(32))
        http(exchanger(listOf(certificate("ca"))), 25, Exchanger.CARRY_DOH, server, wrong)
        assertEquals(Exchanger.TAMPERED, reply().second)
        http(exchanger(listOf(certificate("ca"))), 26, Exchanger.CARRY_DOH, server, SystemTrust.pin(certificate("ca")))
        assertEquals(Exchanger.OK, reply().second)
    }

    /**
     * The security review's nit: each exchange carries its own pins. One without pins (a resolver of the user's on a
     * preset's host) leaves its connection open; a pinned one after it never rides that connection unchecked.
     */
    @Test
    fun aPinnedExchangeNeverRidesAnUnpinnedConnection() {
        val server = tlsServer("dot")
        Thread {
            try {
                repeat(2) {
                    val socket = server.accept()
                    Thread {
                        try {
                            val input = DataInputStream(socket.getInputStream())
                            val out = socket.getOutputStream()
                            while (true) {
                                val asked = ByteArray(input.readUnsignedShort()).also(input::readFully)
                                out.write(byteArrayOf((asked.size shr 8).toByte(), asked.size.toByte()) + asked)
                                out.flush()
                            }
                        } catch (_: Exception) {
                        }
                    }.apply { isDaemon = true; start() }
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true; start() }
        val exchanger = exchanger(listOf(certificate("ca")))
        dot(exchanger, 27, server)
        assertEquals(Exchanger.ANSWER, reply().second)
        dot(exchanger, 28, server, "sha256/" + Base64.getEncoder().encodeToString(ByteArray(32)))
        assertEquals(Exchanger.TAMPERED, reply().second)
    }

    /** Review S-m5: an exchange returns at once, while what it needs is built on the exchanger's own threads. */
    @Test
    fun anExchangeReturnsAtOnceWhileItsClientIsBuilt() {
        val slow = Exchanger(
            object : Exchanger.Host {
                override fun protect(socket: Socket) = true
                override val network: Network? = null
                override val generation: Int
                    get() {
                        Thread.sleep(1_500)
                        return 0
                    }
                override val extraRoots = emptyList<X509Certificate>()
            },
            replies = { ticket, outcome, body -> replies.put(Triple(ticket, outcome, body)) },
            given = SystemTrust.manager(listOf(certificate("ca"))),
        )
        val started = System.nanoTime()
        slow.exchange(29, Exchanger.CARRY_DOH, "https://doh.dnslab.test:9/dns-query", "doh.dnslab.test", "127.0.0.1", "", "", ByteArray(0), ByteArray(0), query)
        assertTrue("returned at once", System.nanoTime() - started < 500_000_000L)
        assertEquals(29L, reply().first)
    }

    /**
     * Review S-m2: a socket to a tool off the loopback (on the LAN) is protected from the network part's own tunnel;
     * one on the loopback needs not.
     */
    @Test
    fun aToolOffTheLoopbackIsProtected() {
        val protectedSockets = mutableListOf<Socket>()
        val exchanger = Exchanger(
            object : Exchanger.Host {
                override fun protect(socket: Socket) = protectedSockets.add(socket)
                override val network: Network? = null
                override val generation = 0
                override val extraRoots = emptyList<X509Certificate>()
            },
            replies = { _, _, _ -> },
            given = SystemTrust.manager(listOf(certificate("ca"))),
        )
        val lan = exchanger.socketFor(Exchanger.Through(InetSocketAddress(InetAddress.getByName("192.0.2.1"), 1080), ByteArray(0), ByteArray(0)))
        assertTrue(lan is ToolSocket)
        assertEquals(listOf(lan), protectedSockets)
        exchanger.socketFor(Exchanger.Through(InetSocketAddress(InetAddress.getLoopbackAddress(), 1080), ByteArray(0), ByteArray(0)))
        assertEquals(1, protectedSockets.size)
        exchanger.socketFor(null)
        assertEquals(2, protectedSockets.size)
    }

    /** The security review's nit: of an answer and a timeout, only the first reaches the engine. */
    @Test
    fun onlyTheFirstOutcomeIsReplied() {
        val seen = mutableListOf<Int>()
        val once = Exchanger.firstOnly { outcome, _ -> seen += outcome }
        once(Exchanger.ANSWER, ByteArray(1))
        once(Exchanger.TIMEOUT, null)
        assertEquals(listOf(Exchanger.ANSWER), seen)
    }

    /** Review R-M1: the screen's check of a resolver: an answer to its question, with the time it took; none, refused. */
    @Test
    fun theProbeAsksOnceAndReadsTheAnswer() {
        val server = tlsServer("dot")
        Thread {
            try {
                server.accept().use { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val asked = ByteArray(input.readUnsignedShort()).also(input::readFully)
                    val answer = asked.copyOf().also {
                        it[2] = 0x81.toByte()
                        it[3] = 0x80.toByte()
                    }
                    socket.getOutputStream().apply {
                        write(byteArrayOf((answer.size shr 8).toByte(), answer.size.toByte()) + answer)
                        flush()
                    }
                    input.read()
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true; start() }
        val results = ArrayBlockingQueue<Pair<Long?, Int>>(2)
        val exchanger = exchanger(listOf(certificate("ca")))
        exchanger.probe(DnsSettings.Choice.Custom(true, "dot.dnslab.test:${server.localPort}", listOf("127.0.0.1"))) { ms, outcome -> results.put(ms to outcome) }
        val (ms, outcome) = results.poll(10, TimeUnit.SECONDS) ?: error("no result")
        assertTrue("answered", ms != null && ms >= 0)
        assertEquals(Exchanger.ANSWER, outcome)
        assertTrue("no reply to the engine", replies.isEmpty())
        // Nothing listens there.
        val closed = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).let { val port = it.localPort; it.close(); port }
        exchanger.probe(DnsSettings.Choice.Custom(true, "dot.dnslab.test:$closed", listOf("127.0.0.1"))) { got, why -> results.put(got to why) }
        val (none, why) = results.poll(10, TimeUnit.SECONDS) ?: error("no result")
        assertNull(none)
        assertEquals(Exchanger.REFUSED, why)
        assertFalse(Exchanger.answers(query))
        // A server that answers something else than an answer to the question: not an answer.
        val echo = tlsServer("dot")
        serveDot(echo, 1)
        exchanger.probe(DnsSettings.Choice.Custom(true, "dot.dnslab.test:${echo.localPort}", listOf("127.0.0.1"))) { got, why2 -> results.put(got to why2) }
        assertNull("an echo is no answer", (results.poll(10, TimeUnit.SECONDS) ?: error("no result")).first)
    }

    @Test
    fun failuresReadAsTheEngineCountsThem() {
        assertEquals(Exchanger.TIMEOUT, Exchanger.outcomeOf(java.net.SocketTimeoutException()))
        assertEquals(Exchanger.TAMPERED, Exchanger.outcomeOf(javax.net.ssl.SSLHandshakeException("bad certificate")))
        assertEquals(Exchanger.TAMPERED, Exchanger.outcomeOf(java.net.SocketException("Connection reset")))
        assertEquals(Exchanger.REFUSED, Exchanger.outcomeOf(java.net.ConnectException("Connection refused")))
        assertEquals(Exchanger.REFUSED, Exchanger.outcomeOf(java.io.IOException("closed")))
    }

    /**
     * The resolver unit: through the network beneath's own proxy, DoH goes by a `CONNECT` to the data pack's address,
     * with `Host` alone (no `User-Agent` names the library), and answers through the tunnel.
     */
    @Test
    fun throughTheNetworksProxyTheConnectAsksForTheAddressWithNothingElse() {
        val server = webServer()
        val seen = ArrayBlockingQueue<String>(4)
        val proxy = connectProxy(seen, 200)
        val exchanger = exchanger(listOf(certificate("ca")), route(proxy))
        val answer = ByteArray(40) { it.toByte() }
        server.enqueue(MockResponse.Builder().code(200).body(Buffer().write(answer)).build())
        http(exchanger, 60, Exchanger.CARRY_DOH, server)
        val (ticket, outcome, body) = reply()
        assertEquals(60L, ticket)
        assertEquals(Exchanger.OK, outcome)
        assertArrayEquals(answer, body)
        assertEquals("CONNECT 127.0.0.1:${server.port} HTTP/1.1\r\nHost: 127.0.0.1:${server.port}\r\n\r\n", seen.poll(5, TimeUnit.SECONDS))
    }

    /** A proxy that refuses the tunnel costs the exchange nothing: it goes directly, and so do the next ones. */
    @Test
    fun aProxyThatRefusesIsLeftForADirectConnection() {
        val server = webServer()
        val seen = ArrayBlockingQueue<String>(4)
        val proxy = connectProxy(seen, 403)
        val route = route(proxy)
        val exchanger = exchanger(listOf(certificate("ca")), route)
        repeat(2) { server.enqueue(MockResponse.Builder().code(200).body(Buffer().write(byteArrayOf(1))).build()) }
        http(exchanger, 61, Exchanger.CARRY_DOH, server)
        assertEquals(Exchanger.OK, reply().second)
        assertTrue(route.refused())
        http(exchanger, 62, Exchanger.CARRY_DOH, server)
        assertEquals(Exchanger.OK, reply().second)
        // The proxy was asked once, by the first exchange only.
        assertTrue(seen.poll(1, TimeUnit.SECONDS) != null)
        assertNull(seen.poll(500, TimeUnit.MILLISECONDS))
    }

    /**
     * The process's own `ProxySelector`, which Android sets by the start order (measurements 7.1, point 3), never
     * decides: with one naming a proxy and none from the network beneath, the exchange goes directly.
     */
    @Test
    fun theProcesssOwnProxySelectorNeverDecides() {
        val before = java.net.ProxySelector.getDefault()
        val seen = ArrayBlockingQueue<String>(4)
        val proxy = connectProxy(seen, 200)
        try {
            java.net.ProxySelector.setDefault(object : java.net.ProxySelector() {
                override fun select(uri: java.net.URI?) =
                    listOf(java.net.Proxy(java.net.Proxy.Type.HTTP, InetSocketAddress(InetAddress.getLoopbackAddress(), proxy.localPort)))

                override fun connectFailed(uri: java.net.URI?, sa: java.net.SocketAddress?, ioe: java.io.IOException?) = Unit
            })
            val server = webServer()
            server.enqueue(MockResponse.Builder().code(200).body(Buffer().write(byteArrayOf(1))).build())
            http(exchanger(listOf(certificate("ca")), null), 63, Exchanger.CARRY_DOH, server)
            assertEquals(Exchanger.OK, reply().second)
            assertNull(seen.poll(500, TimeUnit.MILLISECONDS))
        } finally {
            java.net.ProxySelector.setDefault(before)
        }
    }
}
