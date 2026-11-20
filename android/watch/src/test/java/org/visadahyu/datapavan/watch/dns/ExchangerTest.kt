package org.visadahyu.datapavan.watch.dns

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
 * password. OkHttp's Android platform does not start on the JVM, so DoH and ODoH over it are checked on the emulator
 * against the lab (scripts/verify-dns.sh).
 */
class ExchangerTest {
    private val certs = File("../../scripts/dnslab/certs")
    private val replies = ArrayBlockingQueue<Triple<Long, Int, ByteArray?>>(16)
    private val servers = mutableListOf<ServerSocket>()

    @After
    fun closeServers() = servers.forEach { it.close() }

    private fun certificate(name: String): X509Certificate =
        File(certs, "$name.pem").inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate }

    /** A TLS server socket on the loopback with the lab's certificate and key of [name]. */
    private fun tlsServer(name: String): SSLServerSocket {
        val pem = File(certs, "$name.key").readText().lines().filter { !it.startsWith("-----") }.joinToString("")
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        store.setKeyEntry(name, key, CharArray(0), arrayOf(certificate(name), certificate("ca")))
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
        val context = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        return (context.serverSocketFactory.createServerSocket(0, 8, InetAddress.getLoopbackAddress()) as SSLServerSocket).also { servers += it }
    }

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

    @Test
    fun failuresReadAsTheEngineCountsThem() {
        assertEquals(Exchanger.TIMEOUT, Exchanger.outcomeOf(java.net.SocketTimeoutException()))
        assertEquals(Exchanger.TAMPERED, Exchanger.outcomeOf(javax.net.ssl.SSLHandshakeException("bad certificate")))
        assertEquals(Exchanger.TAMPERED, Exchanger.outcomeOf(java.net.SocketException("Connection reset")))
        assertEquals(Exchanger.REFUSED, Exchanger.outcomeOf(java.net.ConnectException("Connection refused")))
        assertEquals(Exchanger.REFUSED, Exchanger.outcomeOf(java.io.IOException("closed")))
    }
}
