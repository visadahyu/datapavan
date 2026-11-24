package org.visadahyu.datapavan.network.dns

import java.io.DataInputStream
import java.io.File
import java.io.FilterOutputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The DoT client's connections across a change of the network beneath (the DoT crash, 2026-11-24): the change closes
 * nothing on its caller's thread, which is the main one in the service, where Android forbids network I/O and a TLS
 * close writes its close_notify; a query in flight at the change is asked again and answered; what an open in flight
 * across the change brings is closed unused, and its query answered by a fresh connection; a server that takes TCP and
 * never answers TLS, or trickles its answer, fails the exchange in time, with one open for every lookup that waits.
 * Against TLS servers on the loopback with the DNS lab's test certificates, each wait bounded.
 */
class DotClientTest {
    private val certs = File("../../scripts/dnslab/certs")
    private val replies = LinkedBlockingQueue<Triple<Long, Int, ByteArray?>>()
    private val servers = mutableListOf<ServerSocket>()

    /** The server side of every connection accepted, in order. */
    private val accepts = LinkedBlockingQueue<Socket>()
    private val accepted = CopyOnWriteArrayList<Socket>()

    /** By the connection's number from 1, each query a server read. */
    private val asked = LinkedBlockingQueue<Int>()

    /** Every write to and close of a socket the client made, with the thread that did it. */
    private val events = CopyOnWriteArrayList<Pair<String, Thread>>()

    /** The threads that closed one of the client's sockets, in order. */
    private val closes = LinkedBlockingQueue<Thread>()

    private val generation = AtomicInteger()
    private val timers = Executors.newSingleThreadScheduledExecutor { Thread(it, "test-dns-timer").apply { isDaemon = true } }
    private val work = Executors.newCachedThreadPool { Thread(it, "test-dns").apply { isDaemon = true } }

    @After
    fun closeAll() {
        servers.forEach { it.close() }
        accepted.forEach { it.close() }
        work.shutdownNow()
        timers.shutdownNow()
    }

    private fun certificate(name: String): X509Certificate =
        File(certs, "$name.pem").inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate }

    /** A DoT server on the loopback with the lab's certificate; [answering]: whether connection N answers. */
    private fun server(answering: (Int) -> Boolean = { true }): ServerSocket {
        val pem = File(certs, "dot.key").readText().lines().filter { !it.startsWith("-----") }.joinToString("")
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        store.setKeyEntry("dot", key, CharArray(0), arrayOf(certificate("dot"), certificate("ca")))
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
        val tls = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        val server = tls.serverSocketFactory.createServerSocket(0, 50, InetAddress.getLoopbackAddress()) as SSLServerSocket
        listen(server) { socket, n -> serve(socket, n, answering(n)) }
        return server
    }

    /** Accepts on [server] until it closes, telling [accepts] of each connection and handing it to [each]. */
    private fun listen(server: ServerSocket, each: (Socket, Int) -> Unit) {
        servers += server
        Thread {
            try {
                var n = 0
                while (true) {
                    val socket = server.accept()
                    n++
                    accepted += socket
                    accepts.put(socket)
                    val number = n
                    Thread { each(socket, number) }.apply { isDaemon = true }.start()
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true }.start()
    }

    /**
     * Reads each query on [socket], connection [n], and answers it if [answering]: with its ID, and one byte more, the
     * connection's number, which tells which connection answered.
     */
    private fun serve(socket: Socket, n: Int, answering: Boolean) {
        try {
            val input = DataInputStream(socket.getInputStream())
            val out = socket.getOutputStream()
            while (true) {
                val query = ByteArray(input.readUnsignedShort()).also(input::readFully)
                asked.put(n)
                if (!answering) continue
                val answer = query + byteArrayOf(n.toByte())
                out.write(byteArrayOf((answer.size shr 8).toByte(), answer.size.toByte()) + answer)
                out.flush()
            }
        } catch (_: Exception) {
        }
    }

    /** A plain socket that records the thread of each write to it and of its close: TLS's close_notify is a write. */
    private inner class Recording : Socket() {
        override fun getOutputStream(): OutputStream {
            val raw = super.getOutputStream()
            return object : FilterOutputStream(raw) {
                override fun write(b: Int) {
                    events += "write" to Thread.currentThread()
                    raw.write(b)
                }

                override fun write(b: ByteArray, off: Int, len: Int) {
                    events += "write" to Thread.currentThread()
                    raw.write(b, off, len)
                }
            }
        }

        override fun close() {
            events += "close" to Thread.currentThread()
            closes.put(Thread.currentThread())
            super.close()
        }
    }

    private fun client(socket: () -> Socket = { Recording() }) = DotClient(
        { socket() },
        { SSLContext.getInstance("TLS").apply { init(null, arrayOf(SystemTrust.manager(listOf(certificate("ca")))), null) } },
        timers,
        work,
        { ticket, outcome, body -> replies.put(Triple(ticket, outcome, body)) },
        generation::get,
    )

    private val query = byteArrayOf(0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0) + "\u0005probe\u0006dnslab\u0004test\u0000".toByteArray() + byteArrayOf(0, 1, 0, 1)

    private fun ask(client: DotClient, ticket: Long, server: ServerSocket) =
        client.ask(ticket, "dot.dnslab.test", server.localPort, listOf(InetAddress.getLoopbackAddress()), emptyList(), null, query)

    private fun reply() = replies.poll(10, TimeUnit.SECONDS) ?: error("no reply")

    /** The next reply answers [ticket]; returns the number of the connection that answered it. */
    private fun answered(ticket: Long): Int {
        val (got, outcome, body) = reply()
        assertEquals(ticket, got)
        assertEquals(Exchanger.ANSWER, outcome)
        assertEquals(query.size + 1, body?.size)
        return body!!.last().toInt()
    }

    /** Nothing of the client's sockets was written or closed on [caller]'s thread. */
    private fun noIoOn(caller: Thread) {
        val there = events.filter { it.second === caller }.map { it.first }
        assertTrue("on the caller's thread: $there", there.isEmpty())
    }

    /** One of the client's sockets is closed, within the bound, on another thread than [caller]'s. */
    private fun closedOffThe(caller: Thread) = assertNotSame(caller, closes.poll(10, TimeUnit.SECONDS) ?: error("never closed"))

    /** The service's change: the network first, then its generation, then the exchanger. */
    private fun change(client: DotClient) {
        generation.incrementAndGet()
        client.closeAll()
    }

    @Test
    fun aChangeClosesItsConnectionsOffTheCallersThread() {
        val server = server()
        val client = client()
        ask(client, 1, server)
        answered(1)
        assertNotNull(accepts.poll(10, TimeUnit.SECONDS))
        assertEquals(1 to 0, client.counts())
        val caller = Thread.currentThread()
        change(client)
        noIoOn(caller)
        assertEquals(0 to 0, client.counts())
        closedOffThe(caller)
        // The next exchange opens a connection of its own.
        ask(client, 2, server)
        answered(2)
        assertNotNull("a second accept", accepts.poll(10, TimeUnit.SECONDS))
        noIoOn(caller)
    }

    @Test
    fun aQueryInFlightAtTheChangeIsAnsweredWithinItsBound() {
        // The first connection reads the query and never answers; the next one answers.
        val server = server { n -> n > 1 }
        val client = client()
        ask(client, 3, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        val caller = Thread.currentThread()
        val changed = System.nanoTime()
        change(client)
        noIoOn(caller)
        // Asked again on a fresh connection, not refused, nor left to its timer.
        answered(3)
        val took = (System.nanoTime() - changed) / 1_000_000
        assertTrue("answered $took ms after the change", took < Exchanger.CALL_MS)
        assertEquals(2, asked.poll(10, TimeUnit.SECONDS))
        noIoOn(caller)
    }

    @Test
    fun whatAnOpenInFlightAcrossAChangeBringsIsNotKept() {
        // As the service changes the network; as the debug builds' dump does, with no new generation; and the
        // generation risen before the exchanger was told.
        openAcross { change(it) }
        openAcross { it.closeAll() }
        openAcross { generation.incrementAndGet() }
    }

    /**
     * An open held in its socket across [change]: what it brings is closed unused, off the caller's thread, and never
     * kept; its query is answered by a fresh connection, which is kept.
     */
    private fun openAcross(change: (DotClient) -> Unit) {
        closes.clear()
        val before = accepted.size
        val server = server()
        val (client, release) = heldOpen(server, 4)
        val caller = Thread.currentThread()
        change(client)
        release.countDown()
        closedOffThe(caller)
        assertEquals("by the fresh connection", 2, answered(4))
        assertEquals(1 to 0, client.counts())
        // The next exchange rides the fresh connection: no third accept, which would come before its answer.
        ask(client, 5, server)
        assertEquals(2, answered(5))
        assertEquals(2, accepted.size - before)
        noIoOn(caller)
    }

    /** A client whose first open for [ticket] on [server] waits in its socket until the latch returned is released. */
    private fun heldOpen(server: ServerSocket, ticket: Long): Pair<DotClient, CountDownLatch> {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val first = AtomicBoolean(true)
        val client = client {
            if (first.getAndSet(false)) {
                entered.countDown()
                release.await(10, TimeUnit.SECONDS)
            }
            Recording()
        }
        ask(client, ticket, server)
        assertTrue("the open began", entered.await(10, TimeUnit.SECONDS))
        assertEquals(0 to 1, client.counts())
        return client to release
    }

    @Test
    fun aWithdrawnOpenThatSucceededIsNotUsedEvenWhereItWouldAnswer() {
        // The server answers on every connection: the withdrawn one would have answered, on the network before.
        val server = server()
        val (client, release) = heldOpen(server, 6)
        change(client)
        release.countDown()
        assertEquals("by the fresh connection", 2, answered(6))
        // The withdrawn connection got no query at all.
        assertEquals(listOf(2), asked.toList())
    }

    @Test
    fun aServerThatNeverAnswersTlsEndsTheExchangeInTimeWithOneOpen() {
        // TCP taken, the ClientHello never answered: what a censor that blackholes TLS does.
        val silent = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        listen(silent) { _, _ -> }
        endsInTimeWithOneOpen(silent, 10L)
        // TCP taken, the answer trickled a byte at a time, each read well within its timeout: a handshake record
        // header, then a body that never ends. Only a bound on the whole handshake ends it.
        val trickling = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        listen(trickling) { socket, _ ->
            try {
                val out = socket.getOutputStream()
                for (byte in byteArrayOf(0x16, 3, 3, 0x40, 0) + ByteArray(1_000)) {
                    out.write(byte.toInt())
                    out.flush()
                    Thread.sleep(500)
                }
            } catch (_: Exception) {
            }
        }
        endsInTimeWithOneOpen(trickling, 20L)
    }

    /** Ten lookups for [server]'s one key, from [first] on: one open, each ended by a timeout within the bound. */
    private fun endsInTimeWithOneOpen(server: ServerSocket, first: Long) {
        val before = accepted.size
        val client = client()
        val tickets = first until first + 10
        val started = System.nanoTime()
        for (ticket in tickets) ask(client, ticket, server)
        val got = List(10) { replies.poll(Exchanger.CALL_MS + 5_000, TimeUnit.MILLISECONDS) ?: error("no reply within the bound") }
        val took = (System.nanoTime() - started) / 1_000_000
        assertEquals(tickets.toSet(), got.map { it.first }.toSet())
        assertEquals(List(10) { Exchanger.TIMEOUT }, got.map { it.second })
        assertTrue("ended $took ms after the lookups", took < Exchanger.CALL_MS + 2_000)
        assertEquals("one open for the ten", 1, accepted.size - before)
        assertEquals(0 to 0, client.counts())
    }
}
