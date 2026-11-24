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
import javax.net.ssl.SSLSocket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
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

    /** What a test server's connection does with one query it read. */
    private enum class Act {
        ANSWER,

        /** Reads it and never answers. */
        HOLD,

        /** Resets the connection beneath TLS, with no close_notify: what a NAT or a server that forgot the flow sends. */
        RESET,

        /** Closes the connection as TLS does, close_notify and FIN: a server's own close. */
        CLOSE,

        /** Answers it 3.5 s later, after the client's time for it, while the connection goes on. */
        LATE,
    }

    /**
     * A DoT server on the loopback with the lab's certificate: TCP accepted, then TLS on it as a server, so that a test
     * can reset the plain socket beneath. [act]: what connection N does with its query K, both from 1.
     */
    private fun server(act: (Int, Int) -> Act = { _, _ -> Act.ANSWER }): ServerSocket {
        val pem = File(certs, "dot.key").readText().lines().filter { !it.startsWith("-----") }.joinToString("")
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null) }
        store.setKeyEntry("dot", key, CharArray(0), arrayOf(certificate("dot"), certificate("ca")))
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, CharArray(0)) }
        val tls = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        listen(server) { raw, n ->
            val socket = tls.socketFactory.createSocket(raw, raw.inetAddress.hostAddress, raw.port, true) as SSLSocket
            socket.useClientMode = false
            serve(socket, raw, n) { k -> act(n, k) }
        }
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
     * Reads each query on [socket], connection [n] over [raw], and does with its Kth what [act] says: an answer has its
     * ID, and one byte more, the connection's number, which tells which connection answered.
     */
    private fun serve(socket: SSLSocket, raw: Socket, n: Int, act: (Int) -> Act) {
        try {
            val input = DataInputStream(socket.getInputStream())
            val out = socket.getOutputStream()
            var k = 0
            val answer = { query: ByteArray ->
                val framed = (query + byteArrayOf(n.toByte())).let { byteArrayOf((it.size shr 8).toByte(), it.size.toByte()) + it }
                synchronized(out) {
                    out.write(framed)
                    out.flush()
                }
            }
            while (true) {
                val query = ByteArray(input.readUnsignedShort()).also(input::readFully)
                asked.put(n)
                when (act(++k)) {
                    Act.ANSWER -> answer(query)
                    Act.LATE -> Thread {
                        try {
                            Thread.sleep(Exchanger.CALL_MS + 500)
                            answer(query)
                        } catch (_: Exception) {
                        }
                    }.apply { isDaemon = true }.start()
                    Act.HOLD -> {}
                    Act.RESET -> {
                        raw.setSoLinger(true, 0)
                        raw.close()
                        return
                    }
                    Act.CLOSE -> {
                        socket.close()
                        return
                    }
                }
            }
        } catch (_: Exception) {
        }
    }

    /**
     * A plain socket that records the thread of each write to it and of its close: TLS's close_notify is a write.
     * [closing] runs as it is closed, before the close itself.
     */
    private inner class Recording(private val closing: () -> Unit = {}) : Socket() {
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
            closing()
            super.close()
        }
    }

    private fun client(now: () -> Int = generation::get, socket: () -> Socket = { Recording() }) = DotClient(
        { socket() },
        { SSLContext.getInstance("TLS").apply { init(null, arrayOf(SystemTrust.manager(listOf(certificate("ca")))), null) } },
        timers,
        work,
        { ticket, outcome, body -> replies.put(Triple(ticket, outcome, body)) },
        now,
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

    /** The next reply gives [ticket] the outcome [outcome], with no answer. */
    private fun failed(ticket: Long, outcome: Int) {
        val (got, how, body) = reply()
        assertEquals(ticket, got)
        assertEquals(outcome, how)
        assertNull(body)
    }

    /** No reply more comes within half a second: none was answered twice. */
    private fun noMoreReplies() = assertNull("a reply more", replies.poll(500, TimeUnit.MILLISECONDS))

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
        val server = server { n, _ -> if (n > 1) Act.ANSWER else Act.HOLD }
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

    @Test
    fun aSilentConnectionIsRetiredAtItsFirstTimeoutAndWhatWaitsOnItAskedOnAFreshOne() {
        // Connection 1 answers its first query, then reads and never answers: a flow that a path, a NAT or a censor
        // dropped without a reset. Connection 2 answers.
        val server = server { n, k -> if (n == 1 && k > 1) Act.HOLD else Act.ANSWER }
        val client = client()
        ask(client, 1, server)
        assertEquals(1, answered(1))
        asked.clear()
        ask(client, 2, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        // Later, so that lookup 3's own time runs well after lookup 2's, under load too.
        Thread.sleep(1_500)
        ask(client, 3, server)
        assertEquals("lookup 3 on the silent connection", 1, asked.poll(10, TimeUnit.SECONDS))
        // Lookup 2 runs out its time; lookup 3, which waited on the same connection, is asked on a fresh one.
        failed(2, Exchanger.TIMEOUT)
        assertEquals("by the fresh connection", 2, answered(3))
        // The fresh connection is the one kept.
        ask(client, 4, server)
        assertEquals(2, answered(4))
        assertEquals(2, accepted.size)
        noMoreReplies()
    }

    @Test
    fun aStopRightAfterARetirementAsksNothingAgain() {
        // As above, but the retirement's close of connection 1 is held until the service has stopped: what waited on
        // it must not be asked again in a run that ended.
        val server = server { n, k -> if (n == 1 && k > 1) Act.HOLD else Act.ANSWER }
        val closing = CountDownLatch(1)
        val stopped = CountDownLatch(1)
        val first = AtomicBoolean(true)
        val client = client {
            if (first.getAndSet(false)) {
                Recording {
                    closing.countDown()
                    stopped.await(10, TimeUnit.SECONDS)
                }
            } else {
                Recording()
            }
        }
        ask(client, 1, server)
        assertEquals(1, answered(1))
        asked.clear()
        ask(client, 2, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        Thread.sleep(1_500)
        ask(client, 3, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        failed(2, Exchanger.TIMEOUT)
        assertTrue("the retirement closes the socket", closing.await(10, TimeUnit.SECONDS))
        client.closeAll(again = false)
        stopped.countDown()
        failed(3, Exchanger.REFUSED)
        noMoreReplies()
        assertEquals("no fresh connection", 1, accepted.size)
    }

    @Test
    fun aStopWhileALookupIsOnItsWayToTheLockOpensNothing() {
        // The lookup has passed the run's first check and reads the network's generation when the service stops.
        val server = server()
        val reading = CountDownLatch(1)
        val stopped = CountDownLatch(1)
        val first = AtomicBoolean(true)
        val client = client(now = {
            if (first.getAndSet(false)) {
                reading.countDown()
                stopped.await(10, TimeUnit.SECONDS)
            }
            generation.get()
        })
        ask(client, 1, server)
        assertTrue("the lookup reads the generation", reading.await(10, TimeUnit.SECONDS))
        client.closeAll(again = false)
        stopped.countDown()
        failed(1, Exchanger.REFUSED)
        noMoreReplies()
        assertEquals("no connection after the stop", 0, accepted.size)
    }

    @Test
    fun aConnectionThatOwesTooManyAnswersIsRetired() {
        // Connection 1 never answers one query in two, and answers the others at once, so that it is never silent: once
        // it owes more than 64 answers, past their time, it is retired, and the next lookup opens connection 2.
        val server = server { n, k -> if (n == 1 && k % 2 == 1) Act.HOLD else Act.ANSWER }
        val client = client()
        val tickets = 100L until 240L
        for (ticket in tickets) ask(client, ticket, server)
        val got = List(tickets.count()) { replies.poll(Exchanger.CALL_MS + 5_000, TimeUnit.MILLISECONDS) ?: error("no reply") }
        assertEquals("each lookup answered once", tickets.toSet(), got.map { it.first }.toSet())
        ask(client, 1, server)
        assertEquals("by a fresh connection", 2, answered(1))
        assertEquals(2, accepted.size)
        noMoreReplies()
    }

    @Test
    fun aLateAnswerMatchedToNothingShowsTheConnectionLives() {
        // Query 1 is answered after its time, query 2 at once, query 3 never: when query 3 runs out its time, query 1's
        // late answer, which no query waits for any more, is what was heard since query 3 went out.
        val server = server { _, k ->
            when (k) {
                1 -> Act.LATE
                3 -> Act.HOLD
                else -> Act.ANSWER
            }
        }
        val client = client()
        ask(client, 1, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        ask(client, 2, server)
        assertEquals(1, answered(2))
        // Query 3 goes out 1.5 s before query 1's late answer comes, and runs out its time 1.5 s after it.
        Thread.sleep(2_000)
        asked.clear()
        ask(client, 3, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        failed(1, Exchanger.TIMEOUT)
        failed(3, Exchanger.TIMEOUT)
        ask(client, 4, server)
        assertEquals("on the same connection", 1, answered(4))
        assertEquals(1, accepted.size)
        noMoreReplies()
    }

    @Test
    fun oneLateAnswerOnALiveConnectionRetiresNothing() {
        // The server never answers the first query and answers every other at once: one name slow upstream, on a
        // connection that works. RFC 7766 (section 7) lets answers come in any order.
        val server = server { _, k -> if (k == 1) Act.HOLD else Act.ANSWER }
        val client = client()
        ask(client, 1, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        ask(client, 2, server)
        assertEquals(1, answered(2))
        failed(1, Exchanger.TIMEOUT)
        ask(client, 3, server)
        assertEquals("on the same connection", 1, answered(3))
        assertEquals(1, accepted.size)
        noMoreReplies()
    }

    @Test
    fun aResetOrACloseOnAConnectionThatServedIsAskedAgainAndOnlyTheFreshOneCounts() {
        // A reset: what a NAT or a server that forgot the flow sends to the next query on a kept connection. A close:
        // a server's idle close that met the query on its way. Neither is the way failing.
        assertEquals("by the fresh connection", 2, answered(servedThenCut(Act.RESET, 10, fresh = Act.ANSWER)))
        assertEquals("by the fresh connection", 2, answered(servedThenCut(Act.CLOSE, 20, fresh = Act.ANSWER)))
        noMoreReplies()
        // The fresh connection resets too: its outcome is what counts, and nothing is asked a third time.
        val before = accepted.size
        failed(servedThenCut(Act.RESET, 30, fresh = Act.RESET), Exchanger.TAMPERED)
        noMoreReplies()
        assertEquals("two connections, not three", 2, accepted.size - before)
    }

    /**
     * A client and a server whose first connection answers lookup [first] and does [cut] with the next one, which
     * this asks and returns; every later connection does [fresh].
     */
    private fun servedThenCut(cut: Act, first: Long, fresh: Act): Long {
        val server = server { n, k ->
            when {
                n > 1 -> fresh
                k == 1 -> Act.ANSWER
                else -> cut
            }
        }
        val client = client()
        ask(client, first, server)
        assertEquals(1, answered(first))
        ask(client, first + 1, server)
        return first + 1
    }

    @Test
    fun aResetOnAFreshConnectionCountsAsTampering() {
        // Where a censor that blocks DoT strikes: the connection never carried an answer.
        val server = server { _, _ -> Act.RESET }
        val client = client()
        ask(client, 1, server)
        failed(1, Exchanger.TAMPERED)
        noMoreReplies()
        assertEquals("not asked again", 1, accepted.size)
    }

    @Test
    fun theStopAsksNothingAgainOnAConnectionThatServed() {
        val server = server { _, k -> if (k == 1) Act.ANSWER else Act.HOLD }
        val client = client()
        ask(client, 1, server)
        assertEquals(1, answered(1))
        asked.clear()
        ask(client, 2, server)
        assertEquals(1, asked.poll(10, TimeUnit.SECONDS))
        client.closeAll(again = false)
        failed(2, Exchanger.REFUSED)
        noMoreReplies()
        assertEquals("no fresh connection", 1, accepted.size)
    }
}
