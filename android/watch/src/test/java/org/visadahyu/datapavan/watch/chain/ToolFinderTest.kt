package org.visadahyu.datapavan.watch.chain

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.SocketException
import kotlin.concurrent.thread

/**
 * The search against a SOCKS5 greeter on this computer's loopback, with Android's owner lookup played
 * by a list of answers: the lookup is what decides whether the port is the tool's.
 */
class ToolFinderTest {
    private val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
    @Volatile private var method = 0

    init {
        thread(isDaemon = true) {
            while (true) {
                val client = try {
                    server.accept()
                } catch (e: SocketException) {
                    break
                }
                thread(isDaemon = true) {
                    client.use {
                        val input = it.getInputStream()
                        repeat(3) { input.read() }
                        it.getOutputStream().apply {
                            write(byteArrayOf(5, method.toByte()))
                            flush()
                        }
                        // Open until Watch closes, as a proxy waits for the request after the greeting.
                        while (input.read() >= 0) Unit
                    }
                }
            }
        }
    }

    @After
    fun close() = server.close()

    private val tool = KnownTool(
        packageName = PKG,
        name = "Test tool",
        proxyMode = true,
        listeners = listOf(Listener("socks5", "127.0.0.1", server.localPort)),
        auth = "optional",
        udp = true,
        names = true,
    )

    /** Searches with Android's owner lookup answering [owners] in turn, and returns what it found and was asked. */
    private fun search(vararg owners: Int?): Pair<ToolSearch, List<InetSocketAddress>> {
        val asked = mutableListOf<InetSocketAddress>()
        var next = 0
        val finder = ToolFinder(
            uidOf = { if (it == PKG) UID else null },
            table = listOf(tool),
            ownerOf = { local, _ -> asked += local; owners[next++] },
            userId = 0,
        )
        return finder.search() to asked
    }

    private fun ToolSearch.owner(): Boolean? = (this as ToolSearch.Answering).found.ownerConfirmed

    @Test
    fun aToolNamedAtOnceIsAskedOnce() {
        val (found, asked) = search(UID)
        assertEquals(true, found.owner())
        assertEquals("the tool's end is asked about", listOf(server.localPort), asked.map { it.port })
    }

    @Test
    fun aHalfOpenEndIsAskedAgainOnceTheToolAnswered() {
        // The kernel's lookup gives root for an end still half-open (CI, 2026-11-12): not another app.
        val (found, asked) = search(0, UID)
        assertEquals(true, found.owner())
        assertEquals(2, asked.size)
    }

    @Test
    fun rootBothTimesIsUnknownNotAnotherApp() {
        assertEquals(null, search(0, 0).first.owner())
    }

    @Test
    fun anAnswerOnlyAfterTheGreetingStillCounts() {
        // Android could not say at once, and named the tool once it had answered.
        assertEquals(true, search(null, UID).first.owner())
    }

    @Test
    fun anotherAppOnThePortIsPassedOver() {
        val (found, asked) = search(OTHER)
        assertTrue(found is ToolSearch.NotAnswering)
        assertEquals("another app named at once is not asked about again", 1, asked.size)
        // Root at once, then another app: still not the tool.
        assertTrue(search(0, OTHER).first is ToolSearch.NotAnswering)
    }

    @Test
    fun aRefusedGreetingMeansAPassword() {
        method = 0xff
        val found = search(UID).first as ToolSearch.Answering
        assertTrue(found.found.needsPassword)
    }

    /** A port where nothing listens now: bound and closed again, so a connection to it is refused. */
    private fun closedPort(): Int = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }

    private fun toolOn(vararg ports: Int) = tool.copy(listeners = ports.map { Listener("socks5", "127.0.0.1", it) })

    /** A SOCKS5 greeter on [port], opened when the search pauses: the tool is listening again by then. */
    private fun greeterOn(port: Int): ServerSocket = ServerSocket(port, 50, InetAddress.getLoopbackAddress()).also { s ->
        thread(isDaemon = true) {
            val client = try {
                s.accept()
            } catch (e: SocketException) {
                return@thread
            }
            client.use {
                repeat(3) { _ -> it.getInputStream().read() }
                it.getOutputStream().apply { write(byteArrayOf(5, 0)); flush() }
                while (it.getInputStream().read() >= 0) Unit
            }
        }
    }

    private fun finder(
        table: List<KnownTool>,
        retry: Set<String> = setOf(PKG),
        userId: Int = 0,
        owner: () -> Int? = { UID },
        pause: (Long) -> Unit,
    ) = ToolFinder(
        uidOf = { if (it == PKG) UID else null },
        table = table,
        ownerOf = { _, _ -> owner() },
        userId = userId,
        retryRefused = retry,
        pause = pause,
    )

    @Test
    fun theRememberedToolIsFoundOnTheSecondTry() {
        // The tool listened again a moment after a refusal (CI, 2026-11-14).
        val port = closedPort()
        var greeter: ServerSocket? = null
        val pauses = mutableListOf<Long>()
        try {
            val found = finder(listOf(toolOn(port))) { pauses += it; greeter = greeterOn(port) }.search()
            assertTrue("found on the second try: $found", found is ToolSearch.Answering)
            assertEquals("one pause", 1, pauses.size)
        } finally {
            greeter?.close()
        }
    }

    @Test
    fun aRefusedPortIsTriedOnceMoreThenNotAnswering() {
        val pauses = mutableListOf<Long>()
        assertTrue(finder(listOf(toolOn(closedPort()))) { pauses += it }.search() is ToolSearch.NotAnswering)
        assertEquals("one pause, then the answer", 1, pauses.size)
    }

    @Test
    fun aToolNeverFoundIsNotWaitedFor() {
        // A user who never ran the tool in proxy mode: no remembered tool, so no pause.
        val pauses = mutableListOf<Long>()
        val found = finder(listOf(toolOn(closedPort())), retry = emptySet()) { pauses += it }.search()
        assertTrue(found is ToolSearch.NotAnswering)
        assertEquals(0, pauses.size)
    }

    @Test
    fun noPauseWhenNothingRefused() {
        // Another app answers on the port: not refused, so the search does not wait.
        val pauses = mutableListOf<Long>()
        assertTrue(finder(listOf(tool), owner = { OTHER }) { pauses += it }.search() is ToolSearch.NotAnswering)
        assertEquals(0, pauses.size)
    }

    @Test
    fun theSecondTryGreetsOnlyThePortsThatRefused() {
        // One port answers for another app, one refuses: after the pause only the refused one is greeted.
        var asked = 0
        val found = finder(listOf(toolOn(server.localPort, closedPort())), owner = { asked++; OTHER }) { }.search()
        assertTrue(found is ToolSearch.NotAnswering)
        assertEquals("the port held by another app is not greeted again", 1, asked)
    }

    @Test
    fun theUsersShiftedPortIsTriedAgainToo() {
        // A tool that adds the user's number to its port: the shifted port refused, then listened.
        val base = closedPort()
        val shifted = closedPort()
        var greeter: ServerSocket? = null
        try {
            val found = finder(listOf(toolOn(base)), userId = shifted - base) { greeter = greeterOn(shifted) }.search()
            assertEquals(shifted, (found as ToolSearch.Answering).found.port)
        } finally {
            greeter?.close()
        }
    }

    @Test
    fun nothingInstalledIsSaidSo() {
        val finder = ToolFinder(uidOf = { null }, table = listOf(tool), ownerOf = { _, _ -> UID }, userId = 0)
        assertEquals(ToolSearch.NoneInstalled, finder.search())
    }

    private companion object {
        const val PKG = "org.example.tool"
        const val UID = 10211
        const val OTHER = 10999
    }
}
