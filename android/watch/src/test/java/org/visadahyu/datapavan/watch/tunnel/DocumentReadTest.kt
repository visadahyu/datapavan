package org.visadahyu.datapavan.watch.tunnel

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A configuration's file read from a documents provider within bounds of size and time (W7, part 2, fix round,
 * security review M2): a provider that hands the file over slowly, or never, ends the read at its limit, the opening
 * cancelled and the stream closed, rather than holding a thread, and the store's worker never reads one.
 */
class DocumentReadTest {
    /** A stream that waits for data that never comes, as a provider downloading on a blocked network does, until closed. */
    private class Waiting : InputStream() {
        val closed = CountDownLatch(1)

        override fun read(): Int {
            closed.await()
            throw IOException("closed")
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int = read()

        override fun close() {
            closed.countDown()
        }
    }

    @Test(timeout = 10_000)
    fun a_read_that_never_ends_stops_at_its_limit() {
        val stream = Waiting()
        var cancelled = false
        val started = System.nanoTime()
        val read = DocumentRead.read(300, Import.MAX_TEXT, onLate = { cancelled = true }) { stream }
        assertEquals(DocumentRead.Result.TooSlow, read)
        assertTrue("the opening was cancelled", cancelled)
        assertTrue("within its limit and a margin", (System.nanoTime() - started) / 1_000_000 < 3_000)
    }

    @Test(timeout = 10_000)
    fun an_opening_that_never_ends_stops_at_its_limit() {
        val provider = CountDownLatch(1)
        val read = DocumentRead.read(300, Import.MAX_TEXT, onLate = { provider.countDown() }) {
            // The provider gives up once cancelled, as a CancellationSignal makes it (OperationCanceledException).
            provider.await()
            throw IllegalStateException("cancelled")
        }
        assertEquals(DocumentRead.Result.TooSlow, read)
    }

    @Test
    fun a_file_within_the_bounds_is_read_whole_and_a_longer_one_refused() {
        val text = "[Interface]\nPrivateKey = x\n".toByteArray()
        assertArrayEquals(text, (DocumentRead.read(5_000, Import.MAX_TEXT, {}) { ByteArrayInputStream(text) } as DocumentRead.Result.Bytes).bytes)
        val long = ByteArray(Import.MAX_TEXT + 1) { 'a'.code.toByte() }
        assertEquals(DocumentRead.Result.TooLong, DocumentRead.read(5_000, Import.MAX_TEXT, {}) { ByteArrayInputStream(long) })
        assertEquals(DocumentRead.Result.Unreadable, DocumentRead.read(5_000, Import.MAX_TEXT, {}) { null })
        assertEquals(DocumentRead.Result.Unreadable, DocumentRead.read(5_000, Import.MAX_TEXT, {}) { throw IOException("gone") })
    }
}
