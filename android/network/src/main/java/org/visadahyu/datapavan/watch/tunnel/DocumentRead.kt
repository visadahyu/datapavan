package org.visadahyu.datapavan.watch.tunnel

import java.io.IOException
import java.io.InputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A configuration's file read from a documents provider, bounded in size and in time (W7, part 2, fix round, security
 * review M2). A provider may take minutes to hand a file over, a cloud one downloading it on a slow or censored
 * network: the read runs on a thread of its own, never on the store's worker, which would hold every change of the
 * configurations and the apps' routes behind it, and it ends at its time limit. Pure but for the timer, for the JVM
 * tests.
 */
object DocumentRead {
    /** How long the opening and the read may take together. */
    const val LIMIT_MS = 20_000L

    /** What the read gave. */
    sealed interface Result {
        /** The bytes, the caller's to zero. */
        class Bytes(val bytes: ByteArray) : Result

        /** More than the bound: not a configuration. */
        data object TooLong : Result

        /** It could not be opened or read. */
        data object Unreadable : Result

        /** Past the time limit: the opening was cancelled, the stream closed. */
        data object TooSlow : Result
    }

    private val timer = Executors.newSingleThreadScheduledExecutor { Thread(it, "watch-import-limit").apply { isDaemon = true } }

    /**
     * Opens the document with [open] and reads at most [max] bytes of it, all within [limitMs]. Past the limit
     * [onLate] cancels the opening (a `CancellationSignal` the provider gets) and the stream is closed, which on
     * Android wakes a read that waits on it; the answer is then [Result.TooSlow], whatever the read gives after.
     */
    fun read(limitMs: Long, max: Int, onLate: () -> Unit, open: () -> InputStream?): Result {
        val late = AtomicBoolean(false)
        var stream: InputStream? = null
        val lock = Any()
        val limit = timer.schedule(
            {
                late.set(true)
                onLate()
                synchronized(lock) { stream }?.closeQuietly()
            },
            limitMs,
            TimeUnit.MILLISECONDS,
        )
        try {
            // A provider refuses in many ways: an IOException, a SecurityException, an OperationCanceledException once
            // cancelled, an IllegalArgumentException for a document it no longer has.
            val opened = try {
                open()
            } catch (e: IOException) {
                null
            } catch (e: RuntimeException) {
                null
            } ?: return if (late.get()) Result.TooSlow else Result.Unreadable
            synchronized(lock) { stream = opened }
            if (late.get()) return Result.TooSlow
            val read = try {
                readBounded(opened, max)
            } catch (e: IOException) {
                null
            }
            return when {
                late.get() -> {
                    read?.fill(0)
                    Result.TooSlow
                }
                read == null -> Result.Unreadable
                read === TOO_LONG -> Result.TooLong
                else -> Result.Bytes(read)
            }
        } finally {
            limit.cancel(false)
            synchronized(lock) { stream }?.closeQuietly()
        }
    }

    /**
     * At most [max] bytes of [stream], or [TOO_LONG] when there are more. The buffer it read through is zeroed; the
     * caller zeroes what it returns.
     */
    fun readBounded(stream: InputStream, max: Int): ByteArray {
        val held = ByteArray(max + 1)
        var length = 0
        try {
            while (length < held.size) {
                val n = stream.read(held, length, held.size - length)
                if (n < 0) break
                length += n
            }
            return if (length > max) TOO_LONG else held.copyOf(length)
        } finally {
            held.fill(0)
        }
    }

    /** What a stream longer than the bound reads as. */
    private val TOO_LONG = ByteArray(0)

    private fun InputStream.closeQuietly() {
        try {
            close()
        } catch (e: IOException) {
            // Closed already, or its provider is gone: nothing more to read either way.
        }
    }
}
