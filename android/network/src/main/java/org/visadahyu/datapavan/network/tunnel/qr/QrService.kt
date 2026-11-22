package org.visadahyu.datapavan.network.tunnel.qr

import android.app.Service
import android.content.Intent
import android.content.res.AssetFileDescriptor
import android.graphics.ImageDecoder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.IOException
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * The QR decoder of a WireGuard configuration's picture (W7, part 2; ADR 0035, question 10), in an isolated process
 * of its own, `:qr`, as the audit's parsers of untrusted input are (ADR 0045, decision 9): no permissions, no
 * network, none of Watch's files. A picture is hostile input until it is read, through Android's image decoders and
 * ZXing alike; a picture that subverted either would find nothing here worth taking. It gets the picture as a
 * read-only file descriptor and gives back only the QR code's text, at most [QrDecode.MAX_TEXT] bytes, or why not, as
 * primitives ([QrDecode.answer]).
 *
 * Bounds: a picture larger than [QrDecode.MAX_SIDE] a side, by its header, is not decoded; one that is, is brought
 * down to at most [QrDecode.TARGET] a side while Android decodes it, and refused if it still holds more than
 * [QrDecode.MAX_PIXELS];
 * the whole read has [TIME_LIMIT_MS], after which the answer is "too slow" and the process ends. ZXing holds the
 * text as a `String` while it reads it, here alone: the process ends once Watch lets it go ([onDestroy]), and that
 * memory with it. Bound only by Watch ([QrClient]); an isolated service cannot be exported, and the build fails
 * unless it stays isolated (app/build.gradle.kts).
 */
class QrService : Service() {
    private val reader = Executors.newSingleThreadExecutor { Thread(it, "qr-read").apply { isDaemon = true } }

    override fun onBind(intent: Intent): IBinder = object : IQrDecoder.Stub() {
        override fun decode(picture: ParcelFileDescriptor, failure: IntArray): ByteArray? {
            val result = try {
                reader.submit<QrDecode.Result> { picture.use(::read) }.get(TIME_LIMIT_MS, TimeUnit.MILLISECONDS)
            } catch (e: TimeoutException) {
                // A read past its time ends with the process, once this answer has gone.
                endSoon()
                QrDecode.Result.Failed(QrDecode.Failure.TOO_SLOW)
            } catch (e: ExecutionException) {
                QrDecode.Result.Failed(QrDecode.Failure.NOT_A_PICTURE)
            } catch (e: InterruptedException) {
                QrDecode.Result.Failed(QrDecode.Failure.STOPPED)
            }
            return QrDecode.answer(result, failure)
        }
    }

    /**
     * Reads [picture] with Android's image decoder, in one pass that reads from the descriptor as it comes (a file or
     * a pipe): its size from its header first, refused when it is too large, else brought down by a power of two to
     * fit [QrDecode.TARGET] as it is decoded; then the code.
     */
    private fun read(picture: ParcelFileDescriptor): QrDecode.Result {
        val source = ImageDecoder.createSource { AssetFileDescriptor(picture, 0, AssetFileDescriptor.UNKNOWN_LENGTH) }
        val bitmap = try {
            ImageDecoder.decodeBitmap(source) { decoder, info, _ ->
                val sample = QrDecode.sampleSize(info.size.width, info.size.height) ?: throw TooLarge()
                decoder.setTargetSampleSize(sample)
                // Pixels this process can read back, not a picture kept on the graphics processor.
                decoder.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
            }
        } catch (e: TooLarge) {
            return QrDecode.Result.Failed(QrDecode.Failure.TOO_LARGE)
        } catch (e: ImageDecoder.DecodeException) {
            return QrDecode.Result.Failed(QrDecode.Failure.NOT_A_PICTURE)
        } catch (e: IOException) {
            return QrDecode.Result.Failed(QrDecode.Failure.NOT_A_PICTURE)
        } catch (e: IllegalArgumentException) {
            return QrDecode.Result.Failed(QrDecode.Failure.NOT_A_PICTURE)
        }
        try {
            val (width, height) = bitmap.width to bitmap.height
            if (width.toLong() * height > QrDecode.MAX_PIXELS) return QrDecode.Result.Failed(QrDecode.Failure.TOO_LARGE)
            val pixels = IntArray(width * height)
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
            return QrDecode.decode(pixels, width, height).also { pixels.fill(0) }
        } finally {
            bitmap.recycle()
        }
    }

    /** A picture larger than the bounds, refused from its header. */
    private class TooLarge : RuntimeException()

    private fun endSoon() {
        Handler(Looper.getMainLooper()).postDelayed({ Process.killProcess(Process.myPid()) }, END_DELAY_MS)
    }

    override fun onDestroy() {
        super.onDestroy()
        reader.shutdownNow()
        // Watch let it go: the process, the only place the text was a String, ends after this call returns.
        Handler(Looper.getMainLooper()).post { Process.killProcess(Process.myPid()) }
    }

    companion object {
        /** The time a read may take, a picture's decoding included. */
        const val TIME_LIMIT_MS = 10_000L

        /** How long after a read past its time the process ends: its answer goes first. */
        private const val END_DELAY_MS = 500L
    }
}
