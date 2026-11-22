package org.visadahyu.datapavan.watch.tunnel.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.ChecksumException
import com.google.zxing.DecodeHintType
import com.google.zxing.FormatException
import com.google.zxing.LuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * Reads a WireGuard configuration's QR code from a picture's pixels with ZXing's core library (W7, part 2; ADR 0035,
 * question 10), within bounds: the picture is brought down to at most [TARGET] pixels a side before it is read, and
 * the text is at most [MAX_TEXT] bytes. It runs only in [QrService]'s isolated process, which also bounds its time;
 * pure here, for the JVM tests, which draw their pictures with ZXing's own encoder.
 */
object QrDecode {
    /** The longest side a picture is read at: a QR code that fills a third of a photo still has some ten pixels a module. */
    const val TARGET = 2_048

    /** The most pixels read, after the picture is brought down to [TARGET]. */
    const val MAX_PIXELS = TARGET * TARGET

    /** The largest picture taken at all, before it is brought down: 16,384 pixels a side, a phone camera's largest. */
    const val MAX_SIDE = 16_384

    /**
     * The longest text returned, in bytes: a QR code's largest in byte mode (version 40, level L, 2,953 bytes), which
     * a configuration, being text with small letters, always takes. A longer text is not a configuration.
     */
    const val MAX_TEXT = 2_953

    /** Why no text came. */
    enum class Failure {
        /** Not a picture Android can read. */
        NOT_A_PICTURE,

        /** Larger than [MAX_SIDE] a side, or more pixels than [MAX_PIXELS] once brought down. */
        TOO_LARGE,

        /** No QR code found, or one that does not read. */
        NO_CODE,

        /** A text longer than [MAX_TEXT]. */
        TOO_LONG,

        /** Reading took longer than its time limit. */
        TOO_SLOW,

        /** The decoder's process stopped or did not answer. */
        STOPPED,
    }

    /** The text as UTF-8 bytes, or why not. */
    sealed interface Result {
        class Text(val bytes: ByteArray) : Result
        data class Failed(val why: Failure) : Result
    }

    /**
     * The answer as the decoder's process sends it across the binder (fix round, security review m1): the text's bytes,
     * or null with the failure's number in [failure]'s first place.
     */
    fun answer(result: Result, failure: IntArray): ByteArray? = when (result) {
        is Result.Text -> result.bytes
        is Result.Failed -> {
            if (failure.isNotEmpty()) failure[0] = result.why.ordinal
            null
        }
    }

    /**
     * What Watch reads of the decoder's answer: the text, bounded again here, since a decoder a picture subverted
     * may send anything; else the failure its number names, and "stopped" for a number that names none.
     */
    fun fromAnswer(text: ByteArray?, failure: IntArray): Result {
        if (text != null) {
            if (text.size <= MAX_TEXT) return Result.Text(text)
            text.fill(0)
            return Result.Failed(Failure.TOO_LONG)
        }
        return Result.Failed(failure.firstOrNull()?.let { Failure.entries.getOrNull(it) } ?: Failure.STOPPED)
    }

    /**
     * The power of two a picture of [width] by [height] is brought down by to fit [TARGET], or null when it is
     * larger than [MAX_SIDE] a side or empty: such a picture is not read at all.
     */
    fun sampleSize(width: Int, height: Int): Int? {
        if (width <= 0 || height <= 0 || width > MAX_SIDE || height > MAX_SIDE) return null
        var size = 1
        while (width / size > TARGET || height / size > TARGET) size *= 2
        return size
    }

    /** Reads the QR code in [pixels], [width] by [height], as Android's `Bitmap.getPixels` gives them (ARGB). */
    fun decode(pixels: IntArray, width: Int, height: Int): Result {
        if (width <= 0 || height <= 0 || width.toLong() * height > MAX_PIXELS || pixels.size < width * height) {
            return Result.Failed(Failure.TOO_LARGE)
        }
        val source = RGBLuminanceSource(width, height, pixels)
        // The usual way first, then for a code drawn light on dark (a screen in dark mode), then with the binarizer
        // that copes better with an evenly lit, low-contrast photo.
        val attempts = listOf<(LuminanceSource) -> BinaryBitmap>(
            { BinaryBitmap(HybridBinarizer(it)) },
            { BinaryBitmap(HybridBinarizer(it.invert())) },
            { BinaryBitmap(GlobalHistogramBinarizer(it)) },
        )
        for (attempt in attempts) {
            val text = try {
                QRCodeReader().decode(attempt(source), HINTS).text
            } catch (e: NotFoundException) {
                continue
            } catch (e: ChecksumException) {
                continue
            } catch (e: FormatException) {
                continue
            }
            val bytes = text.toByteArray(Charsets.UTF_8)
            if (bytes.size > MAX_TEXT) {
                bytes.fill(0)
                return Result.Failed(Failure.TOO_LONG)
            }
            return Result.Text(bytes)
        }
        return Result.Failed(Failure.NO_CODE)
    }

    private val HINTS = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        DecodeHintType.TRY_HARDER to true,
        DecodeHintType.CHARACTER_SET to "UTF-8",
    )
}
