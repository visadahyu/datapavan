package org.visadahyu.datapavan.network.tunnel.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.File
import java.nio.file.Files
import kotlin.random.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The QR decoder's rules (W7, part 2), on pictures ZXing's own encoder draws in the test: a configuration reads back
 * byte for byte, also drawn light on dark and scaled; a wrong picture, one past the bounds, a barcode that is not a
 * QR code and a text too long give no text; random pixels within the bounds never do; and the camera's photo is
 * deleted on every path.
 */
class QrDecodeTest {
    private val configuration = """
        [Interface]
        PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
        Address = 10.2.0.2/32
        DNS = 10.2.0.1

        [Peer]
        PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
        AllowedIPs = 0.0.0.0/0, ::/0
        Endpoint = 198.51.100.7:51820
    """.trimIndent()

    /** The pixels of [text]'s QR code, [scale] pixels a module, dark on light or the other way, with a margin. */
    private fun qr(
        text: String,
        scale: Int = 4,
        inverted: Boolean = false,
        level: ErrorCorrectionLevel = ErrorCorrectionLevel.M,
        utf8: Boolean = true,
    ): Triple<IntArray, Int, Int> {
        // Without the hint, as WireGuard's app writes its codes, ZXing writes bytes with no ECI header.
        val hints = mapOf(EncodeHintType.ERROR_CORRECTION to level, EncodeHintType.MARGIN to 4) +
            (if (utf8) mapOf(EncodeHintType.CHARACTER_SET to "UTF-8") else emptyMap())
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
        return draw(matrix.width, matrix.height, scale, inverted) { x, y -> matrix[x, y] }
    }

    private fun draw(width: Int, height: Int, scale: Int, inverted: Boolean, dark: (Int, Int) -> Boolean): Triple<IntArray, Int, Int> {
        val (w, h) = width * scale to height * scale
        val pixels = IntArray(w * h) { i ->
            val on = dark((i % w) / scale, (i / w) / scale) != inverted
            if (on) 0xff000000.toInt() else 0xffffffff.toInt()
        }
        return Triple(pixels, w, h)
    }

    private fun decode(picture: Triple<IntArray, Int, Int>) = QrDecode.decode(picture.first, picture.second, picture.third)

    @Test
    fun a_configuration_reads_back_byte_for_byte() {
        val read = decode(qr(configuration))
        assertTrue(read is QrDecode.Result.Text)
        assertArrayEquals(configuration.toByteArray(), (read as QrDecode.Result.Text).bytes)
        val dark = decode(qr(configuration, scale = 3, inverted = true))
        assertArrayEquals("drawn light on dark, as a screen in dark mode shows it", configuration.toByteArray(), (dark as QrDecode.Result.Text).bytes)
        val text = "Name 名前 اسم\n$configuration"
        assertArrayEquals("UTF-8 kept", text.toByteArray(), (decode(qr(text)) as QrDecode.Result.Text).bytes)
    }

    @Test
    fun a_wrong_picture_gives_no_text() {
        val blank = Triple(IntArray(400 * 400) { 0xffffffff.toInt() }, 400, 400)
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.NO_CODE), decode(blank))
        // A QR code with a corner torn off past what its correction mends.
        val (pixels, w, h) = qr(configuration, scale = 4, level = ErrorCorrectionLevel.L)
        for (y in 0 until h / 2) for (x in 0 until w / 2) pixels[y * w + x] = 0xffffffff.toInt()
        assertFalse(decode(Triple(pixels, w, h)) is QrDecode.Result.Text)
    }

    @Test
    fun a_barcode_that_is_not_a_qr_code_gives_no_text() {
        for (format in listOf(BarcodeFormat.DATA_MATRIX, BarcodeFormat.CODE_128, BarcodeFormat.AZTEC, BarcodeFormat.PDF_417)) {
            val contents = if (format == BarcodeFormat.CODE_128) "WIREGUARD-12345" else configuration
            val matrix = MultiFormatWriter().encode(contents, format, 0, 0)
            val picture = draw(matrix.width, matrix.height + (if (format == BarcodeFormat.CODE_128) 40 else 0), 3, false) { x, y ->
                matrix[x, y.coerceAtMost(matrix.height - 1)]
            }
            assertEquals(format.name, QrDecode.Result.Failed(QrDecode.Failure.NO_CODE), decode(picture))
        }
    }

    @Test
    fun a_text_longer_than_a_configuration_can_be_is_refused() {
        // Digits pack tighter than text: 4,000 of them fit a QR code, more than the 2,953 bytes any text may take.
        val digits = (1..4_000).joinToString("") { (it % 10).toString() }
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.TOO_LONG), decode(qr(digits, scale = 2, level = ErrorCorrectionLevel.L)))
        val longest = "a".repeat(QrDecode.MAX_TEXT)
        assertTrue("the longest a configuration can be still reads", decode(qr(longest, scale = 2, level = ErrorCorrectionLevel.L, utf8 = false)) is QrDecode.Result.Text)
    }

    @Test
    fun a_picture_past_the_bounds_is_not_read() {
        assertNull(QrDecode.sampleSize(QrDecode.MAX_SIDE + 1, 10))
        assertNull(QrDecode.sampleSize(10, 0))
        assertEquals(1, QrDecode.sampleSize(QrDecode.TARGET, QrDecode.TARGET))
        assertEquals(2, QrDecode.sampleSize(QrDecode.TARGET + 1, 100))
        assertEquals("a tall picture too", 2, QrDecode.sampleSize(100, QrDecode.TARGET + 1))
        assertEquals(8, QrDecode.sampleSize(QrDecode.MAX_SIDE, QrDecode.MAX_SIDE))
        // Brought down, every allowed size fits the pixel bound.
        for ((w, h) in listOf(16_384 to 16_384, 12_000 to 9_000, 4_000 to 3_000, 4_097 to 4_097)) {
            val s = QrDecode.sampleSize(w, h) ?: error("refused $w x $h")
            assertTrue("$w x $h by $s", (w / s).toLong() * (h / s) <= QrDecode.MAX_PIXELS)
        }
        val side = QrDecode.TARGET + 1
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.TOO_LARGE), QrDecode.decode(IntArray(1), side, side))
        assertEquals("all its pixels given", QrDecode.Result.Failed(QrDecode.Failure.TOO_LARGE), QrDecode.decode(IntArray(side * side), side, side))
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.TOO_LARGE), QrDecode.decode(IntArray(10), 100, 100))
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.TOO_LARGE), QrDecode.decode(IntArray(0), 0, 0))
    }

    @Test
    fun random_pixels_within_the_bounds_give_no_text_and_no_crash() {
        val random = Random(20261120)
        repeat(60) {
            val w = random.nextInt(1, 300)
            val h = random.nextInt(1, 300)
            val pixels = IntArray(w * h) { random.nextInt() }
            assertFalse(decode(Triple(pixels, w, h)) is QrDecode.Result.Text)
        }
        // A QR code with random modules flipped: it may read or not, but never throws.
        repeat(20) {
            val (pixels, w, h) = qr(configuration, scale = 2)
            repeat(random.nextInt(1, 400)) { pixels[random.nextInt(pixels.size)] = random.nextInt() }
            decode(Triple(pixels, w, h))
        }
    }

    /**
     * The decoder's answer crosses the binder as primitives (fix round, security review m1): the text, or the failure's
     * number; the network part bounds the text again and reads a number that names no failure as "stopped".
     */
    @Test
    fun the_decoders_answer_is_primitives_and_the_caller_bounds_it_again() {
        val failure = IntArray(1) { -1 }
        val text = "[Interface]".toByteArray()
        val sent = QrDecode.answer(QrDecode.Result.Text(text), failure)
        assertTrue(sent.contentEquals(text))
        assertTrue((QrDecode.fromAnswer(sent, failure) as QrDecode.Result.Text).bytes.contentEquals(text))
        for (why in QrDecode.Failure.entries) {
            val number = IntArray(1)
            assertNull(QrDecode.answer(QrDecode.Result.Failed(why), number))
            assertEquals(QrDecode.Result.Failed(why), QrDecode.fromAnswer(null, number))
        }
        val tooLong = ByteArray(QrDecode.MAX_TEXT + 1) { 'a'.code.toByte() }
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.TOO_LONG), QrDecode.fromAnswer(tooLong, failure))
        assertTrue("zeroed", tooLong.all { it == 0.toByte() })
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.STOPPED), QrDecode.fromAnswer(null, intArrayOf(99)))
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.STOPPED), QrDecode.fromAnswer(null, intArrayOf(-1)))
        assertEquals(QrDecode.Result.Failed(QrDecode.Failure.STOPPED), QrDecode.fromAnswer(null, IntArray(0)))
    }

    @Test
    fun the_photo_is_deleted_on_every_path() {
        val dir = Files.createTempDirectory("capture").toFile()
        try {
            fun photo() = File(dir, "photo.jpg").apply { writeBytes(byteArrayOf(1, 2, 3)) }
            var file = photo()
            assertEquals("read", Capture.finish(file, taken = true) { "read" })
            assertFalse("after a read", file.exists())
            file = photo()
            assertNull(Capture.finish(file, taken = false) { "read" })
            assertFalse("after a cancel", file.exists())
            file = File(dir, "empty.jpg").apply { createNewFile() }
            assertNull(Capture.finish(file, taken = true) { "read" })
            assertFalse("after an empty answer", file.exists())
            file = photo()
            assertEquals(QrDecode.Result.Failed(QrDecode.Failure.NO_CODE), Capture.finish(file, taken = true) { QrDecode.Result.Failed(QrDecode.Failure.NO_CODE) })
            assertFalse("after a failed read", file.exists())
            file = photo()
            try {
                Capture.finish(file, taken = true) { throw IllegalStateException("the reader broke") }
            } catch (e: IllegalStateException) {
                // Expected.
            }
            assertFalse("after a read that threw", file.exists())
            // At the next start, every photo a crash left goes, but the one a camera may still be writing.
            val left = photo()
            val writing = File(dir, "writing.jpg").apply { writeBytes(byteArrayOf(4)) }
            Capture.deleteLeftovers(dir, keep = writing.name)
            assertFalse("a photo a crash left", left.exists())
            assertTrue("the photo a camera is writing", writing.exists())
            // A screen that finishes while the camera has the photo takes the grant back and deletes it (m7), also
            // where taking the grant back fails.
            var revoked = false
            Capture.abandon(writing) { revoked = true }
            assertTrue("the grant taken back", revoked)
            assertFalse("the photo the camera never answered for", writing.exists())
            file = photo()
            try {
                Capture.abandon(file) { throw SecurityException("no grant") }
            } catch (e: SecurityException) {
                // Expected.
            }
            assertFalse("after a revoke that threw", file.exists())
        } finally {
            dir.deleteRecursively()
        }
    }
}
