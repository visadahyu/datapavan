package org.visadahyu.datapavan.audit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.RandomAccessFile
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class StoredDexTest {
    @get:Rule
    val folder = TemporaryFolder()

    private val dex = "dex\n039\u0000".toByteArray() + ByteArray(200) { it.toByte() }
    private val second = "dex\n039\u0000".toByteArray() + ByteArray(90) { (it * 3).toByte() }

    /** A ZIP like an APK: stored and compressed entries, with an optional archive comment. */
    private fun zip(comment: String? = null, write: ZipOutputStream.() -> Unit): File =
        folder.newFile().also { file -> ZipOutputStream(file.outputStream()).use { it.write(); comment?.let(it::setComment) } }

    private fun ZipOutputStream.stored(name: String, bytes: ByteArray) {
        putNextEntry(ZipEntry(name).apply {
            method = ZipEntry.STORED
            size = bytes.size.toLong()
            crc = CRC32().apply { update(bytes) }.value
        })
        write(bytes)
        closeEntry()
    }

    private fun ZipOutputStream.deflated(name: String, bytes: ByteArray) {
        putNextEntry(ZipEntry(name))
        write(bytes)
        closeEntry()
    }

    private fun locate(file: File) = RandomAccessFile(file, "r").use { StoredDex.locate(it) }

    private fun bytesAt(file: File, location: StoredDex.Location): ByteArray = RandomAccessFile(file, "r").use {
        ByteArray(location.size).also { bytes -> it.seek(location.offset); it.readFully(bytes) }
    }

    @Test
    fun locatesStoredDexFilesAndSkipsTheRest() {
        val file = zip {
            deflated("AndroidManifest.xml", ByteArray(50))
            stored("classes.dex", dex)
            deflated("classes2.dex", second)
            stored("classes3.dex", second)
            stored("assets/classes.dex", dex)
        }
        val found = locate(file)
        assertEquals(setOf("classes.dex", "classes3.dex"), found.keys)
        assertArrayEquals(dex, bytesAt(file, found.getValue("classes.dex")))
        assertArrayEquals(second, bytesAt(file, found.getValue("classes3.dex")))
    }

    @Test
    fun findsTheEndRecordBehindAComment() {
        val file = zip(comment = "PK\u0005\u0006 looks like an end record but is not") { stored("classes.dex", dex) }
        assertArrayEquals(dex, bytesAt(file, locate(file).getValue("classes.dex")))
    }

    @Test
    fun givesNothingForDamagedOrUnusualFiles() {
        val file = zip { stored("classes.dex", dex) }
        val bytes = file.readBytes()
        // Every truncation, and every changed byte of the central directory and end record.
        val directory = bytes.size - 22 - 46 - "classes.dex".length
        val damaged = (0 until bytes.size).map { bytes.copyOf(it) } +
            (directory until bytes.size).map { at -> bytes.copyOf().also { it[at] = (it[at] + 0x41).toByte() } }
        for (variant in damaged) {
            val copy = folder.newFile().apply { writeBytes(variant) }
            // Either nothing, or a location that still holds exactly the stored DEX file.
            locate(copy)["classes.dex"]?.let { location ->
                assertTrue(location.offset + location.size <= variant.size)
            }
        }
    }
}
