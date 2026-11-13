package org.visadahyu.datapavan.audit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
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

    private fun directory(file: File) = RandomAccessFile(file, "r").use { StoredDex.directory(it.channel) }

    private fun read(file: File, entry: StoredDex.DexEntry) = RandomAccessFile(file, "r").use { StoredDex.read(it.channel, entry) }

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

    @Test
    fun readsStoredAndDeflatedDexFilesWithEveryName() {
        val file = zip {
            deflated("AndroidManifest.xml", ByteArray(50))
            stored("classes.dex", dex)
            deflated("classes2.dex", second)
            deflated("lib/arm64-v8a/libexample.so", ByteArray(10))
        }
        val found = directory(file)!!
        assertTrue(found.complete)
        assertEquals(listOf("AndroidManifest.xml", "classes.dex", "classes2.dex", "lib/arm64-v8a/libexample.so"), found.names)
        assertEquals(listOf(true, false), found.dex.map { it.stored })
        assertArrayEquals(dex, read(file, found.dex.first { it.name == "classes.dex" }))
        assertArrayEquals(second, read(file, found.dex.first { it.name == "classes2.dex" }))
    }

    @Test
    fun refusesADexFileThatDoesNotMatchItsDirectory() {
        val file = zip { deflated("classes.dex", second) }
        val entry = directory(file)!!.dex.single()
        for (wrong in listOf(entry.copy(crc = entry.crc xor 1), entry.copy(size = entry.size + 1), entry.copy(size = entry.size - 1))) {
            assertThrows(IOException::class.java) { read(file, wrong) }
        }
        // Every changed byte of the compressed data either fails or still gives the same bytes.
        val bytes = file.readBytes()
        for (at in entry.offset until entry.offset + entry.compressedSize) {
            val copy = folder.newFile().apply { writeBytes(bytes.copyOf().also { it[at.toInt()] = (it[at.toInt()] + 1).toByte() }) }
            try {
                assertArrayEquals(second, read(copy, entry))
            } catch (_: IOException) {
                // Refused, as it should be.
            }
        }
    }

    @Test
    fun marksTheDirectoryIncompleteForADexFileTooLargeToRead() {
        val bytes = zip { deflated("classes.dex", second) }.readBytes()
        // The central directory's entry: its uncompressed size, at offset 24, set beyond the limit.
        val entry = (bytes.size - 22 downTo 0).first { at ->
            bytes[at] == 0x50.toByte() && bytes[at + 1] == 0x4b.toByte() && bytes[at + 2] == 1.toByte() && bytes[at + 3] == 2.toByte()
        }
        val huge = StoredDex.MAX_DEX + 1
        for (i in 0 until 4) bytes[entry + 24 + i] = (huge shr (8 * i)).toByte()
        val copy = folder.newFile().apply { writeBytes(bytes) }
        assertFalse(directory(copy)!!.complete)
    }
}
