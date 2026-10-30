package org.visadahyu.datapavan.audit

import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Where the uncompressed DEX files of an APK lie in the file, so that the tracker scanner can map
 * them instead of reading them: only the pages that the parser touches are then read, and they stay
 * in the page cache, which Android can reclaim, instead of in the app's memory. Most APKs store their
 * DEX files uncompressed, because Android maps them the same way.
 *
 * Reads only the ZIP central directory and local headers, as untrusted input: anything unusual
 * (ZIP64, a split archive, a duplicate name, an offset outside its region) gives no locations, and
 * the scanner then reads the files as before. The scanner also uses a location only when
 * `java.util.zip.ZipFile` reports the same entry as stored with the same size.
 */
internal object StoredDex {
    /** [size] bytes of an uncompressed entry, starting [offset] bytes into the file. */
    data class Location(val offset: Long, val size: Int)

    /** The stored `classes*.dex` entries of [file] by name, or an empty map when the directory is unusual. */
    fun locate(file: RandomAccessFile): Map<String, Location> = try {
        read(file) ?: emptyMap()
    } catch (_: IOException) {
        emptyMap()
    } catch (_: IndexOutOfBoundsException) {
        emptyMap()
    }

    private fun read(file: RandomAccessFile): Map<String, Location>? {
        val length = file.length()
        val tail = bytes(file, maxOf(0, length - MAX_END_RECORD), minOf(length, MAX_END_RECORD).toInt())
        // The end record is the last one whose comment runs exactly to the end of the file.
        val end = (tail.limit() - END_RECORD_SIZE downTo 0).firstOrNull { at ->
            tail.getInt(at) == END_SIGNATURE && at + END_RECORD_SIZE + tail.u16(at + 20) == tail.limit()
        } ?: return null
        val endOffset = length - tail.limit() + end
        val sameDisk = tail.u16(end + 4) == 0 && tail.u16(end + 6) == 0 && tail.u16(end + 8) == tail.u16(end + 10)
        val count = tail.u16(end + 10)
        val directorySize = tail.u32(end + 12)
        val directoryOffset = tail.u32(end + 16)
        // 0xffff and 0xffffffff mark ZIP64 values, which installed APKs do not need.
        if (!sameDisk || count == 0xffff || directorySize == 0xffffffffL || directoryOffset == 0xffffffffL) return null
        if (directorySize > MAX_DIRECTORY || directoryOffset + directorySize > endOffset) return null
        val directory = bytes(file, directoryOffset, directorySize.toInt())
        val found = HashMap<String, Location>()
        val names = HashSet<String>()
        var at = 0
        repeat(count) {
            if (at + ENTRY_SIZE > directory.limit() || directory.getInt(at) != ENTRY_SIGNATURE) return null
            val method = directory.u16(at + 10)
            val compressed = directory.u32(at + 20)
            val size = directory.u32(at + 24)
            val nameLength = directory.u16(at + 28)
            val next = at + ENTRY_SIZE + nameLength + directory.u16(at + 30) + directory.u16(at + 32)
            if (next > directory.limit()) return null
            val name = String(directory.array(), at + ENTRY_SIZE, nameLength, Charsets.UTF_8)
            if (!names.add(name)) return null
            val localOffset = directory.u32(at + 42)
            if (DEX.matches(name) && method == STORED && compressed == size && size in 1..MAX_DEX) {
                val local = bytes(file, localOffset, LOCAL_SIZE)
                if (local.getInt(0) != LOCAL_SIGNATURE) return null
                val data = localOffset + LOCAL_SIZE + local.u16(26) + local.u16(28)
                if (data + size > directoryOffset) return null
                found[name] = Location(data, size.toInt())
            }
            at = next
        }
        return found
    }

    /** [size] bytes of [file] from [offset], little-endian; fails if the file is shorter. */
    private fun bytes(file: RandomAccessFile, offset: Long, size: Int): ByteBuffer {
        if (offset < 0 || offset + size > file.length()) throw IOException("outside the file")
        val array = ByteArray(size)
        file.seek(offset)
        file.readFully(array)
        return ByteBuffer.wrap(array).order(ByteOrder.LITTLE_ENDIAN)
    }

    private fun ByteBuffer.u16(at: Int): Int = getShort(at).toInt() and 0xffff
    private fun ByteBuffer.u32(at: Int): Long = getInt(at).toLong() and 0xffffffffL

    private const val END_SIGNATURE = 0x06054b50
    private const val ENTRY_SIGNATURE = 0x02014b50
    private const val LOCAL_SIGNATURE = 0x04034b50
    private const val END_RECORD_SIZE = 22
    private const val ENTRY_SIZE = 46
    private const val LOCAL_SIZE = 30
    private const val MAX_END_RECORD = END_RECORD_SIZE + 0xffffL
    private const val MAX_DIRECTORY = 64L * 1024 * 1024
    private const val MAX_DEX = 48L * 1024 * 1024
    private const val STORED = 0
    private val DEX = Regex("classes\\d*\\.dex")
}
