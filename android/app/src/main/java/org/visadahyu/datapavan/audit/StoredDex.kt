package org.visadahyu.datapavan.audit

import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.util.zip.CRC32
import java.util.zip.DataFormatException
import java.util.zip.Inflater

/**
 * The ZIP directory of an APK, read from an open file as untrusted input: every entry's name, and where
 * each DEX file lies and how it is stored. The parsers' isolated process (ParserService) reads APKs this
 * way, since it is given a file descriptor and may not open files by name. Uncompressed DEX files can then
 * be mapped instead of read: only the pages the parser needs are read, and they stay in the page cache,
 * which Android can reclaim, instead of in memory. Most APKs store their DEX files uncompressed, because
 * Android maps them the same way.
 *
 * Reads only the central directory and the local headers of DEX files. Anything unusual (ZIP64, a split
 * archive, a duplicate name, an offset outside its region) gives no directory, and a DEX file stored in
 * any way but stored or deflated, or larger than [MAX_DEX], marks the directory incomplete: the app is
 * then reported as one whose code could not be read.
 */
internal object StoredDex {
    /** [size] bytes of an uncompressed entry, starting [offset] bytes into the file. */
    data class Location(val offset: Long, val size: Int)

    /** A DEX file: where its data lies, whether it is stored uncompressed, its sizes and its CRC-32. */
    data class DexEntry(val name: String, val stored: Boolean, val offset: Long, val compressedSize: Long, val size: Int, val crc: Long)

    /** Every entry name of an APK, and its DEX files; [complete] is false when one of them cannot be read. */
    class Directory(val names: List<String>, val dex: List<DexEntry>, val complete: Boolean)

    /** The stored `classes*.dex` entries of [file] by name, or an empty map when the directory is unusual. */
    fun locate(file: RandomAccessFile): Map<String, Location> =
        directory(file.channel)?.dex.orEmpty().filter { it.stored }.associate { it.name to Location(it.offset, it.size) }

    /** The directory of the ZIP file open as [channel], or null when it is unusual or damaged. */
    fun directory(channel: FileChannel): Directory? = try {
        read(channel)
    } catch (_: IOException) {
        null
    } catch (_: IndexOutOfBoundsException) {
        null
    }

    /**
     * The bytes of [entry], inflated if it is compressed, checked against its size and CRC-32. Throws an
     * IOException when they do not match or the data is damaged.
     */
    fun read(channel: FileChannel, entry: DexEntry): ByteArray {
        val data = ByteArray(entry.size)
        if (entry.stored) {
            bytes(channel, entry.offset, entry.size).get(data)
        } else {
            val inflater = Inflater(true)
            try {
                var position = entry.offset
                var left = entry.compressedSize
                var written = 0
                var padded = false
                val chunk = ByteArray(INFLATE_CHUNK)
                while (!inflater.finished()) {
                    if (inflater.needsInput()) {
                        if (left > 0) {
                            val take = minOf(left, INFLATE_CHUNK.toLong()).toInt()
                            bytes(channel, position, take).get(chunk, 0, take)
                            inflater.setInput(chunk, 0, take)
                            position += take
                            left -= take
                        } else if (!padded) {
                            // Raw deflate may want one byte past its data, as java.util.zip.ZipFile gives it.
                            inflater.setInput(ByteArray(1))
                            padded = true
                        } else {
                            throw IOException("${entry.name}: ends before its data does")
                        }
                    }
                    if (inflater.needsDictionary()) throw IOException("${entry.name}: asks for a dictionary")
                    // When full, the stream must end without one more byte of output.
                    val made = if (written == data.size) inflater.inflate(ByteArray(1)) else inflater.inflate(data, written, data.size - written)
                    if (written == data.size && made != 0) throw IOException("${entry.name}: larger than its directory says")
                    if (made == 0 && !inflater.finished() && !inflater.needsInput() && !inflater.needsDictionary()) {
                        throw IOException("${entry.name}: damaged")
                    }
                    written += if (written == data.size) 0 else made
                }
                if (written != data.size) throw IOException("${entry.name}: smaller than its directory says")
            } catch (e: DataFormatException) {
                throw IOException("${entry.name}: damaged", e)
            } finally {
                inflater.end()
            }
        }
        if (CRC32().apply { update(data) }.value != entry.crc) throw IOException("${entry.name}: wrong CRC-32")
        return data
    }

    private fun read(channel: FileChannel): Directory? {
        val length = channel.size()
        val tail = bytes(channel, maxOf(0, length - MAX_END_RECORD), minOf(length, MAX_END_RECORD).toInt())
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
        val directory = bytes(channel, directoryOffset, directorySize.toInt())
        val dex = ArrayList<DexEntry>()
        val names = LinkedHashSet<String>()
        var complete = true
        var at = 0
        repeat(count) {
            if (at + ENTRY_SIZE > directory.limit() || directory.getInt(at) != ENTRY_SIGNATURE) return null
            val method = directory.u16(at + 10)
            val crc = directory.u32(at + 16)
            val compressed = directory.u32(at + 20)
            val size = directory.u32(at + 24)
            val nameLength = directory.u16(at + 28)
            val next = at + ENTRY_SIZE + nameLength + directory.u16(at + 30) + directory.u16(at + 32)
            if (next > directory.limit()) return null
            val name = String(directory.array(), at + ENTRY_SIZE, nameLength, Charsets.UTF_8)
            if (!names.add(name)) return null
            val localOffset = directory.u32(at + 42)
            if (DEX.matches(name)) {
                val stored = method == STORED && compressed == size
                if ((stored || method == DEFLATED) && size in 1..MAX_DEX && compressed in 1..MAX_COMPRESSED) {
                    val local = bytes(channel, localOffset, LOCAL_SIZE)
                    if (local.getInt(0) != LOCAL_SIGNATURE) return null
                    val data = localOffset + LOCAL_SIZE + local.u16(26) + local.u16(28)
                    if (data + compressed > directoryOffset) return null
                    dex += DexEntry(name, stored, data, compressed, size.toInt(), crc)
                } else {
                    complete = false
                }
            }
            at = next
        }
        return Directory(names.toList(), dex, complete)
    }

    /** [size] bytes of [channel] from [offset], little-endian; fails if the file is shorter. */
    private fun bytes(channel: FileChannel, offset: Long, size: Int): ByteBuffer {
        if (offset < 0 || size < 0 || offset + size > channel.size()) throw IOException("outside the file")
        val buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN)
        while (buffer.hasRemaining()) {
            if (channel.read(buffer, offset + buffer.position()) < 0) throw IOException("the file ended")
        }
        return buffer.flip() as ByteBuffer
    }

    private fun ByteBuffer.u16(at: Int): Int = getShort(at).toInt() and 0xffff
    private fun ByteBuffer.u32(at: Int): Long = getInt(at).toLong() and 0xffffffffL

    /** The largest DEX file read; a larger one could exhaust memory, so it makes the app unreadable. */
    const val MAX_DEX = 48L * 1024 * 1024
    private const val MAX_COMPRESSED = MAX_DEX + 1024 * 1024
    private const val END_SIGNATURE = 0x06054b50
    private const val ENTRY_SIGNATURE = 0x02014b50
    private const val LOCAL_SIGNATURE = 0x04034b50
    private const val END_RECORD_SIZE = 22
    private const val ENTRY_SIZE = 46
    private const val LOCAL_SIZE = 30
    private const val MAX_END_RECORD = END_RECORD_SIZE + 0xffffL
    private const val MAX_DIRECTORY = 64L * 1024 * 1024
    private const val INFLATE_CHUNK = 64 * 1024
    private const val STORED = 0
    private const val DEFLATED = 8
    private val DEX = Regex("classes\\d*\\.dex")
}
