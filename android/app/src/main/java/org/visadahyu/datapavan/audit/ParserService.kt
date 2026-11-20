package org.visadahyu.datapavan.audit

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import org.visadahyu.datapavan.core.NativeCore
import java.io.FileDescriptor
import java.io.IOException
import java.nio.channels.FileChannel

/**
 * The audit's parsers of untrusted input, in an isolated process of their own (ADR 0045, decision 9), as
 * Android's media extractor parses media: the DEX files and ZIP directories of other apps' APKs, and the
 * key-attestation extension. An isolated process has no permissions, no network and none of the app's
 * files; it gets each APK as a read-only file descriptor and gives back only numbers and names. A parser
 * that some crafted APK could subvert then holds nothing worth taking, and cannot change the audit's
 * verdicts except for that one app. Bound only by the audit (Parsers.kt); an isolated service cannot be
 * exported.
 */
class ParserService : Service() {
    override fun onBind(intent: Intent): IBinder = object : IParser.Stub() {
        override fun loadSignatures(tsv: String): Boolean = try {
            NativeCore.loadTrackers(tsv)
            true
        } catch (_: RuntimeException) {
            false
        }

        override fun scanApk(apk: ParcelFileDescriptor, libraries: MutableList<String>): IntArray? {
            val scan = ApkScan.scan(apk) ?: return null
            libraries.addAll(scan.libraries)
            return ApkScan.encode(scan)
        }

        override fun parseAttestation(extension: ByteArray): ByteArray? = try {
            NativeCore.parseAttestation(extension)
        } catch (_: RuntimeException) {
            null
        }
    }
}

/**
 * One APK's scan, in the parsers' process ([scan]), and as it crosses the binder: primitives only (W7, part 2, fix
 * round, security review m1), the tracker ids as [encode] writes them and the libraries' names as a list of strings,
 * which the audit reads back with [decode].
 */
internal object ApkScan {
    /**
     * What a scan found: the tracker ids whose code the APK contains ([embedded]), those its code only refers to
     * ([referenced]), and the names of its entries under lib/, for the native-library signatures
     * (SdkList.nativeMatches).
     */
    class Result(val embedded: IntArray, val referenced: IntArray, val libraries: List<String>)

    /** The ids as they cross the binder: the count of embedded ids, those ids, then the referenced ones. */
    fun encode(scan: Result): IntArray = intArrayOf(scan.embedded.size) + scan.embedded + scan.referenced

    /**
     * What the audit reads of the parsers' answer: null, as for an APK that could not be read, where [ids] is
     * missing or its count does not fit it, since a subverted parser may send anything.
     */
    fun decode(ids: IntArray?, libraries: List<String>): Result? {
        val count = ids?.firstOrNull() ?: return null
        if (count < 0 || count > ids.size - 1) return null
        return Result(ids.copyOfRange(1, 1 + count), ids.copyOfRange(1 + count, ids.size), libraries)
    }

    /** Scans [apk] and closes it: null when it could not be read. */
    fun scan(apk: ParcelFileDescriptor): Result? = ParcelFileDescriptor.AutoCloseInputStream(apk).use { stream ->
        try {
            scan(stream.channel, apk.fileDescriptor)
        } catch (_: IOException) {
            null
        } catch (_: RuntimeException) {
            // A malformed DEX file, reported by the Rust parser.
            null
        }
    }

    private fun scan(channel: FileChannel, fd: FileDescriptor): Result? {
        val directory = StoredDex.directory(channel) ?: return null
        if (!directory.complete) return null
        val embedded = sortedSetOf<Int>()
        val referenced = sortedSetOf<Int>()
        for (entry in directory.dex) {
            val found = (if (entry.stored) scanMapped(fd, entry) else null) ?: NativeCore.scanDex(StoredDex.read(channel, entry))
            val count = found.firstOrNull() ?: 0
            embedded += found.drop(1).take(count)
            referenced += found.drop(1 + count)
        }
        return Result(embedded.toIntArray(), referenced.toIntArray(), directory.names.filter { it.startsWith("lib/") })
    }

    /**
     * Scans a stored DEX file through a read-only mapping of its bytes in the APK, so that only the pages
     * the parser needs are read. Null when the mapping fails; the file is then read instead.
     */
    private fun scanMapped(fd: FileDescriptor, entry: StoredDex.DexEntry): IntArray? {
        val start = entry.offset - entry.offset % pageSize
        val length = entry.offset - start + entry.size
        val address = try {
            Os.mmap(0, length, OsConstants.PROT_READ, OsConstants.MAP_PRIVATE, fd, start)
        } catch (_: ErrnoException) {
            return null
        }
        try {
            return NativeCore.scanMappedDex(address + (entry.offset - start), entry.size)
        } finally {
            try {
                Os.munmap(address, length)
            } catch (_: ErrnoException) {
                // Nothing to undo: the mapping is gone with the process at the latest.
            }
        }
    }

    private val pageSize: Long by lazy { Os.sysconf(OsConstants._SC_PAGESIZE) }
}
