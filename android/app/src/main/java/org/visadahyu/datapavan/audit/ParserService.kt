package org.visadahyu.datapavan.audit

import android.app.Service
import android.content.Intent
import android.os.Bundle
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

        override fun scanApk(apk: ParcelFileDescriptor): Bundle = ApkScan.scan(apk)

        override fun parseAttestation(extension: ByteArray): LongArray? = try {
            NativeCore.parseAttestation(extension)
        } catch (_: RuntimeException) {
            null
        }
    }
}

/** One APK's scan, in the parsers' process: what [scan] returns, under these keys. */
internal object ApkScan {
    /** Whether the APK could not be read; then the other keys are absent. */
    const val UNREADABLE = "unreadable"

    /** The tracker ids whose code the APK contains, as an IntArray. */
    const val EMBEDDED = "embedded"

    /** The tracker ids its code only refers to, as an IntArray. */
    const val REFERENCED = "referenced"

    /** The names of its entries under lib/, for the native-library signatures (SdkList.nativeMatches). */
    const val LIBRARIES = "libraries"

    /** Scans [apk] and closes it. */
    fun scan(apk: ParcelFileDescriptor): Bundle = ParcelFileDescriptor.AutoCloseInputStream(apk).use { stream ->
        try {
            scan(stream.channel, apk.fileDescriptor)
        } catch (_: IOException) {
            unreadable()
        } catch (_: RuntimeException) {
            // A malformed DEX file, reported by the Rust parser.
            unreadable()
        }
    }

    private fun scan(channel: FileChannel, fd: FileDescriptor): Bundle {
        val directory = StoredDex.directory(channel) ?: return unreadable()
        if (!directory.complete) return unreadable()
        val embedded = sortedSetOf<Int>()
        val referenced = sortedSetOf<Int>()
        for (entry in directory.dex) {
            val found = (if (entry.stored) scanMapped(fd, entry) else null) ?: NativeCore.scanDex(StoredDex.read(channel, entry))
            val count = found.firstOrNull() ?: 0
            embedded += found.drop(1).take(count)
            referenced += found.drop(1 + count)
        }
        return Bundle().apply {
            putIntArray(EMBEDDED, embedded.toIntArray())
            putIntArray(REFERENCED, referenced.toIntArray())
            putStringArrayList(LIBRARIES, ArrayList(directory.names.filter { it.startsWith("lib/") }))
        }
    }

    private fun unreadable() = Bundle().apply { putBoolean(UNREADABLE, true) }

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
