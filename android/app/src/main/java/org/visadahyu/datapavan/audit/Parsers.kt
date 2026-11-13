package org.visadahyu.datapavan.audit

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.DeadObjectException
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * The audit's side of its parsers' isolated process (ParserService). Binds on first use, binds again if
 * that process dies (a crafted APK may crash it), loads the signatures again then, and unbinds on [close].
 * Every call blocks, so it must not be made on the main thread, where Android delivers the binding.
 * A call that fails throws a RemoteException; the caller reports what it was reading as unreadable.
 */
internal class Parsers(context: Context) : AutoCloseable {
    private val context = context.applicationContext
    private val lock = Any()

    @Volatile
    private var parser: IParser? = null
    private var connection: ServiceConnection? = null
    private var signatures: String? = null

    /** Loads the tracker signatures into the parsers' engine, now and after every new binding. */
    fun loadSignatures(tsv: String): Boolean {
        val loaded = call { it.loadSignatures(tsv) }
        if (loaded) synchronized(lock) { signatures = tsv }
        return loaded
    }

    /** Scans the APK at [path] (ApkScan has the result's keys). */
    fun scanApk(path: String): Bundle = ParcelFileDescriptor.open(java.io.File(path), ParcelFileDescriptor.MODE_READ_ONLY).use { apk ->
        call { it.scanApk(apk) }
    }

    /** The fields of a KeyDescription extension (NativeCore.parseAttestation), or null when it is malformed. */
    fun parseAttestation(extension: ByteArray): LongArray? = call { it.parseAttestation(extension) }

    override fun close() = synchronized(lock) { disconnect() }

    /** Runs [block] on the parser, binding again once if its process died. */
    private fun <T> call(block: (IParser) -> T): T {
        try {
            return block(connected())
        } catch (_: DeadObjectException) {
            synchronized(lock) { parser = null }
        }
        return block(connected())
    }

    private fun connected(): IParser = synchronized(lock) {
        parser?.takeIf { it.asBinder().isBinderAlive }?.let { return it }
        check(Looper.myLooper() != Looper.getMainLooper()) { "The parsers bind off the main thread only" }
        disconnect()
        val ready = LinkedBlockingQueue<Result<IParser>>(1)
        val binding = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                ready.offer(Result.success(IParser.Stub.asInterface(service)))
            }

            override fun onServiceDisconnected(name: ComponentName) {
                parser = null
            }

            override fun onBindingDied(name: ComponentName) {
                parser = null
                ready.offer(Result.failure(RemoteException("the parsers' process died while binding")))
            }

            override fun onNullBinding(name: ComponentName) {
                ready.offer(Result.failure(RemoteException("the parsers gave no binder")))
            }
        }
        connection = binding
        if (!context.bindService(Intent(context, ParserService::class.java), binding, Context.BIND_AUTO_CREATE)) {
            disconnect()
            throw RemoteException("the parsers' service could not be bound")
        }
        val bound = ready.poll(BIND_SECONDS, TimeUnit.SECONDS)?.getOrNull()
        if (bound == null) {
            disconnect()
            throw RemoteException("the parsers' service did not answer")
        }
        signatures?.let { tsv ->
            if (!bound.loadSignatures(tsv)) {
                disconnect()
                throw RemoteException("the parsers could not load the signatures again")
            }
        }
        parser = bound
        bound
    }

    private fun disconnect() {
        connection?.let { binding ->
            try {
                context.unbindService(binding)
            } catch (_: IllegalArgumentException) {
                // Not bound any more.
            }
        }
        connection = null
        parser = null
    }

    private companion object {
        /** Starting an isolated process takes well under a second; a slow phone gets far longer. */
        const val BIND_SECONDS = 30L
    }
}
