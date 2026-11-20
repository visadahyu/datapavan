package org.visadahyu.datapavan.watch.tunnel.qr

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Watch's side of the QR decoder (W7, part 2): binds [QrService]'s isolated process for one picture, hands it the
 * picture as a read-only descriptor, and lets it go, which ends that process. Called off the main thread; the
 * binding's callbacks come on a thread of their own, so a caller on any thread but theirs may wait.
 */
object QrClient {
    /** How long Watch waits for the process to start and answer: its own limit, and a margin to start it. */
    private const val WAIT_MS = QrService.TIME_LIMIT_MS + 5_000L

    private val callbacks = Executors.newSingleThreadExecutor { Thread(it, "watch-qr-binding").apply { isDaemon = true } }

    /** The code's text in [picture], which this closes, or why not; the caller zeroes the text after use. */
    fun decode(context: Context, picture: ParcelFileDescriptor): QrDecode.Result = picture.use {
        val bound = AtomicReference<IQrDecoder?>(null)
        val connected = CountDownLatch(1)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                bound.set(IQrDecoder.Stub.asInterface(service))
                connected.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) {
                bound.set(null)
            }

            override fun onBindingDied(name: ComponentName) {
                connected.countDown()
            }

            override fun onNullBinding(name: ComponentName) {
                connected.countDown()
            }
        }
        val intent = Intent(context, QrService::class.java)
        if (!context.bindService(intent, Context.BIND_AUTO_CREATE, callbacks, connection)) {
            context.unbindService(connection)
            return QrDecode.Result.Failed(QrDecode.Failure.STOPPED)
        }
        try {
            if (!connected.await(WAIT_MS, TimeUnit.MILLISECONDS)) return QrDecode.Result.Failed(QrDecode.Failure.STOPPED)
            val decoder = bound.get() ?: return QrDecode.Result.Failed(QrDecode.Failure.STOPPED)
            val failure = IntArray(1) { -1 }
            val text = try {
                decoder.decode(picture, failure)
            } catch (e: RemoteException) {
                // The process died on the picture: what a hostile one may do.
                return QrDecode.Result.Failed(QrDecode.Failure.STOPPED)
            }
            return QrDecode.fromAnswer(text, failure)
        } finally {
            context.unbindService(connection)
        }
    }
}
