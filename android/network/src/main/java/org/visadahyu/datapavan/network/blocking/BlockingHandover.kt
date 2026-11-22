package org.visadahyu.datapavan.network.blocking

import android.content.Context
import android.util.Log
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import org.visadahyu.datapavan.network.Engine

/**
 * Hands tracker blocking to the engine for [org.visadahyu.datapavan.network.NetworkVpnService] (W8, part 3a; ADR 0053), on
 * a thread of its own, one handover at a time, since it reads the data pack, the apps installed, the audit's scan and
 * signing certificates: the table at the tunnel's start and whenever the pack's changed, and the setting, whole, at the
 * start and whenever anything it depends on changed. What it read of the phone is kept between handovers, so that a
 * tap ("Allow trackers in this app", the pause) hands the setting again within milliseconds, reading nothing but the
 * preferences ([apply] with `full` false); an app installed, removed or updated, the chain or the tool, the scan or the
 * pack, and the settings that change what is covered read everything again (`full` true).
 */
internal class BlockingHandover(private val context: Context) {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "network-blocking").apply { isDaemon = true }
    }

    /** The table's bytes last handed to the engine's library, and what was read with them. Worker only. */
    private var handed: ByteArray? = null
    private var facts: BlockingFacts? = null

    /**
     * Hands blocking over on the worker: everything read again where [full], or nothing read yet; with [fresh], the
     * table handed even where its bytes did not change, as at the tunnel's start. The future ends once the engine has it.
     */
    fun apply(full: Boolean, fresh: Boolean = false): Future<*> {
        // The service is gone: the next one hands everything at its start.
        if (worker.isShutdown) return CompletableFuture.completedFuture(null)
        return worker.submit(Runnable { handOver(full, fresh) })
    }

    /** Stops the worker, with the service. */
    fun shutdown() {
        worker.shutdownNow()
    }

    private fun handOver(full: Boolean, fresh: Boolean) {
        if (fresh) handed = null
        try {
            hand(full || facts == null)
        } catch (e: RuntimeException) {
            // The engine keeps the setting it had. Only the kind is logged: a message could name an app.
            Log.w(TAG, "Tracker blocking was not handed over: ${e.javaClass.simpleName}")
        }
    }

    /** Hands the table's [bytes] to the engine's library where they changed, and gives its counts of them. */
    private fun handTable(bytes: ByteArray): IntArray {
        val before = handed
        val known = facts?.counts
        if (before != null && known != null && before.contentEquals(bytes)) return known
        val counts = Engine.nativeBlockingTable(bytes)
        handed = bytes
        return counts
    }

    private fun hand(full: Boolean) {
        val settings = BlockingSettings.of(context)
        if (full) facts = BlockingFacts.read(context, settings.browsers, covering = settings.on, hand = ::handTable)
        val read = facts ?: return
        val now = System.currentTimeMillis()
        val apps = HashMap<Int, Long?>()
        for ((name, end) in settings.appsAllowed(now)) {
            val uid = read.uids[name] ?: continue
            val left = Allowances.left(end, now, BlockingSettings.APP_MS)
            apps[uid] = maxOf(left, apps[uid] ?: 0L)
        }
        val entries = settings.entriesAllowed().mapNotNull { (name, host) -> read.uids[name]?.let { it to host } }
            .filter { read.table.row(it.second) != null }
        val paused = settings.pausedUntil(now)?.let { Allowances.left(it, now, BlockingSettings.PAUSE_MS) } ?: 0L
        val text = Handover.text(
            on = settings.on && read.table.rows.isNotEmpty(),
            toolDns = settings.toolDns,
            pausedMs = paused,
            covered = read.covered,
            decided = read.decided,
            apps = apps,
            entries = entries,
        )
        Engine.nativeBlocking(text)
        BlockingState.publish(read)
    }

    private companion object {
        const val TAG = "Network"
    }
}
