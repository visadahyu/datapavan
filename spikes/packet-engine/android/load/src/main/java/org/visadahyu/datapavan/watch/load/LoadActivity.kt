package org.visadahyu.datapavan.watch.load

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import kotlin.concurrent.thread

/**
 * The spike's workload, started by the measuring script with `--es op OP --es url URL [--ei n N]
 * [--el bytes B] [--ei parallel P] [--es tag T]`. Each run logs one line tagged SPIKE_RESULT:
 * - download: GET url n times, the megabits per second of all of it;
 * - upload: POST bytes to url n times;
 * - latency: n GETs of url, each on a new connection, the percentiles of the time to the answer;
 * - connect: n TCP connections to the host and port of url, the percentiles of the time to connect;
 * - rtt: n GETs of url on one kept-alive connection, the percentiles of the time to each answer;
 * - parallel: P downloads at once, n times each;
 * - dns: n lookups of names that do not exist under the host of url.
 */
class LoadActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent) {
        val op = intent.getStringExtra("op") ?: return
        val url = intent.getStringExtra("url") ?: return
        val n = intent.getIntExtra("n", 1)
        val bytes = intent.getLongExtra("bytes", 10_000_000L)
        val parallel = intent.getIntExtra("parallel", 4)
        val tag = intent.getStringExtra("tag") ?: ""
        thread(name = "load") {
            val result = try {
                when (op) {
                    "download" -> rate { repeat(n) { download(url) } }
                    "upload" -> rate { repeat(n) { upload(url, bytes) } }
                    "parallel" -> rate { (1..parallel).map { thread { repeat(n) { download(url) } } }.forEach { it.join() }; totalOf(parallel) }
                    "latency" -> percentiles((1..n).map { timed { fetch(url, close = true) } })
                    "connect" -> percentiles((1..n).map { timed { connect(url) } })
                    "rtt" -> {
                        fetch(url, close = false)
                        percentiles((1..n).map { timed { fetch(url, close = false) } })
                    }
                    "dns" -> percentiles((1..n).map { i -> timed { lookup("spike-${System.nanoTime()}-$i.${URL(url).host}") } })
                    else -> "error=unknown-op"
                }
            } catch (e: Exception) {
                "error=${e.javaClass.simpleName}:${e.message}"
            }
            Log.i(TAG, "SPIKE_RESULT tag=$tag op=$op n=$n $result")
            runOnUiThread { finish() }
        }
    }

    private val counted = java.util.concurrent.atomic.AtomicLong()

    private fun totalOf(@Suppress("UNUSED_PARAMETER") streams: Int) = counted.get()

    private fun rate(work: () -> Any): String {
        counted.set(0)
        val start = System.nanoTime()
        work()
        val seconds = (System.nanoTime() - start) / 1e9
        val total = counted.get()
        return "bytes=$total seconds=${"%.3f".format(seconds)} mbps=${"%.1f".format(total * 8 / seconds / 1e6)}"
    }

    private fun open(url: String): HttpURLConnection = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = 10_000
        readTimeout = 30_000
        useCaches = false
    }

    private fun download(url: String) {
        val connection = open(url)
        try {
            connection.inputStream.use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    counted.addAndGet(read.toLong())
                }
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun upload(url: String, bytes: Long) {
        val connection = open(url)
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(bytes)
            connection.outputStream.use { output ->
                val buffer = ByteArray(64 * 1024)
                var left = bytes
                while (left > 0) {
                    val chunk = minOf(left, buffer.size.toLong()).toInt()
                    output.write(buffer, 0, chunk)
                    left -= chunk
                    counted.addAndGet(chunk.toLong())
                }
            }
            connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    private fun fetch(url: String, close: Boolean) {
        val connection = open(url)
        if (close) connection.setRequestProperty("Connection", "close")
        try {
            connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    private fun connect(url: String) {
        val target = URL(url)
        java.net.Socket().use { it.connect(java.net.InetSocketAddress(target.host, target.port), 10_000) }
    }

    private fun lookup(name: String) {
        try {
            InetAddress.getAllByName(name)
        } catch (_: java.net.UnknownHostException) {
            // The names do not exist; the time to the resolver's answer is what counts.
        }
    }

    private fun timed(work: () -> Unit): Double {
        val start = System.nanoTime()
        work()
        return (System.nanoTime() - start) / 1e6
    }

    private fun percentiles(ms: List<Double>): String {
        val sorted = ms.sorted()
        fun at(p: Double) = sorted[((sorted.size - 1) * p).toInt()]
        return "p50_ms=${"%.2f".format(at(0.5))} p90_ms=${"%.2f".format(at(0.9))} p99_ms=${"%.2f".format(at(0.99))} " +
            "mean_ms=${"%.2f".format(sorted.average())}"
    }

    private companion object {
        const val TAG = "WatchLoad"
    }
}
