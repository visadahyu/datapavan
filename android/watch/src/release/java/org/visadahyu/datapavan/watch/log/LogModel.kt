package org.visadahyu.datapavan.watch.log

import android.content.Context

/** Release builds carry no model test of the log; the debug build's is in src/debug. */
object LogModel {
    @Suppress("UNUSED_PARAMETER")
    fun start(context: Context, seed: Long, steps: Int): String = "log-model not in this build"

    fun result(): String = "log-model not in this build"
}
