package org.visadahyu.datapavan.ui

import android.content.Context
import java.io.PrintWriter

/** Release builds read no labels for a dump; the debug build's commands are in src/debug (ADR 0054). */
object LabelsLab {
    @Suppress("UNUSED_PARAMETER")
    fun dump(context: Context, args: List<String>, writer: PrintWriter) = Unit
}
