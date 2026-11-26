package org.visadahyu.datapavan.network

/** Release builds check nothing of the JNI bridge's error path; the debug build's check is in src/debug. */
object JniErrors {
    fun check(): List<String> = emptyList()
}
