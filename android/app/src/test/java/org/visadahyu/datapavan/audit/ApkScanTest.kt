package org.visadahyu.datapavan.audit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * An APK's scan crosses the binder from the parsers' isolated process as primitives only (W7, part 2, fix round,
 * security review m1): the tracker ids in one array, the libraries' names as strings; the audit reads back exactly
 * what was sent, and an answer whose count does not fit it reads as an APK that could not be read.
 */
class ApkScanTest {
    @Test
    fun a_scan_reads_back_as_it_was_sent() {
        val scan = ApkScan.Result(intArrayOf(49, 447), intArrayOf(52), listOf("lib/arm64-v8a/libflutter.so"))
        val back = ApkScan.decode(ApkScan.encode(scan), scan.libraries)!!
        assertArrayEquals(intArrayOf(49, 447), back.embedded)
        assertArrayEquals(intArrayOf(52), back.referenced)
        assertEquals(listOf("lib/arm64-v8a/libflutter.so"), back.libraries)
        val empty = ApkScan.decode(ApkScan.encode(ApkScan.Result(IntArray(0), IntArray(0), emptyList())), emptyList())!!
        assertEquals(0, empty.embedded.size + empty.referenced.size)
    }

    @Test
    fun an_answer_that_does_not_fit_reads_as_unreadable() {
        assertNull("no answer: the APK could not be read", ApkScan.decode(null, emptyList()))
        assertNull(ApkScan.decode(IntArray(0), emptyList()))
        assertNull("a count past the ids", ApkScan.decode(intArrayOf(3, 1, 2), emptyList()))
        assertNull("a negative count", ApkScan.decode(intArrayOf(-1, 1), emptyList()))
        assertArrayEquals(intArrayOf(1, 2), ApkScan.decode(intArrayOf(2, 1, 2), emptyList())!!.embedded)
    }
}
