package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

class DataSizeTest {
    private fun parts(bytes: Long, step: Double = DataSize.AOSP_STEP) =
        DataSize.parts(bytes, step).let { Triple(String.format(Locale.ROOT, "%.2f", it.value), it.unit, it.decimals) }

    @Test
    fun stepsUpAboveNineHundred() {
        assertEquals(Triple("900.00", 0, 0), parts(900))
        assertEquals(Triple("0.88", 1, 2), parts(901))
        assertEquals(Triple("574.00", 1, 0), parts(587_776))
    }

    @Test
    fun matchesTheStepOfEachVendorsSettings() {
        // The emulator's AOSP Settings showed 37.39 MB and 4.26 GB for these totals.
        assertEquals(Triple("37.39", 2, 2), parts(39_206_000))
        assertEquals(Triple("4.26", 3, 2), parts(4_574_000_000))
        // Samsung's Settings steps by 1,000.
        assertEquals(Triple("39.21", 2, 2), parts(39_206_000, DataSize.SI_STEP))
        assertEquals(Triple("4.57", 3, 2), parts(4_574_000_000, DataSize.SI_STEP))
    }
}
