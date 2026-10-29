package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class TrackerScannerTest {
    @Test
    fun `reads the bundled tracker data`() {
        // Unit tests run in the app module's directory.
        val trackers = TrackerData.parse(File("../../data/exodus/trackers.tsv").readText())
        assertTrue(trackers.size > 400)
        val sentry = trackers.values.single { it.name == "Sentry" }
        assertEquals(listOf("Crash reporting"), sentry.categories)
        assertTrue(sentry.website.startsWith("https://"))
    }

    @Test
    fun `skips comments and malformed lines`() {
        val tsv = "# comment\n1\tOne\tAnalytics,Profiling\thttps://one.example\tcom.one.\tone\\.example\nnot a line\n2\tshort\n"
        assertEquals(mapOf(1 to TrackerInfo(1, "One", listOf("Analytics", "Profiling"), "https://one.example")), TrackerData.parse(tsv))
    }

    @Test
    fun `cached results are reused only with the same signature data`() {
        val file = File.createTempFile("tracker-scan", ".tsv").apply { deleteOnExit() }
        val result = AppTrackers(embedded = listOf(49, 447), referencedOnly = listOf(52))
        val unreadable = AppTrackers(emptyList(), emptyList(), unreadable = true)
        ScanCache.write(file, "v1", listOf(Triple("org.example.app", 1234L, result), Triple("org.example.broken", 5L, unreadable)))
        assertEquals(
            mapOf("org.example.app" to (1234L to result), "org.example.broken" to (5L to unreadable)),
            ScanCache.read(file, "v1"),
        )
        assertEquals(emptyMap<String, Pair<Long, AppTrackers>>(), ScanCache.read(file, "v2"))
        assertEquals(emptyMap<String, Pair<Long, AppTrackers>>(), ScanCache.read(File(file.path + ".missing"), "v1"))
    }
}
