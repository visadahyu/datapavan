package org.visadahyu.datapavan.watch.blocking

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.watch.blocking.Grades.Decided

/**
 * A row joined to εxodus's tracker by its SDK's package prefix, a code-dependent row decided by the app's own code, the
 * vendor's exceptions by package and certificate, and the audit's scan as Watch reads it (W8, part 3a; ADR 0053).
 */
class GradesTest {
    private val table = checkNotNull(BlockingTable.parse(File("../../data/blocking/hosts.tsv").readText()))
    private val trackers = TrackerCode.parse(File("../../data/exodus/trackers.tsv").readText())
    private val graph = checkNotNull(table.row("graph.facebook.com"))

    private fun id(name: String) = trackers.single { it.name == name }.id

    /** Each row's prefix names its SDK's εxodus tracker: the alternative a prefix of it, or it of the alternative. */
    @Test
    fun aRowsPrefixNamesItsSdksTracker() {
        fun names(host: String) = TrackerCode.named(checkNotNull(table.row(host)).classes, trackers).map { it.name }
        // com.google.android.gms.ads. begins AdMob's com.google.android.gms.ads.AdView.
        assertEquals(listOf("Google AdMob"), names("googleads.g.doubleclick.net"))
        assertEquals(listOf("Google Firebase Analytics"), names("app-measurement.com"))
        // Facebook's com.facebook.appevents begins the row's com.facebook.appevents.
        assertEquals(listOf("Facebook Analytics"), names("graph.facebook.com"))
        assertEquals(listOf("Facebook Login"), names("m.facebook.com"))
        // No εxodus tracker holds GoogleDataTransport's classes: the row is named by its host.
        assertEquals(emptyList<String>(), names("firebaselogging.googleapis.com"))
        // Every block-with and keep-with prefix of the code row names a tracker, or the condition would decide nothing.
        for (prefix in graph.blockWith + graph.keepWith) assertTrue(prefix, TrackerCode.named(prefix, trackers).isNotEmpty())
    }

    /** Escapes are read as the text they match, and an empty alternative or prefix names nothing. */
    @Test
    fun escapesAndEmptyAlternatives() {
        assertEquals("com.example.", TrackerCode.unescape("com\\.example\\."))
        val read = TrackerCode.parse("# c\n7\tX\t\thttps://x.example\tcom\\.x\\.||com.y.\tx\\.com\n8\tY\t\t\t\t\nbad\tline")
        assertEquals(listOf(listOf("com.x.", "com.y."), emptyList()), read.map { it.prefixes })
        assertEquals(listOf(7), TrackerCode.named("com.x.sdk.", read).map { it.id })
        assertEquals(emptyList<Int>(), TrackerCode.named("", read).map { it.id })
        assertEquals(emptyList<Int>(), TrackerCode.named("org.other.", read).map { it.id })
    }

    /**
     * `graph.facebook.com` is blocked in an app whose code holds Facebook's App Events or its ads and none of Login, Share
     * and Places; kept in one that holds Login too, and in one the audit never read. That is the app's function, not who
     * made it (decision 2).
     */
    @Test
    fun aCodeRowIsDecidedByTheAppsCode() {
        assertEquals(Decided.BLOCK, Grades.ofCode(graph, setOf(id("Facebook Analytics")), trackers))
        assertEquals(Decided.BLOCK, Grades.ofCode(graph, setOf(id("Facebook Ads"), id("Google AdMob")), trackers))
        assertEquals(Decided.KEEP, Grades.ofCode(graph, setOf(id("Facebook Analytics"), id("Facebook Login")), trackers))
        assertEquals(Decided.KEEP, Grades.ofCode(graph, setOf(id("Facebook Share")), trackers))
        assertEquals(Decided.KEEP, Grades.ofCode(graph, emptySet(), trackers))
        assertEquals(Decided.NOT_READ, Grades.ofCode(graph, null, trackers))
        // Only a code row is decided by code.
        assertEquals(Decided.KEEP, Grades.ofCode(checkNotNull(table.row("app-measurement.com")), setOf(id("Facebook Analytics")), trackers))
        // Without the εxodus table nothing joins, and the row is kept.
        assertEquals(Decided.KEEP, Grades.ofCode(graph, setOf(id("Facebook Analytics")), emptyList()))
        val decided = Grades.forApp(table, trackers, setOf(id("Facebook Analytics")), emptySet())
        assertEquals(mapOf("graph.facebook.com" to Decided.BLOCK), decided)
        assertTrue(Grades.blocks(graph, decided))
        assertFalse(Grades.blocks(graph, null))
        assertTrue(Grades.blocks(checkNotNull(table.row("app-measurement.com")), null))
        assertFalse(Grades.blocks(checkNotNull(table.row("m.facebook.com")), decided))
    }

    /** An exception keeps its host for the vendor's own app, by package AND certificate, and wins over the app's code. */
    @Test
    fun anExceptionNeedsThePackageAndTheCertificate() {
        val exceptions = Exceptions.parse(File("../../data/blocking/exceptions.tsv").readText())
        val katana = exceptions.first { it.packageName == "com.facebook.katana" }
        val signed = AppSigning(listOf(katana.certificate), emptyList(), debug = false)
        assertEquals(setOf("graph.facebook.com"), Grades.excepted(exceptions, listOf("com.facebook.katana" to signed)))
        // A rotated key keeps the exception through its history, as the owners' table keeps a publisher.
        val rotated = AppSigning(listOf("b".repeat(64)), listOf(katana.certificate), debug = false)
        assertEquals(setOf("graph.facebook.com"), Grades.excepted(exceptions, listOf("com.facebook.katana" to rotated)))
        // Another certificate under the same name, the same certificate under another name, or none: blocked as any app.
        val other = AppSigning(listOf("c".repeat(64)), emptyList(), debug = false)
        assertEquals(emptySet<String>(), Grades.excepted(exceptions, listOf("com.facebook.katana" to other)))
        assertEquals(emptySet<String>(), Grades.excepted(exceptions, listOf("com.example.repackaged" to signed)))
        assertEquals(emptySet<String>(), Grades.excepted(exceptions, listOf("com.facebook.katana" to null)))
        val decided = Grades.forApp(table, trackers, setOf(id("Facebook Analytics")), setOf("graph.facebook.com", "not.a.row.example"))
        assertEquals(mapOf("graph.facebook.com" to Decided.EXCEPTED), decided)
        assertFalse(Grades.blocks(graph, decided))
        // An exception for a row graded block keeps it too.
        val kept = Grades.forApp(table, trackers, null, setOf("app-measurement.com"))
        assertFalse(Grades.blocks(checkNotNull(table.row("app-measurement.com")), kept))
    }

    /** The audit's scan as its ScanCache writes it: an app's ids at the version it was scanned at, never after an update. */
    @Test
    fun readsTheAuditsScanAsItsCacheWritesIt() {
        // The format of app/.../audit/TrackerScanner.kt's ScanCache.write, line for line.
        val written = "data\tdeadbeef\ncom.example.app\t1700000000000\t0\t66,312\t49\ncom.example.unread\t5\t1\t\t\nbroken line\n" +
            "com.example.empty\t7\t0\t\t\n"
        val scans = ScanResults.parse(written)
        assertEquals(setOf(66, 312), ScanResults.embedded(scans, "com.example.app", 1_700_000_000_000))
        // Updated since its scan, unreadable, or never scanned: nothing known.
        assertNull(ScanResults.embedded(scans, "com.example.app", 1_700_000_000_001))
        assertNull(ScanResults.embedded(scans, "com.example.unread", 5))
        assertNull(ScanResults.embedded(scans, "com.example.other", 5))
        assertEquals(emptySet<Int>(), ScanResults.embedded(scans, "com.example.empty", 7))
        assertEquals(emptyMap<String, ScanResults.Scan>(), ScanResults.parse("com.example.app\t1\t0\t66\t\n"))
        assertEquals(emptyMap<String, ScanResults.Scan>(), ScanResults.parse(""))
    }
}
