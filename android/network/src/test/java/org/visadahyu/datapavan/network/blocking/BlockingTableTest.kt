package org.visadahyu.datapavan.network.blocking

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Tracker blocking's graded table as Kotlin reads it, by the engine's rules (W8, part 3a; ADR 0053). */
class BlockingTableTest {
    private val tsv = File("../../data/blocking/hosts.tsv").readText()
    private val table = checkNotNull(BlockingTable.parse(tsv)) { "data/blocking/hosts.tsv is refused" }

    private fun row(host: String, grade: String = "block", condition: String = "-") =
        "$host\tcom.example:sdk\tcom.example.\t$grade\t$condition\tSends events\tcode\thttps://example.org\t2026-11-21"

    /** The table the data pack holds reads whole, with the counts its SOURCE states, which the engine gives too. */
    @Test
    fun readsTheTableThePackHolds() {
        val source = File("../../data/blocking/SOURCE").readText()
        val stated = Regex("""hosts\.tsv, (\d+) rows \((\d+) block, (\d+) keep, (\d+) code\)""").find(source)?.groupValues?.drop(1)?.map(String::toInt)
        val counts = listOf(table.rows.size) + BlockingTable.Grade.entries.map { grade -> table.rows.count { it.grade == grade } }
        assertEquals(stated, counts)
        val graph = checkNotNull(table.row("graph.facebook.com"))
        assertEquals(BlockingTable.Grade.CODE to "com.facebook.android:facebook-core", graph.grade to graph.sdk)
        assertEquals(listOf("com.facebook.appevents.", "com.facebook.ads."), graph.blockWith)
        assertEquals(listOf("com.facebook.login.", "com.facebook.share.", "com.facebook.places."), graph.keepWith)
        assertEquals(BlockingTable.Grade.BLOCK, table.row("app-measurement.com")?.grade)
        assertEquals(BlockingTable.Grade.KEEP, table.row("firebaseinstallations.googleapis.com")?.grade)
        assertTrue(table.ofSdk("com.adjust.sdk:adjust-android").size >= 10)
    }

    /** Hosts match on label boundaries, never as substrings; the narrowest row names a name; case and a last dot aside. */
    @Test
    fun matchesOnLabelBoundariesAndTheNarrowestRowNames() {
        assertEquals("app-measurement.com", table.find("app-measurement.com")?.host)
        assertEquals("app-measurement.com", table.find("x.y.App-Measurement.COM.")?.host)
        assertNull(table.find("notapp-measurement.com"))
        assertNull(table.find("measurement.com"))
        // onesignal.com and api.onesignal.com are both rows: the narrower names what is under it.
        assertEquals("api.onesignal.com", table.find("v2.api.onesignal.com")?.host)
        assertEquals("onesignal.com", table.find("cdn.onesignal.com")?.host)
        assertNull(table.find(""))
        assertNull(table.find("."))
        // An address is named by none, even where its last labels would be a row.
        val numbers = checkNotNull(BlockingTable.parse(row("3.4") + "\n" + row("example.net")))
        assertNull(numbers.find("1.2.3.4"))
        assertEquals("3.4", numbers.find("x.3.4")?.host)
        assertNull(numbers.find("2001:db8::1"))
    }

    /** As the engine does, anything that is not a table refuses the whole of it, so that nothing is blocked by half. */
    @Test
    fun refusesWhatTheEngineRefuses() {
        assertNotNull(BlockingTable.parse("# a comment\n\n" + row("ads.example.com") + "\n"))
        assertEquals(0, BlockingTable.parse("")?.rows?.size)
        val refused = mapOf(
            "eight columns" to row("ads.example.com").substringBeforeLast('\t'),
            "ten columns" to row("ads.example.com") + "\tmore",
            "one label" to row("localhost"),
            "an address" to row("192.0.2.1"),
            "upper case" to row("Ads.example.com"),
            "a label starting with -" to row("-ads.example.com"),
            "a label of 64" to row("a".repeat(64) + ".example.com"),
            "an unknown grade" to row("ads.example.com", "drop"),
            "a condition on block" to row("ads.example.com", "block", "block-with a.b. keep-with c.d."),
            "code with no condition" to row("ads.example.com", "code"),
            "a prefix without its dot" to row("ads.example.com", "code", "block-with com.a keep-with com.b."),
            "a condition out of order" to row("ads.example.com", "code", "keep-with com.b. block-with com.a."),
            "twice" to row("ads.example.com") + "\n" + row("ads.example.com"),
        )
        for ((why, text) in refused) assertNull(why, BlockingTable.parse(text))
        val code = BlockingTable.parse(row("graph.example.com", "code", "block-with com.a.|com.b_c. keep-with com.d."))?.rows?.single()
        assertEquals(listOf("com.a.", "com.b_c.") to listOf("com.d."), code?.blockWith to code?.keepWith)
        val many = (0..BlockingTable.MAX_ROWS).joinToString("\n") { row("h$it.example.com") }
        assertNull(BlockingTable.parse(many))
        assertEquals(BlockingTable.MAX_ROWS, BlockingTable.parse(many.substringBeforeLast('\n'))?.rows?.size)
    }

    /** A debug build's row for the lab's names follows the pack's table, on a line of its own; a release build adds none. */
    @Test
    fun aDebugBuildsLabRowFollowsThePacksTable() {
        val bytes = BlockingFacts.tableBytes("# no last line's end\n${row("ads.example.com")}".toByteArray())
        val read = checkNotNull(BlockingTable.parse(String(bytes)))
        if (LabRow.ROW.isEmpty()) {
            assertEquals(listOf("ads.example.com"), read.rows.map { it.host })
        } else {
            assertEquals(listOf("ads.example.com", "tracker.blocklab.home.arpa"), read.rows.map { it.host })
            assertEquals(BlockingTable.Grade.BLOCK, read.find("x.tracker.blocklab.home.arpa")?.grade)
            assertEquals("org.visadahyu.datapavan:blockfixture", read.row("tracker.blocklab.home.arpa")?.sdk)
        }
        assertEquals(table.rows.size + if (LabRow.ROW.isEmpty()) 0 else 1, BlockingTable.parse(String(BlockingFacts.tableBytes(tsv.toByteArray())))?.rows?.size)
    }

    /** The exceptions the pack holds read whole: a vendor's own app by package and certificate, never by company. */
    @Test
    fun readsTheExceptionsThePackHolds() {
        val read = Exceptions.parse(File("../../data/blocking/exceptions.tsv").readText())
        val stated = Regex("""exceptions\.tsv, (\d+) rows""").find(File("../../data/blocking/SOURCE").readText())?.groupValues?.get(1)?.toInt()
        assertEquals(stated, read.size)
        assertTrue(read.all { it.host == "graph.facebook.com" && table.row(it.host) != null })
        assertTrue(read.any { it.packageName == "com.facebook.katana" })
        val cert = "a".repeat(64)
        assertEquals(1, Exceptions.parse("p\t$cert\tads.example.com\treason\tsource\t2026-11-21").size)
        assertFalse(Exceptions.parse("p\tABC\tads.example.com\treason\tsource\t2026-11-21").isNotEmpty())
        assertFalse(Exceptions.parse("p\t$cert\tads.example.com\treason").isNotEmpty())
    }
}
