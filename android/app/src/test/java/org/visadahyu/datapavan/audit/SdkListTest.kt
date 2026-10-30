package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SdkListTest {
    private val sdks = """
        # comment
        share	Share SDK	Share Inc	traffic-sharing		Web Indexing	https://example.org
        support	Support SDK	Support Ltd	remote-support	app-screen,device-control		https://example.org
        record	Record SDK	Record Co	screen-recording	live		https://example.org
        queued	Queued SDK	Queue Co	traffic-sharing			https://example.org
        broken	Broken	Nobody	unknown-category
    """.trimIndent()

    private fun row(sdk: String, type: String, value: String, specificity: String, grade: Int, date: String = "2026-10-30") =
        listOf(sdk, type, value, specificity, grade, "vendor", "https://example.org", "https://example.org/sdk.aar", "a".repeat(64), date).joinToString("\t")

    private val signatures = listOf(
        "# comment",
        row("share", "class-prefix", "com.share.sdk.", "high", 1, "2026-10-01"),
        row("share", "manifest-component", "com.share.sdk.Service", "high", 1, "2026-10-30"),
        row("share", "class", "com.example.Generic", "low", 1),
        row("share", "native-lib", "libshare.so", "high", 1),
        row("support", "class-prefix", "com.support.", "high", 2),
        row("record", "class-prefix", "com.record.", "high", 3),
        row("queued", "class-prefix", "com.queued.", "high", 4),
    ).joinToString("\n")

    private val list = SdkList.parse(sdks, signatures)

    @Test
    fun `reads categories, capabilities and the opt-out label`() {
        val share = list.sdks.first { it.name == "Share SDK" }
        assertEquals(SdkCategory.TRAFFIC_SHARING, share.category)
        assertEquals("Web Indexing", share.settingsLabel)
        assertEquals("2026-10-30", share.checked)
        val support = list.sdks.first { it.name == "Support SDK" }
        assertEquals(setOf(SdkCapability.APP_SCREEN, SdkCapability.DEVICE_CONTROL), support.capabilities)
        assertEquals(setOf(SdkCapability.LIVE), list.sdks.first { it.name == "Record SDK" }.capabilities)
        assertEquals(4, list.sdks.size)
        assertTrue(list.sdks.all { it.id >= SdkList.FIRST_ID })
        assertEquals(share, list.byId(share.id))
        assertNull(list.byId(1))
    }

    @Test
    fun `only shipped, specific class identifiers reach the scanner`() {
        val lines = list.signatureTsv().lines()
        // Grade 4 waits in the queue, and a low-specificity name or a native library is not a class match.
        assertEquals(3, lines.size)
        val share = lines.first { "Share SDK" in it }.split('\t')
        assertEquals(6, share.size)
        assertEquals("com.share.sdk.|com.share.sdk.Service", share[4])
        assertTrue(lines.none { "Queued" in it })
    }

    @Test
    fun `scanner lines parse like εxodus lines`() {
        val parsed = TrackerData.parse(list.signatureTsv())
        assertEquals(setOf("Share SDK", "Support SDK", "Record SDK"), parsed.values.map { it.name }.toSet())
    }

    @Test
    fun `reads the bundled list`() {
        // Unit tests run in the app module's directory.
        val bundled = SdkList.parse(File("../../data/sdks/sdks.tsv").readText(), File("../../data/sdks/signatures.tsv").readText())
        val pawns = bundled.sdks.first { it.name == "Pawns SDK" }
        assertEquals(SdkCategory.TRAFFIC_SHARING, pawns.category)
        assertTrue(bundled.signatureTsv().lines().any { it.contains("com.pawns.sdk.") })
        // Bright SDK waits until an artefact is read.
        assertTrue(bundled.signatureTsv().lines().none { it.contains("Bright SDK") })
    }
}
