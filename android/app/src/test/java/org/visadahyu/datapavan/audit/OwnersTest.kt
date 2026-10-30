package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class OwnersTest {
    private val entities = """
        # comment
        holding	Holding Inc.	Q1	-			https://example.org	2026-10-30
        search	Search LLC	Q2	holding	whole	2015-10-02		https://example.org	2026-10-30
        video	Video LLC	Q3	search	whole	2006-11-13		https://example.org	2026-10-30
        partner	Partner Ltd	Q4	holding	minority	2020-01-01		https://example.org	2026-10-30
        sold	Sold Ltd	Q5	holding	whole	2010-01-01	2022-01-01	https://example.org	2026-10-30
        other	Other Corp	Q6	-			https://example.org	2026-10-30
        broken
    """.trimIndent()

    private fun operator(key: String, prefix: String, entity: String, shutDown: String = "", grade: String = "1") =
        listOf(key, "$key SDK", prefix, entity, "", "", shutDown, grade, "https://example.org", "2026-10-30").joinToString("\t")

    private val operators = listOf(
        operator("analytics", "com.search.analytics.", "search"),
        operator("ads", "com.video.ads.", "video"),
        operator("old", "com.search.old.", "search", shutDown = "2023-07-01"),
        operator("partner", "com.partner.", "partner"),
        operator("sold", "com.sold.", "sold"),
        operator("ungraded", "com.other.", "other", grade = "5"),
        operator("unknown", "com.nobody.", "nobody"),
    ).joinToString("\n")

    private val cert = "a".repeat(64)
    private val old = "b".repeat(64)
    private val publishers = listOf(
        "com.video.app\t$cert\tvideo\t1\turl\t${"c".repeat(64)}\t2026-10-30",
        "com.search.app\t$old\tsearch\t1\turl\t${"c".repeat(64)}\t2026-10-30",
        "com.bad\tnot-a-hash\tsearch\t1\turl\t${"c".repeat(64)}\t2026-10-30",
    ).joinToString("\n")

    private val owners = Owners.parse(entities, operators, publishers)
    private val today = "2026-10-30"
    private fun found(vararg names: String) = owners.operators.filter { it.name.removeSuffix(" SDK") in names }

    @Test
    fun readsGradedOperatorsOfKnownCompanies() {
        assertEquals(listOf("analytics", "ads", "old", "partner", "sold"), owners.operators.map { it.name.removeSuffix(" SDK") })
        assertEquals(Owners.FIRST_ID, owners.operators.first().id)
        assertTrue(owners.signatureTsv().startsWith("${Owners.FIRST_ID}\tanalytics SDK\t\t\tcom.search.analytics.\t"))
    }

    @Test
    fun followsWholeAndMajorityControlOnly() {
        assertEquals("holding", owners.group("video", today))
        assertEquals("partner", owners.group("partner", today))
        // Sold in 2022: its own group now, Holding's before.
        assertEquals("sold", owners.group("sold", today))
        assertEquals("holding", owners.group("sold", "2021-06-01"))
        assertNull(owners.group("nobody", today))
    }

    @Test
    fun matchesAppsByPackageAndCertificate() {
        assertEquals("video", owners.publisher("com.video.app", AppSigning(listOf(cert), emptyList(), debug = false)))
        // A rotated key counts through its history.
        assertEquals("search", owners.publisher("com.search.app", AppSigning(listOf(cert), listOf(old, cert), debug = false)))
        assertNull(owners.publisher("com.video.app", AppSigning(listOf(old), emptyList(), debug = false)))
        assertNull(owners.publisher("com.other.app", AppSigning(listOf(cert), emptyList(), debug = false)))
        assertNull(owners.publisher("com.video.app", null))
    }

    @Test
    fun notesTheSameGroupAndShutDownServices() {
        val notes = owners.notes("video", found("analytics", "ads", "old", "partner", "sold"), today)
        assertEquals("Holding Inc.", notes.group)
        assertEquals(listOf("analytics SDK", "ads SDK"), notes.sameGroup)
        assertEquals(listOf("old SDK" to "2023-07-01"), notes.shutDown)
        // Unknown publisher: no group note, but a shut-down service is still a fact.
        val unknown = owners.notes(null, found("analytics", "old"), today)
        assertNull(unknown.group)
        assertEquals(emptyList<String>(), unknown.sameGroup)
        assertEquals(listOf("old SDK" to "2023-07-01"), unknown.shutDown)
        // A minority stake is never the same group.
        assertEquals(emptyList<String>(), owners.notes("search", found("partner"), today).sameGroup)
    }

    @Test
    fun readsTheShippedData() {
        val data = File("../../data/owners")
        val shipped = Owners.parse(
            File(data, "entities.tsv").readText(),
            File(data, "sdk-operators.tsv").readText(),
            File(data, "publishers.tsv").readText(),
        )
        assertEquals("alphabet", shipped.group("youtube", today))
        assertTrue(shipped.operators.any { it.name == "Firebase Crashlytics" })
        val gms = AppSigning(listOf("f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"), emptyList(), debug = false)
        assertEquals("google", shipped.publisher("com.google.android.gms", gms))
    }
}
