package org.visadahyu.datapavan.watch.chain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.audit.AppSigners
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.audit.SignatureVerdict
import java.io.File
import java.time.LocalDate

class ToolKeysTest {
    /** The keys as the build copies them, from the repository (the test runs in android/watch). */
    private val signers = AppSigners.parse(
        File("../../data/app-signers/apps.tsv").readText(),
        File("../../data/app-signers/signers.tsv").readText(),
    )

    @Test
    fun keysAreFreshForSixMonths() {
        val source = "# SPDX-License-Identifier: CC0-1.0\nretrieved: 2026-11-11\napps: 51\n"
        assertTrue(ToolKeys.fresh(source, LocalDate.parse("2027-05-11")))
        assertFalse(ToolKeys.fresh(source, LocalDate.parse("2027-05-12")))
        assertFalse("no date", ToolKeys.fresh("apps: 51\n", LocalDate.parse("2026-11-11")))
        assertFalse("a date it cannot read", ToolKeys.fresh("retrieved: soon\n", LocalDate.parse("2026-11-11")))
    }

    @Test
    fun theBundledKeysJudgeTheToolsOfW6() {
        // v2rayNG's developer key, as data/app-signers records it.
        val v2ray = signers.judge("com.v2ray.ang", AppSigning(listOf(key("com.v2ray.ang")), emptyList(), false), fresh = true)
        assertTrue(v2ray is SignatureVerdict.Genuine)
        // Any other key on a tool whose official keys are not all known is no claim, only unknown.
        val other = AppSigning(listOf("0".repeat(64)), emptyList(), false)
        assertTrue(signers.judge("moe.nb4a", other, fresh = true) is SignatureVerdict.UnknownKey)
        // DNSTT.XYZ's releases carry a debug key, so a debug key on it is not taken for a rebuild.
        val dnstt = signers.judge("xyz.dnstt.app", AppSigning(listOf("1".repeat(64)), emptyList(), debug = true), fresh = true)
        assertTrue(dnstt is SignatureVerdict.UnknownKey)
        assertEquals(51, signers.size)
    }

    /** The first key data/app-signers records for [packageName]. */
    private fun key(packageName: String): String =
        File("../../data/app-signers/signers.tsv").readLines().first { it.startsWith("$packageName\t") }.split('\t')[1]
}
