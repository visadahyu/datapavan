package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory

class AppSignersTest {
    private val dev = "a".repeat(64)
    private val play = "b".repeat(64)
    private val old = "c".repeat(64)
    private val other = "d".repeat(64)

    private val apps = """
        # comment
        org.example.closed	Closed	yes	note
        org.example.open	Open	no
        org.example.weak	Weak	yes
        org.example.debugbuilds	Debug builds	no
    """.trimIndent()

    private val signers = """
        # comment
        org.example.closed	$dev	1	developer	github,website	no	2026-10-30	https://example.org
        org.example.closed	$play	4	google	play	no	2026-10-30	https://example.org
        org.example.closed	$old	1	developer	website	no	2026-10-30	https://example.org
        org.example.open	${"e".repeat(64)}	2	developer	fdroid	no	2026-10-30	https://example.org
        org.example.weak	${"f".repeat(64)}	5	developer	github	no	2026-10-30	https://example.org
        org.example.debugbuilds	${"9".repeat(64)}	4	developer	github	yes	2026-10-30	https://example.org
        org.example.closed	not-a-digest	1	developer	github	no	2026-10-30	https://example.org
    """.trimIndent()

    private val list = AppSigners.parse(apps, signers)

    private fun signing(vararg current: String, history: List<String> = current.toList(), debug: Boolean = false) =
        AppSigning(current.toList(), history, debug)

    @Test
    fun `a recorded key is genuine and names whose key it is`() {
        assertEquals(SignatureVerdict.Genuine("Closed", "developer", pastKeyOnly = false), list.judge("org.example.closed", signing(dev), fresh = true))
        assertEquals(SignatureVerdict.Genuine("Closed", "google", pastKeyOnly = false), list.judge("org.example.closed", signing(play), fresh = true))
    }

    @Test
    fun `an older key in the lineage still identifies a genuine copy`() {
        val rotated = signing(other, history = listOf(old, other))
        assertEquals(SignatureVerdict.Genuine("Closed", "developer", pastKeyOnly = true), list.judge("org.example.closed", rotated, fresh = true))
    }

    @Test
    fun `another key is modified only for a closed, fresh and proven key set`() {
        assertEquals(SignatureVerdict.Modified("Closed", other, debugKey = false), list.judge("org.example.closed", signing(other), fresh = true))
        // Stale data: keys change, so the same copy is only unknown.
        assertEquals(SignatureVerdict.UnknownKey("Closed", other), list.judge("org.example.closed", signing(other), fresh = false))
        // Not closed, or resting on a single reading.
        assertEquals(SignatureVerdict.UnknownKey("Open", other), list.judge("org.example.open", signing(other), fresh = true))
        assertEquals(SignatureVerdict.UnknownKey("Weak", other), list.judge("org.example.weak", signing(other), fresh = true))
    }

    @Test
    fun `a debug key is modified only where official builds never use one`() {
        assertEquals(SignatureVerdict.Modified("Open", other, debugKey = true), list.judge("org.example.open", signing(other, debug = true), fresh = false))
        assertEquals(SignatureVerdict.UnknownKey("Debug builds", other), list.judge("org.example.debugbuilds", signing(other, debug = true), fresh = true))
        assertEquals(SignatureVerdict.UnknownKey("Weak", other), list.judge("org.example.weak", signing(other, debug = true), fresh = true))
    }

    @Test
    fun `several signers must all be recorded`() {
        assertEquals(SignatureVerdict.Genuine("Closed", "developer", pastKeyOnly = false), list.judge("org.example.closed", signing(dev, old), fresh = true))
        assertEquals(SignatureVerdict.Modified("Closed", "$dev $other", debugKey = false), list.judge("org.example.closed", signing(dev, other), fresh = true))
    }

    @Test
    fun `a developer key under another package name is a disguised build`() {
        assertEquals(SignatureVerdict.Disguised("Closed"), list.judge("com.random.name", signing(dev), fresh = true))
        // Keys held by Google or F-Droid identify one build of one app, not a developer.
        assertNull(list.judge("com.random.name", signing(play), fresh = true))
        assertNull(list.judge("com.random.name", signing(other), fresh = true))
        assertNull(list.judge("org.example.closed", null, fresh = true))
    }

    @Test
    fun `reads the bundled lists`() {
        // Unit tests run in the app module's directory.
        val bundled = AppSigners.parse(File("../../data/app-signers/apps.tsv").readText(), File("../../data/app-signers/signers.tsv").readText())
        assertTrue(bundled.size > 20)
        val proton = "dcc9439ec1a6c6a8d0203f3423ee42bcc8b970628e53cb73a0393f398dd5b853"
        assertEquals(SignatureVerdict.Genuine("Proton VPN", "developer", pastKeyOnly = false), bundled.judge("ch.protonvpn.android", signing(proton), fresh = true))
    }

    @Test
    fun `the bundled lists hold the published certificate as Datapavan's only key`() {
        val bundled = AppSigners.parse(File("../../data/app-signers/apps.tsv").readText(), File("../../data/app-signers/signers.tsv").readText())
        val certificate = File("../../keys/datapavan-release.pem").inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val own = MessageDigest.getInstance("SHA-256").digest(certificate.encoded).joinToString("") { "%02x".format(it) }
        val datapavan = "org.visadahyu.datapavan"
        assertEquals(SignatureVerdict.Genuine("Datapavan", "developer", pastKeyOnly = false), bundled.judge(datapavan, signing(own), fresh = true))
        assertEquals(SignatureVerdict.Modified("Datapavan", other, debugKey = false), bundled.judge(datapavan, signing(other), fresh = true))
        assertEquals(SignatureVerdict.Modified("Datapavan", other, debugKey = true), bundled.judge(datapavan, signing(other, debug = true), fresh = true))
        assertEquals(SignatureVerdict.Disguised("Datapavan"), bundled.judge("org.example.lookalike", signing(own), fresh = true))
    }
}
