package org.visadahyu.datapavan.audit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/** The debug builds' lab record (src/debug): its lines carry the whole chain, each under logcat's limit. */
class AttestationLabTest {
    private val chain = File("../../core/engine/testdata/keyattestation/blueline/sdk28/SB_RSA_NONE.pem").inputStream().use { input ->
        CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate }
    }

    @Test
    fun `the lines carry the verdict and every certificate whole`() {
        val lines = AttestationLab.lines(AttestationSeen("GOOGLE_ROOT", AttestationTrust.GOOGLE_ROOT, 2, chain))
        assertEquals("check verdict=GOOGLE_ROOT chain=GOOGLE_ROOT level=2 certificates=${chain.size}", lines.first())
        assertEquals("end", lines.last())
        assertTrue(lines.all { it.toByteArray().size < 4000 })
        // Reassembled from its parts, each certificate is the one the keystore gave.
        val parts = lines.drop(1).dropLast(1).map { it.split(" ") }
        for ((index, certificate) in chain.withIndex()) {
            val text = parts.filter { it[1] == "${index + 1}/${chain.size}" }.sortedBy { it[3].substringBefore('/').toInt() }
                .joinToString("") { it[4] }
            assertArrayEquals(certificate.encoded, Base64.getDecoder().decode(text))
        }
    }

    @Test
    fun `a failed check without a chain says so`() {
        val lines = AttestationLab.lines(AttestationSeen("failed: FAILED (ProviderException)", null, null, emptyList()))
        assertEquals(listOf("check verdict=failed: FAILED (ProviderException) chain=- level=- certificates=0", "end"), lines)
    }
}
