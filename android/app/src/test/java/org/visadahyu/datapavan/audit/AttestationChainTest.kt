package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** The test chain (leaf 3003, intermediate 2002, root 1001) and the second root are throwaway certificates. */
class AttestationChainTest {
    private fun certificates(name: String): List<X509Certificate> =
        requireNotNull(javaClass.getResourceAsStream("/attestation/$name")).use { input ->
            CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate }
        }

    private val chain = certificates("chain.pem")
    private val otherRoot = certificates("other-root.pem").single()
    private val rootKey = AttestationChain.keyFingerprint(chain.last().publicKey)

    @Test
    fun `a chain that ends at a trusted root key is trusted`() {
        assertEquals(AttestationTrust.GOOGLE_ROOT, AttestationChain(setOf(rootKey), emptySet()).trust(chain))
    }

    @Test
    fun `a valid chain to any other root is not trusted`() {
        assertEquals(AttestationTrust.OTHER_ROOT, AttestationChain(emptySet(), emptySet()).trust(chain))
    }

    @Test
    fun `a certificate that the next one did not sign breaks the chain`() {
        val forged = listOf(chain.first(), otherRoot)
        assertEquals(AttestationTrust.BROKEN_CHAIN, AttestationChain(setOf(rootKey), emptySet()).trust(forged))
    }

    @Test
    fun `a chain must end in a self-signed root`() {
        assertEquals(AttestationTrust.BROKEN_CHAIN, AttestationChain(setOf(rootKey), emptySet()).trust(chain.dropLast(1)))
        assertEquals(AttestationTrust.BROKEN_CHAIN, AttestationChain(setOf(rootKey), emptySet()).trust(emptyList()))
    }

    @Test
    fun `a revoked certificate anywhere in the chain wins over a trusted root`() {
        assertEquals(AttestationTrust.REVOKED, AttestationChain(setOf(rootKey), setOf("2002")).trust(chain))
    }

    @Test
    fun `the bundled roots hold exactly the two root keys Google publishes`() {
        val roots = File(DATA, "google-roots.pem").inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificates(input)
        }
        assertEquals(
            setOf(
                // RSA 4096, the Google Hardware Attestation Root since 2016 (reissued with the same key).
                "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
                // ECDSA P-384, "Key Attestation CA1", signing new chains from 2026-02-01.
                "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec",
            ),
            roots.map { AttestationChain.keyFingerprint(it.publicKey) }.toSet(),
        )
    }

    @Test
    fun `the bundled revocation list holds only lowercase hex serials`() {
        val serials = File(DATA, "revoked-serials.txt").readLines().filter { it.isNotBlank() && !it.startsWith("#") }
        assertTrue(serials.size > 1000)
        assertTrue(serials.all { Regex("[a-f1-9][a-f0-9]*").matches(it) })
        File(DATA, "google-roots.pem").inputStream().use { roots ->
            File(DATA, "revoked-serials.txt").inputStream().use { revoked -> AttestationChain.load(roots, revoked) }
        }
    }

    private companion object {
        // Unit tests run in the app module's directory.
        val DATA = File("../../data/attestation")
    }
}
