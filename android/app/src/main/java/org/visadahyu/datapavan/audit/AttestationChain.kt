package org.visadahyu.datapavan.audit

import java.io.InputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale

/**
 * Checks a key attestation certificate chain as Google's documentation describes: each certificate is
 * signed by the next, the root holds one of Google's attestation root keys, and no certificate is on
 * Google's revocation list. Validity dates are not checked, because Google compares root keys, not root
 * certificates, and older devices keep chains under root certificates that have since expired.
 *
 * The roots and the revocation list come from `data/attestation`, in the data pack (ADR 0015).
 */
class AttestationChain(
    /** SHA-256 of each trusted root's SubjectPublicKeyInfo, in lowercase hex. */
    private val rootKeys: Set<String>,
    /** Revoked certificate serial numbers in lowercase hex, as in Google's list. */
    private val revokedSerials: Set<String>,
) {
    fun trust(chain: List<X509Certificate>): AttestationTrust {
        if (chain.isEmpty()) return AttestationTrust.BROKEN_CHAIN
        val signed = chain.indices.all { i -> signedBy(chain[i], chain[minOf(i + 1, chain.lastIndex)].publicKey) }
        return when {
            !signed -> AttestationTrust.BROKEN_CHAIN
            chain.any { serial(it.serialNumber) in revokedSerials } -> AttestationTrust.REVOKED
            keyFingerprint(chain.last().publicKey) in rootKeys -> AttestationTrust.GOOGLE_ROOT
            else -> AttestationTrust.OTHER_ROOT
        }
    }

    private fun signedBy(certificate: X509Certificate, key: PublicKey): Boolean = try {
        certificate.verify(key)
        true
    } catch (_: GeneralSecurityException) {
        false
    }

    companion object {
        const val ROOTS_PATH = "attestation/google-roots.pem"
        const val REVOKED_PATH = "attestation/revoked-serials.txt"

        fun keyFingerprint(key: PublicKey): String =
            MessageDigest.getInstance("SHA-256").digest(key.encoded).joinToString("") { "%02x".format(Locale.ROOT, it) }

        private fun serial(number: BigInteger): String = number.toString(16)

        /** Reads the data pack's files: PEM certificates, and one serial per line with `#` comments. */
        fun load(roots: InputStream, revoked: InputStream): AttestationChain {
            val certificates = CertificateFactory.getInstance("X.509").generateCertificates(roots)
            val keys = certificates.map { keyFingerprint(it.publicKey) }.toSet()
            val serials = revoked.bufferedReader().useLines { lines ->
                lines.map(String::trim).filter { it.isNotEmpty() && !it.startsWith("#") }.toSet()
            }
            return AttestationChain(keys, serials)
        }
    }
}
