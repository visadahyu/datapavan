package org.visadahyu.datapavan.audit

import java.io.InputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Locale
import javax.security.auth.x500.X500Principal

/**
 * Checks a key attestation certificate chain, leaf first, as Google's reference verifier does
 * (`android/keyattestation`, `KeyAttestationCertPathValidator.kt`), for the key the app has just generated:
 *
 * - The KeyDescription extension occurs once, in the leaf: a certificate below the attested key, which a
 *   hooked keystore can sign with any key of its own, carries a forged one ([AttestationTrust.FORGED]).
 * - The leaf certifies the key the app generated, not one from another request or another phone
 *   ([AttestationTrust.FORGED]); the caller compares the challenge, once the extension is decoded ([verdict]).
 * - The chain has the shape of its provisioning: four certificates from a factory-provisioned key, five from
 *   a remotely provisioned one, three from a software keystore. Each is issued by the next by name and
 *   signed by it ([AttestationTrust.BROKEN_CHAIN]).
 * - No certificate is on Google's revocation list ([AttestationTrust.REVOKED]), and the root holds one of
 *   Google's attestation root keys ([AttestationTrust.OTHER_ROOT]).
 * - Every certificate between the leaf and the root is valid at the phone's date, but for an expired one in
 *   a factory-provisioned chain, which Google exempts ([AttestationTrust.OUT_OF_DATE]). The leaf's dates are
 *   set on the phone and the root's are not used, as in Google's verifier.
 *
 * Like Google's verifier, it does not require basicConstraints or keyUsage of the certificates above the
 * leaf: the attestation certificates of a Pixel 2 and a Sony Xperia 10 III in Google's test data are not
 * marked as CAs, and their chains are genuine. Their places in the chain are fixed by its shape instead.
 *
 * The date is the phone's, which its system sets. A wrong date can make a sound chain look out of date; a
 * system that sets the date back can make an expired one look valid, but cannot make a chain to an unknown or
 * revoked key, or one with a forged extension, pass.
 *
 * The roots and the revocation list come from `data/attestation`, in the data pack (ADR 0015).
 */
class AttestationChain(
    /** SHA-256 of each trusted root's SubjectPublicKeyInfo, in lowercase hex. */
    private val rootKeys: Set<String>,
    /** Revoked certificate serial numbers in lowercase hex, as in Google's list. */
    private val revokedSerials: Set<String>,
) {
    /** The verdict on [chain], leaf first, as the attestation of [generatedKey], at [now] by the phone's clock. */
    fun trust(chain: List<X509Certificate>, generatedKey: PublicKey, now: Date): AttestationTrust {
        val holders = chain.indices.filter { chain[it].getExtensionValue(KEY_DESCRIPTION_OID) != null }
        if (holders.isEmpty()) return AttestationTrust.BROKEN_CHAIN
        if (holders != listOf(0)) return AttestationTrust.FORGED
        if (!chain[0].publicKey.encoded.contentEquals(generatedKey.encoded)) return AttestationTrust.FORGED

        val provisioning = if (chain.size >= 2) provisioning(chain[chain.size - 2].subjectX500Principal) else null
        val shaped = when (provisioning) {
            Provisioning.FACTORY -> chain.size == 4
            Provisioning.REMOTE -> chain.size == 5
            null -> chain.size == 3 || chain.size == 4
        }
        val chained = chain.indices.all { i ->
            val issuer = chain[minOf(i + 1, chain.lastIndex)]
            chain[i].issuerX500Principal == issuer.subjectX500Principal && signedBy(chain[i], issuer.publicKey)
        }
        return when {
            !shaped || !chained -> AttestationTrust.BROKEN_CHAIN
            chain.any { serial(it.serialNumber) in revokedSerials } -> AttestationTrust.REVOKED
            keyFingerprint(chain.last().publicKey) !in rootKeys -> AttestationTrust.OTHER_ROOT
            !valid(chain.subList(1, chain.lastIndex), now, expiryExempt = provisioning == Provisioning.FACTORY) ->
                AttestationTrust.OUT_OF_DATE
            else -> AttestationTrust.GOOGLE_ROOT
        }
    }

    private fun signedBy(certificate: X509Certificate, key: PublicKey): Boolean = try {
        certificate.verify(key)
        true
    } catch (_: GeneralSecurityException) {
        false
    }

    private fun valid(certificates: List<X509Certificate>, now: Date, expiryExempt: Boolean): Boolean =
        certificates.all { certificate ->
            try {
                certificate.checkValidity(now)
                true
            } catch (_: CertificateNotYetValidException) {
                false
            } catch (_: CertificateExpiredException) {
                expiryExempt
            }
        }

    /** How the phone's attestation key was provisioned, as Google's verifier tells it from the certificate the root signed. */
    private enum class Provisioning { FACTORY, REMOTE }

    companion object {
        const val ROOTS_PATH = "attestation/google-roots.pem"
        const val REVOKED_PATH = "attestation/revoked-serials.txt"
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"

        /**
         * The verdict once the leaf's KeyDescription is decoded: an attestation whose challenge is not the one the
         * app generated the key with answers another request, however sound its chain.
         */
        fun verdict(chainTrust: AttestationTrust, attestedChallenge: ByteArray, challenge: ByteArray): AttestationTrust =
            if (attestedChallenge.contentEquals(challenge)) chainTrust else AttestationTrust.FORGED

        fun keyFingerprint(key: PublicKey): String =
            MessageDigest.getInstance("SHA-256").digest(key.encoded).joinToString("") { "%02x".format(Locale.ROOT, it) }

        private fun serial(number: BigInteger): String = number.toString(16)

        /**
         * A factory-provisioned intermediate names its serial number (OID 2.5.4.5); Remote Key Provisioning's is
         * "Droid CA2" of "Google LLC"; anything else is unknown, as in Google's `KeyAttestationCertPath.kt`.
         */
        private fun provisioning(subject: X500Principal): Provisioning? {
            val attributes = attributes(subject)
            return when {
                attributes.any { it.first == OID_SERIAL_NUMBER } -> Provisioning.FACTORY
                (OID_COMMON_NAME to "Droid CA2") in attributes && (OID_ORGANIZATION to "Google LLC") in attributes ->
                    Provisioning.REMOTE
                else -> null
            }
        }

        private const val OID_COMMON_NAME = "2.5.4.3"
        private const val OID_SERIAL_NUMBER = "2.5.4.5"
        private const val OID_ORGANIZATION = "2.5.4.10"

        /**
         * The attribute types (dotted OIDs) and string values of a name, read from its DER encoding, which the
         * platform has already parsed, rather than from a printed form that differs between platforms.
         */
        private fun attributes(name: X500Principal): List<Pair<String, String>> {
            val der = name.encoded
            val out = mutableListOf<Pair<String, String>>()
            // Name ::= SEQUENCE OF RelativeDistinguishedName ::= SET OF SEQUENCE { type OID, value ANY }.
            val (_, nameStart, nameEnd) = element(der, 0) ?: return out
            var set = nameStart
            while (set < nameEnd) {
                val (_, setStart, setEnd) = element(der, set) ?: return out
                var pair = setStart
                while (pair < setEnd) {
                    val (_, pairStart, pairEnd) = element(der, pair) ?: return out
                    val (oidTag, oidStart, oidEnd) = element(der, pairStart) ?: return out
                    val (_, valueStart, valueEnd) = element(der, oidEnd) ?: return out
                    if (oidTag == 0x06 && valueEnd <= pairEnd) {
                        out += oid(der.copyOfRange(oidStart, oidEnd)) to String(der.copyOfRange(valueStart, valueEnd), Charsets.UTF_8)
                    }
                    pair = pairEnd
                }
                set = setEnd
            }
            return out
        }

        /** The tag, content start and end of the DER element at [at], or null when it does not fit. */
        private fun element(der: ByteArray, at: Int): Triple<Int, Int, Int>? {
            if (at + 2 > der.size) return null
            val tag = der[at].toInt() and 0xff
            var length = der[at + 1].toInt() and 0xff
            var start = at + 2
            if (length and 0x80 != 0) {
                val count = length and 0x7f
                if (count == 0 || count > 3 || start + count > der.size) return null
                length = (0 until count).fold(0) { acc, i -> (acc shl 8) or (der[start + i].toInt() and 0xff) }
                start += count
            }
            return if (start + length <= der.size) Triple(tag, start, start + length) else null
        }

        private fun oid(bytes: ByteArray): String {
            if (bytes.isEmpty()) return ""
            val first = bytes[0].toInt() and 0xff
            val parts = mutableListOf(minOf(first / 40, 2).toLong(), (first - minOf(first / 40, 2) * 40).toLong())
            var value = 0L
            for (i in 1 until bytes.size) {
                val b = bytes[i].toInt() and 0xff
                value = (value shl 7) or (b and 0x7f).toLong()
                if (b and 0x80 == 0) {
                    parts += value
                    value = 0
                }
            }
            return parts.joinToString(".")
        }

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
