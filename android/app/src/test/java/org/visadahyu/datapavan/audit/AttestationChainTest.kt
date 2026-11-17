package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.datapack.DataPack
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.LocalDate
import java.util.Date

/**
 * The chain check on real phones' chains: Google's test data in `core/engine/testdata/keyattestation` (SOURCE
 * there), checked against the bundled roots, each as the attestation of its own leaf's key, at a date when its
 * certificates were valid unless a test says otherwise.
 */
class AttestationChainTest {
    private fun chain(file: File): List<X509Certificate> = file.inputStream().use { input ->
        CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate }
    }

    private fun corpus(path: String) = chain(File(CORPUS, path))

    private val google = File(DATA, "google-roots.pem").inputStream().use { roots ->
        AttestationChain.load(roots, "".byteInputStream())
    }

    /** A date at which every certificate between the leaf and the root is valid. */
    private fun whenValid(chain: List<X509Certificate>) =
        Date(chain.subList(1, chain.lastIndex).maxOf { it.notBefore.time } + 60_000)

    private fun AttestationChain.trust(chain: List<X509Certificate>, now: Date = whenValid(chain)) =
        trust(chain, chain.first().publicKey, now)

    @Test
    fun `every genuine chain is trusted, and the software keystore's is told by its published root`() {
        for (path in GENUINE) {
            assertEquals(path, AttestationTrust.GOOGLE_ROOT, google.trust(corpus(path)))
        }
        // The Pixel XL's software keystore signs under AOSP's software attestation root, whose private key AOSP
        // publishes: not a maker's own root.
        assertEquals(AttestationTrust.SOFTWARE_ROOT, google.trust(corpus("marlin/sdk29/TEE_EC_NONE.pem")))
        val otherRoot = chain(File(javaClass.getResource("/attestation/synthetic/root-expired.pem")!!.toURI()))
        assertEquals(AttestationTrust.OTHER_ROOT, google.trust(otherRoot, otherRoot.first().publicKey, Date.from(Instant.parse("2026-06-01T00:00:00Z"))))
    }

    @Test
    fun `the revocation list is dated by its SOURCE`() {
        val loaded = File(DATA, "google-roots.pem").inputStream().use { roots ->
            File(DATA, "revoked-serials.txt").inputStream().use { revoked ->
                File(DATA, "SOURCE").inputStream().use { source -> AttestationChain.load(roots, revoked, source) }
            }
        }
        val retrieved = File(DATA, "SOURCE").readLines().first { it.startsWith("retrieved:") }
        assertEquals(retrieved.substringAfter(":").trim().take(10), loaded.revocationListDate.toString())
        assertEquals(null, google.revocationListDate)
    }

    /** A data pack holding [files], by path. */
    private fun pack(files: Map<String, String>): DataPack {
        var bytes = ByteArray(0)
        val ranges = files.mapValues { (_, text) ->
            val start = bytes.size
            bytes += text.toByteArray()
            start until bytes.size
        }
        return DataPack(bytes, 0, 1, "2026-11-17", emptyList(), emptyList(), ranges)
    }

    @Test
    fun `the revocation list comes with its own date, from the pack that holds it`() {
        val roots = File(DATA, "google-roots.pem").readText()
        val sony = corpus("sony-xperia10-iii/sdk33/TEE_EC.pem")
        val revokedSony = sony[0].serialNumber.toString(16) + "\n"
        val bundled = pack(
            mapOf(
                AttestationChain.ROOTS_PATH to roots,
                AttestationChain.REVOKED_PATH to "# none\n",
                AttestationChain.SOURCE_PATH to "retrieved: 2026-10-29T15:10:29Z\n",
            ),
        )
        // A newer pack with a date but no list: the date is not put on the APK's older list.
        val dateOnly = pack(mapOf(AttestationChain.SOURCE_PATH to "retrieved: 2027-03-01T00:00:00Z\n"))
        assertEquals(LocalDate.of(2026, 10, 29), AttestationChain.load(dateOnly, bundled).revocationListDate)
        // A newer pack with a list but no date: its list is used, and not called as old as the APK's.
        val listOnly = AttestationChain.load(pack(mapOf(AttestationChain.REVOKED_PATH to revokedSony)), bundled)
        assertEquals(AttestationTrust.REVOKED, listOnly.trust(sony))
        assertEquals(null, listOnly.revocationListDate)
        // A whole newer dataset, as packs carry it.
        val newer = pack(
            mapOf(
                AttestationChain.ROOTS_PATH to roots,
                AttestationChain.REVOKED_PATH to revokedSony,
                AttestationChain.SOURCE_PATH to "retrieved: 2027-03-01T00:00:00Z\n",
            ),
        )
        val loaded = AttestationChain.load(newer, bundled)
        assertEquals(AttestationTrust.REVOKED, loaded.trust(sony))
        assertEquals(LocalDate.of(2027, 3, 1), loaded.revocationListDate)
        assertEquals(LocalDate.of(2026, 10, 29), AttestationChain.load(bundled).revocationListDate)
    }

    @Test
    fun `the software keystore's chain is told by its root before its dates, after revocation`() {
        // The Pixel XL's software chain at the time of this test: its intermediate expired in January 2026, and
        // the chain is still the published root's, not merely out of date.
        val marlin = corpus("marlin/sdk29/TEE_EC_NONE.pem")
        val today = Date.from(Instant.parse("2026-11-17T00:00:00Z"))
        assertTrue(marlin[1].notAfter.before(today))
        assertEquals(AttestationTrust.SOFTWARE_ROOT, google.trust(marlin, today))
        // A revoked serial in it is reported as revoked, as from any chain.
        val roots = File(DATA, "google-roots.pem").inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificates(input).map { AttestationChain.keyFingerprint(it.publicKey) }.toSet()
        }
        val revoked = AttestationChain(roots, setOf(marlin[1].serialNumber.toString(16)))
        assertEquals(AttestationTrust.REVOKED, revoked.trust(marlin))
    }

    @Test
    fun `a chain whose leaf was edited is broken`() {
        // Google's sample with entries out of tag order: its leaf's signature does not verify.
        assertEquals(AttestationTrust.BROKEN_CHAIN, google.trust(corpus("invalid/tags_not_in_ascending_order.pem")))
    }

    @Test
    fun `a chain extended below the attested key is forged`() {
        // The second review's probe: [forged, leaf, intermediate, root], where `forged` carries a "locked and
        // verified" KeyDescription and is signed by the leaf's own key, as a hooked keystore can sign with any key
        // it holds. Its signatures and names chain, so the check before this branch called it trusted. Google's
        // verifier calls it CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION.
        val extended = chain(File(javaClass.getResource("/attestation/extended-chain.pem")!!.toURI()))
        val probeRoot = AttestationChain(setOf(AttestationChain.keyFingerprint(extended.last().publicKey)), emptySet())
        for (key in listOf(extended[0].publicKey, extended[1].publicKey)) {
            assertEquals(AttestationTrust.FORGED, probeRoot.trust(extended, key, whenValid(extended)))
        }
        // The same on a genuine chain: an extra certificate below the leaf, with an extension, or without one.
        val genuine = corpus("caiman/sdk36/TEE_EC_RKP.pem")
        assertEquals(AttestationTrust.FORGED, google.trust(listOf(genuine[0]) + genuine, genuine[0].publicKey, whenValid(genuine)))
        val other = corpus("akita/sdk34/TEE_EC_NONE.pem")[1]
        assertEquals(AttestationTrust.FORGED, google.trust(listOf(other) + genuine, other.publicKey, whenValid(genuine)))
    }

    @Test
    fun `an attestation of another key is forged`() {
        // A genuine chain replayed from another phone, or another request: the leaf is not the app's key.
        val chain = corpus("sony-xperia10-iii/sdk33/TEE_EC.pem")
        val otherKey = corpus("caiman/sdk36/TEE_EC_RKP.pem").first().publicKey
        assertEquals(AttestationTrust.FORGED, google.trust(chain, otherKey, whenValid(chain)))
    }

    @Test
    fun `an attestation that answers another challenge is forged`() {
        val challenge = "challenge".toByteArray()
        for (trust in AttestationTrust.entries) {
            assertEquals(trust, AttestationChain.verdict(trust, challenge.copyOf(), challenge))
            assertEquals(AttestationTrust.FORGED, AttestationChain.verdict(trust, "challengf".toByteArray(), challenge))
        }
        assertEquals(AttestationTrust.FORGED, AttestationChain.verdict(AttestationTrust.GOOGLE_ROOT, ByteArray(0), challenge))
    }

    @Test
    fun `a chain without an attestation, or of the wrong shape, is broken`() {
        val chain = corpus("blueline/sdk28/SB_RSA_NONE.pem")
        // No KeyDescription at all: the chain from the attestation key up.
        assertEquals(AttestationTrust.BROKEN_CHAIN, google.trust(chain.drop(1), chain[1].publicKey, whenValid(chain)))
        // Without its root, or with the root twice: no longer a factory chain of four.
        assertEquals(AttestationTrust.BROKEN_CHAIN, google.trust(chain.dropLast(1), chain[0].publicKey, whenValid(chain)))
        assertEquals(AttestationTrust.BROKEN_CHAIN, google.trust(chain + chain.last(), chain[0].publicKey, whenValid(chain)))
        // A remotely provisioned chain cut to four, and a factory one stretched to five, by an intermediate of
        // another chain: neither shape nor signatures fit.
        val remote = corpus("akita/sdk34/TEE_EC_NONE.pem")
        assertEquals(AttestationTrust.BROKEN_CHAIN, google.trust(remote.take(2) + remote.drop(3)))
        assertEquals(
            AttestationTrust.BROKEN_CHAIN,
            google.trust(chain.take(2) + remote[2] + chain.drop(2), chain[0].publicKey, whenValid(chain)),
        )
    }

    @Test
    fun `a certificate that the next one did not sign breaks the chain`() {
        val sony = corpus("sony-xperia10-iii/sdk33/TEE_EC.pem")
        val walleye = corpus("walleye/sdk27/TEE_EC_NONE.pem")
        // Both factory chains of four under the same root; swap their attestation certificates.
        val swapped = listOf(sony[0], walleye[1], sony[2], sony[3])
        assertEquals(AttestationTrust.BROKEN_CHAIN, google.trust(swapped, sony[0].publicKey, whenValid(sony)))
    }

    @Test
    fun `a revoked certificate anywhere in the chain wins over a trusted root`() {
        val chain = corpus("tokay/sdk37/TEE_MLDSA_RKP.pem")
        val roots = File(DATA, "google-roots.pem").inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificates(input).map { AttestationChain.keyFingerprint(it.publicKey) }.toSet()
        }
        for (certificate in chain) {
            val revoked = AttestationChain(roots, setOf(certificate.serialNumber.toString(16)))
            assertEquals(AttestationTrust.REVOKED, revoked.trust(chain))
        }
    }

    @Test
    fun `dates are checked between the leaf and the root, as Google's verifier checks them`() {
        val today = Date.from(Instant.parse("2026-11-17T00:00:00Z"))
        // Remote Key Provisioning's certificates live for weeks; these expired long ago.
        for (path in REMOTE) {
            assertEquals(path, AttestationTrust.OUT_OF_DATE, google.trust(corpus(path), today))
        }
        // An expired certificate of a factory-provisioned chain is exempt, as Google exempts it: the Sony's
        // intermediate expired in May 2026.
        val sony = corpus("sony-xperia10-iii/sdk33/TEE_EC.pem")
        assertTrue(sony[2].notAfter.before(today))
        assertEquals(AttestationTrust.GOOGLE_ROOT, google.trust(sony, today))
        // A certificate not yet valid is not, from any chain: a phone whose date is years behind.
        val past = Date.from(Instant.parse("2015-01-01T00:00:00Z"))
        assertEquals(AttestationTrust.OUT_OF_DATE, google.trust(sony, past))
    }

    /** A synthetic chain (`synthetic/generate.sh`), checked with its own root trusted, in mid-2026. */
    private fun synthetic(name: String): AttestationTrust {
        val chain = chain(File(javaClass.getResource("/attestation/synthetic/$name")!!.toURI()))
        val trusted = AttestationChain(setOf(AttestationChain.keyFingerprint(chain.last().publicKey)), emptySet())
        return trusted.trust(chain, chain.first().publicKey, Date.from(Instant.parse("2026-06-01T00:00:00Z")))
    }

    @Test
    fun `the leaf's and the root's dates are not checked, as in Google's verifier`() {
        // The leaf's dates are set on the phone; the root's do not matter, since its key is what is trusted.
        assertEquals(AttestationTrust.GOOGLE_ROOT, synthetic("leaf-not-yet-valid.pem"))
        assertEquals(AttestationTrust.GOOGLE_ROOT, synthetic("root-expired.pem"))
    }

    @Test
    fun `only a factory chain is exempt from expiry`() {
        // A chain whose provisioning is unknown, with its attestation certificate expired in 2025.
        assertEquals(AttestationTrust.OUT_OF_DATE, synthetic("intermediate-expired.pem"))
    }

    @Test
    fun `shapes and signatures no phone makes are broken`() {
        // Five certificates whose second from the root is "Droid CA2" but not of "Google LLC": not Remote Key
        // Provisioning, and five is too many for any other provisioning.
        assertEquals(AttestationTrust.BROKEN_CHAIN, synthetic("five-not-remote.pem"))
        // A root named as its own issuer, but signed by another key.
        assertEquals(AttestationTrust.BROKEN_CHAIN, synthetic("root-not-self-signed.pem"))
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
        val CORPUS = File("../../core/engine/testdata/keyattestation")

        val REMOTE = listOf("akita/sdk34/TEE_EC_NONE.pem", "caiman/sdk36/TEE_EC_RKP.pem", "tokay/sdk37/TEE_MLDSA_RKP.pem")

        /** Chains whose signatures verify up to one of Google's roots. */
        val GENUINE = REMOTE + listOf(
            "blueline/sdk28/SB_RSA_NONE.pem",
            "sony-xperia10-iii/sdk33/TEE_EC.pem",
            "walleye/sdk27/TEE_EC_NONE.pem",
            // deviceLocked written as 0x01: a genuine chain all the same.
            "invalid/malformed_rot_device_locked.pem",
        )
    }
}
