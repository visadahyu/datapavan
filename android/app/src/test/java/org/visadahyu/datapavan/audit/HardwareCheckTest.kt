package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The hardware check's wiring, with a keystore that answers with real phones' chains from Google's test data and
 * a parser that answers with what the test says, so that what DeviceCollector runs is tested without a phone.
 */
class HardwareCheckTest {
    private fun corpus(path: String): List<X509Certificate> =
        File("../../core/engine/testdata/keyattestation/$path").inputStream().use { input ->
            CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate }
        }

    private val google = File("../../data/attestation/google-roots.pem").inputStream().use { roots ->
        AttestationChain.load(roots, "".byteInputStream())
    }

    private val sony = corpus("sony-xperia10-iii/sdk33/TEE_EC.pem")
    private val walleye = corpus("walleye/sdk27/TEE_EC_NONE.pem")
    private val validDate = Date(maxOf(sony[1].notBefore.time, walleye[1].notBefore.time) + 60_000)

    /** A keystore that hands out [chains] in turn, one per key, and remembers each key's challenge. */
    private open inner class FakeKeystore(vararg chains: List<X509Certificate>) : AttestationKeystore {
        private val queue = ArrayDeque(chains.toList())
        val keys = mutableMapOf<String, Pair<List<X509Certificate>, ByteArray>>()
        val generated = mutableListOf<String>()
        val deleted = mutableListOf<String>()

        override fun generate(alias: String, challenge: ByteArray): PublicKey = synchronized(this) {
            val chain = queue.removeFirst().also { queue.addLast(it) }
            keys[alias] = chain to challenge.copyOf()
            generated += alias
            chain.first().publicKey
        }

        override fun chain(alias: String) = synchronized(this) { keys[alias]?.first.orEmpty() }

        override fun aliases() = synchronized(this) { keys.keys.toList() }

        override fun delete(alias: String) = synchronized(this) {
            keys.remove(alias)
            deleted += alias
            Unit
        }

        /** The challenge the key whose leaf has [extension] was generated with. */
        fun challengeOf(extension: ByteArray): ByteArray? = synchronized(this) {
            keys.values.firstOrNull { (chain, _) ->
                chain.first().getExtensionValue(AttestationChain.KEY_DESCRIPTION_OID).contentEquals(extension)
            }?.second
        }
    }

    /** What the parsers' process decodes from the corpus's leaves: a locked, verified TEE, with [challenge]. */
    private fun fields(challenge: ByteArray) = AttestationFields(
        attestationVersion = 3, securityLevel = 1, deviceLocked = true, verifiedBoot = 0, osVersion = 130_000,
        osPatchLevel = 202_307, vendorPatchLevel = 202_307, bootPatchLevel = 202_307, challenge = challenge,
        verifiedBootKey = byteArrayOf(1, 2), verifiedBootHash = null,
    )

    private fun check(
        keystore: FakeKeystore,
        parse: (ByteArray) -> AttestationFields? = { extension -> keystore.challengeOf(extension)?.let(::fields) },
        failure: (Exception) -> IntegrityFailure = { IntegrityFailure.FAILED },
    ) = HardwareCheck(
        keystore = keystore,
        chains = { google },
        parse = parse,
        random = { bytes -> bytes.fill(7) },
        now = { validDate },
        failure = failure,
    )

    @Test
    fun `a sound phone's check is trusted, and its key is deleted`() {
        val keystore = FakeKeystore(sony)
        val result = check(keystore).run()
        assertEquals(AttestationTrust.GOOGLE_ROOT, result.integrity?.trust)
        assertEquals(true, result.integrity?.deviceLocked)
        assertEquals("0102", result.integrity?.verifiedBootKey)
        assertNull(result.failure)
        assertEquals(keystore.generated, keystore.deleted)
        assertTrue(keystore.aliases().isEmpty())
    }

    @Test
    fun `an answer to another challenge is forged`() {
        val keystore = FakeKeystore(sony)
        val result = check(keystore, parse = { fields("another challenge".toByteArray()) }).run()
        assertEquals(AttestationTrust.FORGED, result.integrity?.trust)
    }

    @Test
    fun `a forged chain is not even decoded`() {
        // A certificate below the leaf, carrying an extension of its own.
        val keystore = FakeKeystore(listOf(sony[0]) + sony)
        var decoded = false
        val result = check(keystore, parse = { decoded = true; null }).run()
        assertEquals(Integrity.forged(), result.integrity)
        assertFalse(decoded)
    }

    @Test
    fun `no extension, an unreadable one, or a failing keystore is a failed check`() {
        assertEquals(IntegrityFailure.FAILED, check(FakeKeystore(sony.drop(1))).run().failure)
        assertEquals(IntegrityFailure.FAILED, check(FakeKeystore(sony), parse = { null }).run().failure)
        val failing = object : FakeKeystore(sony) {
            override fun generate(alias: String, challenge: ByteArray): PublicKey = throw IllegalStateException("keystore")
        }
        var seen: Exception? = null
        val result = check(failing, failure = { seen = it; IntegrityFailure.FAILED }).run()
        assertEquals(IntegrityFailure.FAILED, result.failure)
        assertEquals("keystore", seen?.message)
    }

    @Test
    fun `each check has an alias of its own, and leftovers are swept`() {
        val keystore = FakeKeystore(sony)
        keystore.keys[HardwareCheck.ALIAS_PREFIX] = sony to ByteArray(0)
        keystore.keys["${HardwareCheck.ALIAS_PREFIX}-left-by-a-killed-check"] = sony to ByteArray(0)
        keystore.keys["another app's key"] = sony to ByteArray(0)
        check(keystore).run()
        check(keystore).run()
        assertEquals(2, keystore.generated.toSet().size)
        assertTrue(keystore.generated.all { it.startsWith("${HardwareCheck.ALIAS_PREFIX}-") })
        assertEquals(listOf("another app's key"), keystore.aliases())
    }

    @Test
    fun `two checks at once do not read each other's keys`() {
        // A configuration change can start a second check while the first still waits on the keystore. Each
        // key here gets another phone's chain, so a check that read the other's would see a key and a challenge
        // that are not its own, and call a sound phone's check forged.
        val inside = AtomicInteger()
        var most = 0
        val second = CountDownLatch(1)
        val keystore = object : FakeKeystore(sony, walleye) {
            override fun generate(alias: String, challenge: ByteArray): PublicKey {
                val now = inside.incrementAndGet()
                synchronized(this) { most = maxOf(most, now) }
                // The first waits for the second; with one check at a time, the second never comes, and the
                // first goes on after the wait.
                if (generated.isEmpty()) second.await(500, TimeUnit.MILLISECONDS) else second.countDown()
                try {
                    return super.generate(alias, challenge)
                } finally {
                    inside.decrementAndGet()
                }
            }
        }
        val found = mutableListOf<IntegrityResult>()
        val threads = List(2) { Thread { check(keystore).run().also { synchronized(found) { found += it } } } }
        threads.forEach(Thread::start)
        threads.forEach { it.join(5_000) }
        assertEquals(1, most)
        assertEquals(listOf(AttestationTrust.GOOGLE_ROOT, AttestationTrust.GOOGLE_ROOT), found.map { it.integrity?.trust })
    }
}
