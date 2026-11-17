package org.visadahyu.datapavan.audit

import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Locale
import java.util.UUID

/** The keystore operations the hardware check needs; AndroidKeyStore on the phone, a fake in tests. */
interface AttestationKeystore {
    /** Generates a signing key under [alias] whose attestation carries [challenge], and returns its public key. */
    fun generate(alias: String, challenge: ByteArray): PublicKey

    /** The certificate chain of the key under [alias], leaf first; empty when there is none. */
    fun chain(alias: String): List<X509Certificate>

    fun aliases(): List<String>

    fun delete(alias: String)
}

/**
 * The hardware check: creates a throwaway key with a fresh random challenge, checks its certificate chain
 * ([AttestationChain]), decodes the leaf's KeyDescription with [parse] (the parsers' isolated process on the
 * phone), compares its challenge with the one sent ([AttestationChain.verdict]), and deletes the key again.
 *
 * One check runs at a time in the process, each under an alias of its own. Before both, a configuration change
 * that recreated the screen during a check could start a second one under the same alias: it could read the
 * first check's chain, whose challenge and key are not its own, and call a sound phone's check tampered with,
 * or have its key deleted by the first and call the check failed.
 */
class HardwareCheck(
    private val keystore: AttestationKeystore,
    /** The chain check; loading it reads the data pack, which can fail. */
    private val chains: () -> AttestationChain,
    /** Decodes a KeyDescription extension; null when it is malformed. */
    private val parse: (ByteArray) -> AttestationFields?,
    /** Fills the challenge with random bytes. */
    private val random: (ByteArray) -> Unit,
    /** The phone's date. */
    private val now: () -> Date,
    /** What a failure of the keystore, the data pack or the parsers' process means. */
    private val failure: (Exception) -> IntegrityFailure,
) {
    /** The check's result: the attestation's decoded state, or why there is none. */
    fun run(): IntegrityResult = synchronized(LOCK) {
        sweep()
        val alias = "$ALIAS_PREFIX-${UUID.randomUUID()}"
        try {
            check(alias)
        } catch (error: Exception) {
            // Every failure of the keystore, the data pack or the parsers' process ends the check the same way:
            // without a result, and with what it most likely means.
            IntegrityResult(failure = failure(error))
        } finally {
            delete(alias)
        }
    }

    private fun check(alias: String): IntegrityResult {
        val challenge = ByteArray(CHALLENGE_BYTES).also(random)
        val key = keystore.generate(alias, challenge)
        val chain = keystore.chain(alias)
        val trust = chains().trust(chain, key, now())
        // Nothing a forged attestation says is used, so it is not even decoded.
        if (trust == AttestationTrust.FORGED) return IntegrityResult(Integrity.forged())
        val extension = chain.firstOrNull()?.getExtensionValue(AttestationChain.KEY_DESCRIPTION_OID)
            ?: return IntegrityResult(failure = IntegrityFailure.FAILED)
        val fields = parse(extension) ?: return IntegrityResult(failure = IntegrityFailure.FAILED)
        return IntegrityResult(
            Integrity(
                securityLevel = fields.securityLevel,
                deviceLocked = fields.deviceLocked,
                verifiedBoot = fields.verifiedBoot,
                osPatchLevel = fields.osPatchLevel,
                trust = AttestationChain.verdict(trust, fields.challenge, challenge),
                verifiedBootKey = fields.verifiedBootKey?.joinToString("") { "%02x".format(Locale.ROOT, it) },
                vendorPatchLevel = fields.vendorPatchLevel,
            ),
        )
    }

    /** Deletes the keys of checks that did not finish, as when the app was killed during one. */
    private fun sweep() {
        val leftovers = try {
            keystore.aliases().filter { it == ALIAS_PREFIX || it.startsWith("$ALIAS_PREFIX-") }
        } catch (_: Exception) {
            emptyList()
        }
        leftovers.forEach(::delete)
    }

    private fun delete(alias: String) {
        try {
            keystore.delete(alias)
        } catch (_: Exception) {
            // Nothing to clean up, or a keystore that fails: the next check sweeps it.
        }
    }

    companion object {
        /** The aliases of the check's keys start with this; the bare prefix is the alias of earlier versions. */
        const val ALIAS_PREFIX = "datapavan-integrity-check"
        const val CHALLENGE_BYTES = 16

        /** One check at a time in the process, whichever screen asked for it. */
        private val LOCK = Any()
    }
}
