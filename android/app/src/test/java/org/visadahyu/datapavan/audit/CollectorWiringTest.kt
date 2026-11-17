package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.ProviderException

/**
 * How DeviceCollector's reads are judged (deviceFacts, HardwareCheck.keystoreErrors): what it reads from the system
 * needs a phone, and the emulator's audit shard sees it there ("No hardware check on an emulator").
 */
class CollectorWiringTest {
    private fun facts(hardware: String = "qcom", sdk: Int = 33, check: IntegrityResult = IntegrityResult(failure = IntegrityFailure.FAILED)) =
        deviceFacts(
            usbDebugging = true, wirelessDebugging = false, userCertificateAuthorities = listOf("CN=x"), vpnActive = true,
            check = check, hardwareKeystore = true, hardware = hardware, sdk = sdk,
        )

    @Test
    fun `the emulator and the version are read as the system states them`() {
        assertTrue(facts(hardware = "ranchu").emulator)
        assertTrue(facts(hardware = "goldfish").emulator)
        assertFalse(facts(hardware = "qcom").emulator)
        assertFalse(facts(hardware = "ranchu2").emulator)
        assertEquals(30, facts(sdk = 30).sdk)
        assertEquals(35, facts(sdk = 35).sdk)
        val all = facts()
        assertEquals(listOf(true, false, true, true), listOf(all.usbDebugging, all.wirelessDebugging, all.vpnActive, all.hardwareKeystore))
        assertEquals(listOf("CN=x"), all.userCertificateAuthorities)
        assertEquals(IntegrityFailure.FAILED, all.integrityFailure)
        val sound = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_609, trust = AttestationTrust.GOOGLE_ROOT)
        assertEquals(sound, facts(check = IntegrityResult(sound)).integrity)
    }

    /** Stands for android.security.KeyStoreException, which the JVM's android.jar cannot make. */
    private class KeystoreFailure(val code: Int, val policy: Int, cause: Throwable? = null) : Exception(cause)

    private val read = { cause: Throwable -> (cause as? KeystoreFailure)?.let { KeystoreError(it.code, it.policy) } }

    @Test
    fun `the keystore's errors are found down the causes, as Android 13 nests them`() {
        // generateKeyPair throws a ProviderException whose cause is the KeyStoreException, which may wrap another.
        val nested = ProviderException("generate", KeystoreFailure(16, 3, KeystoreFailure(16, 1)))
        assertEquals(listOf(KeystoreError(16, 3), KeystoreError(16, 1)), HardwareCheck.keystoreErrors(nested, read).toList())
        assertEquals(IntegrityFailure.KEYS_REFUSED, HardwareCheck.failureOf(HardwareCheck.keystoreErrors(nested, read)))
        val waiting = ProviderException("generate", KeystoreFailure(16, 3))
        assertEquals(IntegrityFailure.KEYS_UNAVAILABLE, HardwareCheck.failureOf(HardwareCheck.keystoreErrors(waiting, read)))
        // Only so deep: the eighth cause is looked at, the ninth is not.
        var eighth: Throwable = KeystoreFailure(16, 3)
        repeat(HardwareCheck.MAX_CAUSES - 1) { eighth = RuntimeException(eighth) }
        assertEquals(listOf(KeystoreError(16, 3)), HardwareCheck.keystoreErrors(eighth, read).toList())
        val ninth = RuntimeException(eighth)
        assertEquals(emptyList<KeystoreError>(), HardwareCheck.keystoreErrors(ninth, read).toList())
        assertEquals(8, HardwareCheck.MAX_CAUSES)
    }
}
