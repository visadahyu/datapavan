package org.visadahyu.datapavan.watch.log

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/** Wraps day keys for storage and unwraps them for reading (ADR 0037). */
interface KeyWrap {
    /** The day key wrapped, ready to store. Works on a locked phone. */
    fun wrap(dayKey: ByteArray): ByteArray

    /** The day key, or null when it cannot be unwrapped now (a locked phone) or at all. */
    fun unwrap(wrapped: ByteArray): ByteArray?

    /** Destroys the key that unwraps, so that nothing wrapped with it can be read again. */
    fun destroy()

    /** Whether the key exists. */
    fun exists(): Boolean
}

/**
 * The Keystore's RSA key pair for the log: its private key never leaves the Keystore and works only
 * while the phone is unlocked; the public key wraps each day key with RSA-OAEP. RSA-2048 in StrongBox
 * where the phone has one (StrongBox's largest RSA key), otherwise RSA-3072 in the trusted environment.
 */
class KeystoreWrap(private val prefs: SharedPreferences) : KeyWrap {
    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** Whether the key pair works only on an unlocked phone; false where the phone refused that. */
    val unlockedOnly: Boolean get() = prefs.getBoolean(UNLOCKED_ONLY, true)

    override fun wrap(dayKey: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey(), OAEP)
        return cipher.doFinal(dayKey)
    }

    override fun unwrap(wrapped: ByteArray): ByteArray? = try {
        val key = keyStore.getKey(ALIAS, null) as? PrivateKey
        key?.let {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, it, OAEP)
            cipher.doFinal(wrapped)
        }
    } catch (e: GeneralSecurityException) {
        // A locked phone, or a key that is gone.
        null
    }

    override fun exists(): Boolean = try {
        keyStore.containsAlias(ALIAS)
    } catch (e: GeneralSecurityException) {
        false
    }

    override fun destroy() {
        try {
            keyStore.deleteEntry(ALIAS)
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "The log's key could not be deleted", e)
        }
    }

    private fun publicKey() = (keyStore.getCertificate(ALIAS) ?: generate().let { keyStore.getCertificate(ALIAS) }).publicKey

    private fun generate() {
        for ((strongBox, bits, unlocked) in listOf(Triple(true, 2048, true), Triple(false, 3072, true), Triple(false, 3072, false))) {
            try {
                val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setAlgorithmParameterSpec(RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4))
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                    .setUnlockedDeviceRequired(unlocked)
                    .setIsStrongBoxBacked(strongBox)
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PROVIDER).apply { initialize(spec) }.generateKeyPair()
                prefs.edit().putBoolean(UNLOCKED_ONLY, unlocked).apply()
                return
            } catch (e: StrongBoxUnavailableException) {
                continue
            } catch (e: GeneralSecurityException) {
                // Some phones refuse a combination: try the next one (ADR 0037, "Keystore behaviour").
                Log.w(TAG, "Key pair refused: strongBox=$strongBox bits=$bits unlocked=$unlocked", e)
            } catch (e: java.security.ProviderException) {
                Log.w(TAG, "Key pair refused: strongBox=$strongBox bits=$bits unlocked=$unlocked", e)
            }
        }
        throw GeneralSecurityException("No key pair for the log")
    }

    private companion object {
        const val TAG = "WatchLog"
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "watch-log"
        const val UNLOCKED_ONLY = "log_key_unlocked_only"
        const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

        /** SHA-256 for OAEP, SHA-1 for its MGF1: the combination every Keystore version accepts. */
        val OAEP = OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
    }
}
