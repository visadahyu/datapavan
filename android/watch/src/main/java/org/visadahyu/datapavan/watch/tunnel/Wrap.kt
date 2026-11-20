package org.visadahyu.datapavan.watch.tunnel

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Wraps what Watch keeps of a WireGuard configuration (W7, part 2, ADR 0035): its text and its name, each sealed
 * apart, so that showing a name never opens a key. [TunnelStore] holds the files; this is the key. Behind an
 * interface so that the JVM tests hold the store with a wrap of their own.
 */
interface Wrap {
    /**
     * [plain] sealed for the slot [slot] and its [part], which are bound to it as associated data: a wrap moved to
     * another slot, or a name's moved to a text's, does not open. A fresh IV each time.
     */
    fun wrap(slot: Int, part: Part, plain: ByteArray): ByteArray

    /** What [wrapped] holds, or why it cannot be opened now or at all. */
    fun unwrap(slot: Int, part: Part, wrapped: ByteArray): Opened

    /** Destroys the key, so that nothing wrapped with it opens again. */
    fun destroy()

    /** Where the key lives, for the screen. */
    fun home(): KeyHome

    /** What of a configuration a wrap holds. */
    enum class Part(val label: String) { NAME("name"), TEXT("text") }
}

/** What an unwrap gave. */
sealed interface Opened {
    /** The bytes; the caller zeroes them after use. */
    class Plain(val bytes: ByteArray) : Opened

    /** The key works only while the phone is unlocked, and it is locked: the configuration waits for the unlock. */
    data object Locked : Opened

    /** The key is gone, or the wrap is not one it made for this slot: it cannot be opened again. */
    data object Lost : Opened
}

/** Where the Keystore keeps the key: a separate secure chip, the processor's trusted environment, or neither. */
enum class KeyHome { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN }

/**
 * The Android Keystore's AES-256 key for the configurations: generated inside the Keystore and never exportable,
 * in StrongBox where the phone has one and takes it, otherwise in the trusted environment (the processor's TEE),
 * or wherever this phone's Keystore keeps keys. AES-GCM with a 128-bit tag; the Keystore draws each wrap's
 * 96-bit IV itself (randomised encryption, its default), which is stored before the sealed bytes; the slot's
 * number and the part are the associated data.
 *
 * The key does not require an unlocked phone (`setUnlockedDeviceRequired`): Watch, started again while the phone
 * is locked, as after an update installed at night, sets its configurations at once, and its apps do not wait
 * for the unlock. ADR 0035, "How it is built (W7, part 2)", gives the measure and the reason, and the maintainer
 * decides it. [unlockedOnly] makes the other key, for the debug builds' measure only.
 */
class KeystoreWrap(private val alias: String = ALIAS, private val unlockedOnly: Boolean = false) : Wrap {
    private val keyStore: KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    override fun wrap(slot: Int, part: Wrap.Part, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key() ?: generate())
        cipher.updateAAD(associated(slot, part))
        val iv = cipher.iv
        check(iv.size == IV_BYTES) { "The Keystore gave an IV of ${iv.size} bytes" }
        val sealed = cipher.doFinal(plain)
        return iv + sealed
    }

    override fun unwrap(slot: Int, part: Wrap.Part, wrapped: ByteArray): Opened {
        if (wrapped.size < IV_BYTES + TAG_BITS / 8) return Opened.Lost
        val key = try {
            key()
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "The configurations' key could not be read", e)
            null
        } ?: return Opened.Lost
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, wrapped, 0, IV_BYTES))
            cipher.updateAAD(associated(slot, part))
            Opened.Plain(cipher.doFinal(wrapped, IV_BYTES, wrapped.size - IV_BYTES))
        } catch (e: UserNotAuthenticatedException) {
            lastError = e.javaClass.simpleName
            Opened.Locked
        } catch (e: KeyPermanentlyInvalidatedException) {
            Opened.Lost
        } catch (e: AEADBadTagException) {
            Opened.Lost
        } catch (e: GeneralSecurityException) {
            // A key that needs an unlocked phone, used while it is locked, fails here on some versions, as a
            // Keystore error rather than UserNotAuthenticatedException: told apart by the lock's own state.
            failed(e)
        } catch (e: ProviderException) {
            failed(e)
        }
    }

    /** The class of the last error an unwrap met, for debug builds' measure; never a value. */
    @Volatile
    var lastError: String? = null
        private set

    private fun failed(e: Exception): Opened {
        lastError = e.javaClass.simpleName
        return if (unlockedOnly && lockedNow()) Opened.Locked else Opened.Lost.also { Log.w(TAG, "A configuration did not open", e) }
    }

    override fun destroy() {
        try {
            keyStore.deleteEntry(alias)
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "The configurations' key could not be deleted", e)
        }
    }

    override fun home(): KeyHome = try {
        val key = key() ?: return KeyHome.UNKNOWN
        val info = SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyHome.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyHome.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeyHome.SOFTWARE
                else -> KeyHome.UNKNOWN
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeyHome.TRUSTED_ENVIRONMENT else KeyHome.SOFTWARE
        }
    } catch (e: GeneralSecurityException) {
        KeyHome.UNKNOWN
    }

    private fun key(): SecretKey? = keyStore.getKey(alias, null) as? SecretKey

    /** Makes the key: in StrongBox first, then wherever the Keystore keeps keys. */
    private fun generate(): SecretKey {
        for (strongBox in listOf(true, false)) {
            try {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(KEY_BITS)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .setUnlockedDeviceRequired(unlockedOnly)
                    .setIsStrongBoxBacked(strongBox)
                    .build()
                return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).apply { init(spec) }.generateKey()
            } catch (e: StrongBoxUnavailableException) {
                continue
            } catch (e: ProviderException) {
                // Some phones list StrongBox and refuse a key of this size there: the next way.
                Log.w(TAG, "The configurations' key was refused: strongBox=$strongBox", e)
            }
        }
        throw GeneralSecurityException("No key for the configurations")
    }

    private fun lockedNow(): Boolean = locked()

    companion object {
        const val ALIAS = "watch-tunnels"
        private const val TAG = "WatchTunnels"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        const val IV_BYTES = 12
        const val TAG_BITS = 128

        /** Whether the phone is locked now, for an error the Keystore gave without saying why; set by Watch's process. */
        @Volatile
        var locked: () -> Boolean = { false }
    }
}

/**
 * The associated data of a wrap: a label of its own, the record's version, the slot's number and the part, so that a
 * wrap opens only where it was made.
 */
fun associated(slot: Int, part: Wrap.Part): ByteArray {
    val label = "datapavan-watch tunnel ${part.label}".toByteArray(Charsets.US_ASCII)
    return ByteBuffer.allocate(label.size + 1 + 4).put(label).put(TunnelStore.VERSION).putInt(slot).array()
}
