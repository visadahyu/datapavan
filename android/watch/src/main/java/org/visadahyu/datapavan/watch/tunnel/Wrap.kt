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

    /** What of a configuration a wrap holds, or the store's state (slot 0). */
    enum class Part(val label: String) { NAME("name"), TEXT("text"), STATE("state") }
}

/** What an unwrap gave. */
sealed interface Opened {
    /** The bytes; the caller zeroes them after use. */
    class Plain(val bytes: ByteArray) : Opened

    /** The key works only while the phone is unlocked, and it is locked: the configuration waits for the unlock. */
    data object Locked : Opened

    /**
     * The Keystore erred for another reason (busy, restarting) or the file could not be read: it cannot be opened
     * now, and is tried again; never taken as lost (W7, part 2, fix round, security review m2).
     */
    data object Unavailable : Opened

    /**
     * The key is gone (no key under its alias, or one Android invalidated for good), or the wrap is not one it made
     * for this slot (its tag does not match): it cannot be opened again.
     */
    data object Lost : Opened
}

/**
 * Where the Keystore keeps the key: a separate secure chip, the processor's trusted environment, secure hardware of
 * either kind (before Android 12, which does not say which), or neither.
 */
enum class KeyHome { STRONGBOX, TRUSTED_ENVIRONMENT, SECURE_HARDWARE, SOFTWARE, UNKNOWN }

/**
 * The Android Keystore's AES-256 key for the configurations: generated inside the Keystore and never exportable,
 * in StrongBox where the phone has one and takes it, otherwise in the trusted environment (the processor's TEE),
 * or wherever this phone's Keystore keeps keys. AES-GCM with a 128-bit tag; the Keystore draws each wrap's
 * 96-bit IV itself (randomised encryption, its default), which is stored before the sealed bytes; the slot's
 * number and the part are the associated data.
 *
 * Two such keys (the maintainer's decision of 2026-11-20, ADR 0035): [ALIAS], key A, which opens at any time, and
 * [UNLOCKED_ALIAS], key B, made with [unlockedOnly] (`setUnlockedDeviceRequired`), which from Android 12 the
 * Keystore makes unusable while the phone is locked, even to code running as Watch. [TunnelStore] wraps the
 * configurations under key B while ADR 0047's profile is on, and what decides the routes under key A always.
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
            // No key under the alias: it is gone for good.
            key() ?: return Opened.Lost
        } catch (e: GeneralSecurityException) {
            return failed(e)
        } catch (e: ProviderException) {
            return failed(e)
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, wrapped, 0, IV_BYTES))
            cipher.updateAAD(associated(slot, part))
            Opened.Plain(cipher.doFinal(wrapped, IV_BYTES, wrapped.size - IV_BYTES))
        } catch (e: GeneralSecurityException) {
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
        return opened(e, unlockedOnly, ::lockedNow).also { if (it != Opened.Locked) Log.w(TAG, "A configuration did not open: $it", e) }
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
            // Android 10 and 11 say only whether the key is in secure hardware, not whether that is StrongBox.
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeyHome.SECURE_HARDWARE else KeyHome.SOFTWARE
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

        /** Key B: needs an unlocked phone. */
        const val UNLOCKED_ALIAS = "watch-tunnels-unlocked"
        private const val TAG = "WatchTunnels"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEY_BITS = 256
        const val IV_BYTES = 12
        const val TAG_BITS = 128

        /** Whether the phone is locked now, for an error the Keystore gave without saying why; set by Watch's process. */
        @Volatile
        var locked: () -> Boolean = { false }

        /**
         * What an error of the Keystore's means for a wrap (fix round, security review m2): the phone locked for a key
         * that needs it unlocked; lost for good only where the Keystore says the key was invalidated or the wrap's tag
         * does not match; anything else, a busy or restarting Keystore among them, cannot be opened now and is tried
         * again. A key that needs an unlocked phone fails on some versions with a plain Keystore error rather than
         * [UserNotAuthenticatedException]: told apart by the lock's own state.
         */
        fun opened(e: Exception, unlockedOnly: Boolean, lockedNow: () -> Boolean): Opened = when (e) {
            is UserNotAuthenticatedException -> Opened.Locked
            is KeyPermanentlyInvalidatedException, is AEADBadTagException -> Opened.Lost
            else -> if (unlockedOnly && lockedNow()) Opened.Locked else Opened.Unavailable
        }
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
