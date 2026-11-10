package org.visadahyu.datapavan.watch.log

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Seals and opens the records of one day key (ADR 0037): AES-256-GCM under a key derived from the
 * day key, a fresh 96-bit nonce per record, and the day, the key's row and the app's token as
 * associated data. The token is an HMAC of the UID under a second derived key, so that it links one
 * app's rows under that key and nothing else.
 */
class Sealer(dayKey: ByteArray, private val day: Long, val keyId: Long) {
    private val sealKey = SecretKeySpec(derive(dayKey, "datapavan-watch log seal"), "AES")
    private val tokenKey = SecretKeySpec(derive(dayKey, "datapavan-watch log token"), "HmacSHA256")

    /** The token of the app with `uid` (null: Android did not name it). */
    fun token(uid: Int?): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(tokenKey)
        val bytes = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(uid ?: -1).array()
        return mac.doFinal(bytes).copyOf(TOKEN)
    }

    /** The record sealed: nonce, then ciphertext and tag. */
    fun seal(record: ByteArray, token: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, sealKey, GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(associated(token))
        return nonce + cipher.doFinal(record)
    }

    /** The record a sealed row holds, or null if it was not sealed under this key for this token. */
    fun open(sealed: ByteArray, token: ByteArray): ByteArray? {
        if (sealed.size < NONCE + TAG_BITS / 8) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, sealKey, GCMParameterSpec(TAG_BITS, sealed, 0, NONCE))
            cipher.updateAAD(associated(token))
            cipher.doFinal(sealed, NONCE, sealed.size - NONCE)
        } catch (e: java.security.GeneralSecurityException) {
            null
        }
    }

    private fun associated(token: ByteArray): ByteArray =
        ByteBuffer.allocate(16 + TOKEN).order(ByteOrder.LITTLE_ENDIAN).putLong(day).putLong(keyId).put(token).array()

    companion object {
        /** A day key's length: 256 bits. */
        const val KEY = 32
        private const val NONCE = 12
        private const val TAG_BITS = 128
        private const val TOKEN = 8
        private val random = SecureRandom()

        /** A fresh day key. */
        fun newDayKey(): ByteArray = ByteArray(KEY).also { random.nextBytes(it) }

        /** HMAC-SHA-256 of `label` under the day key: one key for each use. */
        private fun derive(dayKey: ByteArray, label: String): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(dayKey, "HmacSHA256"))
            return mac.doFinal(label.toByteArray(Charsets.US_ASCII))
        }
    }
}
