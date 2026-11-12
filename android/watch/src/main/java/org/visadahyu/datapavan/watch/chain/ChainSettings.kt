package org.visadahyu.datapavan.watch.chain

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The user's chain (W6): whether it is on, the tool it goes through and where its proxy answered last,
 * which apps go through it, and whether their destinations are logged. The last proxy is kept so that,
 * when the tool is stopped as the tunnel starts, the chained apps still wait instead of going directly.
 *
 * The password Watch offers for the tool's proxy is made here, once, and kept encrypted under a key in
 * the Android Keystore; it is shown to the user to set in the tool, and never logged.
 */
class ChainSettings private constructor(private val prefs: SharedPreferences) {
    var on: Boolean
        get() = prefs.getBoolean(ON, false)
        set(value) = prefs.edit { putBoolean(ON, value) }

    /** Every app but the tool, or only [apps]. */
    var allApps: Boolean
        get() = prefs.getBoolean(ALL_APPS, true)
        set(value) = prefs.edit { putBoolean(ALL_APPS, value) }

    /** The package names of the apps the user chose. */
    var apps: Set<String>
        get() = prefs.getStringSet(APPS, emptySet()).orEmpty().toSet()
        set(value) = prefs.edit { putStringSet(APPS, value) }

    var logDestinations: Boolean
        get() = prefs.getBoolean(LOG_DESTINATIONS, false)
        set(value) = prefs.edit { putBoolean(LOG_DESTINATIONS, value) }

    /**
     * Whether the chosen apps' UDP goes through the tool too (ADR 0041, decision 5). Off unless the user turns it on:
     * no tool is known to tie its UDP relay to the app that opened it, so while the relay carries Watch's
     * datagrams, any app on the phone can send through it, password or not. Off, the chain is TCP only.
     */
    var udp: Boolean
        get() = prefs.getBoolean(UDP_CHOSEN, false)
        set(value) = prefs.edit { putBoolean(UDP_CHOSEN, value) }

    /** Whether the chain carries UDP: the tool can, and the user chose it. */
    fun carriesUdp(remembered: Remembered): Boolean = remembered.udp && udp

    /** The tool whose proxy answered last, and where. */
    val lastTool: Remembered?
        get() {
            val tool = prefs.getString(TOOL, null) ?: return null
            val host = prefs.getString(HOST, null) ?: return null
            return Remembered(tool, host, prefs.getInt(PORT, 0), prefs.getBoolean(UDP, true))
        }

    /** Where the tool's proxy is, from the tool that answered. */
    fun remember(found: FoundTool) {
        prefs.edit {
            putString(TOOL, found.tool.packageName)
            putString(HOST, found.host)
            putInt(PORT, found.port)
            putBoolean(UDP, found.tool.udp != false)
        }
    }

    /** A tool's proxy as Watch last found it. */
    data class Remembered(val packageName: String, val host: String, val port: Int, val udp: Boolean)

    /**
     * The password Watch offers for the tool's proxy, made on first use: 20 characters of letters and
     * digits, about 116 bits, with no character a keyboard or a tool's settings could mangle. Null when
     * the Keystore cannot keep it.
     */
    fun password(): String? = try {
        prefs.getString(PASSWORD, null)?.let(::decrypt) ?: generate().also { made -> prefs.edit { putString(PASSWORD, encrypt(made)) } }
    } catch (e: GeneralSecurityException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }

    private fun generate(): String {
        val random = SecureRandom()
        return String(CharArray(PASSWORD_LENGTH) { ALPHABET[random.nextInt(ALPHABET.length)] })
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return generator.generateKey()
    }

    private fun encrypt(password: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }
        val sealed = cipher.iv + cipher.doFinal(password.toByteArray())
        return Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    private fun decrypt(stored: String): String {
        val sealed = Base64.decode(stored, Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES))
        return String(cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES))
    }

    companion object {
        /** The user name Watch offers with its password; Hiddify's is fixed (data/tools). */
        const val USER = "watch"
        private const val HIDDIFY = "app.hiddify.com"

        private const val FILE = "chain"
        private const val ON = "on"
        private const val ALL_APPS = "all_apps"
        private const val APPS = "apps"
        private const val LOG_DESTINATIONS = "log_destinations"
        private const val TOOL = "tool"
        private const val HOST = "host"
        private const val PORT = "port"
        private const val UDP = "udp"
        private const val UDP_CHOSEN = "udp_chosen"
        private const val PASSWORD = "password"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "watch-chain"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val IV_BYTES = 12
        private const val PASSWORD_LENGTH = 20
        private const val ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

        /** The user name for [tool]: Hiddify allows only its own. */
        fun userFor(tool: String): String = if (tool == HIDDIFY) "hiddify" else USER

        fun of(context: Context): ChainSettings =
            ChainSettings(context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE))
    }
}
