package org.visadahyu.datapavan.network.proxy

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import androidx.core.content.edit
import org.visadahyu.datapavan.network.NetworkVpnService
import org.visadahyu.datapavan.network.dns.NetworkProxy

/**
 * The user's choice "Send apps through this proxy" (the proxy record's unit S2, the maintainer's decision 1 of
 * 2026-11-26), for a user who set a network's own proxy as a privacy proxy of their own: with it on, every direct app's
 * TCP on that network goes through the proxy, as Android sends the apps that follow it without Datapavan; off, the
 * proxy is only the way where a direct connection fails. Off unless the user turns it on.
 *
 * Kept by the proxy setting it was made for ([key]: the network's transport, the proxy's host and port), not by the
 * network's name: Android gives no app a Wi-Fi network's name without the location permission, and a network's proxy is
 * a setting saved on this phone for that network, so the choice follows the setting.
 */
class ThroughProxy private constructor(private val prefs: SharedPreferences, private val changed: () -> Unit) {
    /** Whether the user chose to send apps through the proxy of [key]. */
    fun on(key: String): Boolean = key in prefs.getStringSet(KEYS, emptySet()).orEmpty()

    /** Sets the choice for the proxy of [key], and has the running service hand it to the engine. */
    fun set(key: String, on: Boolean) {
        val keys = prefs.getStringSet(KEYS, emptySet()).orEmpty()
        prefs.edit { putStringSet(KEYS, if (on) keys + key else keys - key) }
        changed()
    }

    companion object {
        private const val PREFS = "network_proxy"
        private const val KEYS = "through"

        /** The key of a network's proxy at [host] and [port] on a network of [transport] (`Engine.nativeProxies`' codes). */
        fun key(transport: Int, host: String, port: Int): String = "$transport ${NetworkProxy.folded(NetworkProxy.bare(host))} $port"

        fun of(context: Context): ThroughProxy {
            val app = context.applicationContext
            return ThroughProxy(app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)) {
                if (NetworkVpnService.running.value) {
                    try {
                        app.startService(Intent(app, NetworkVpnService::class.java).setAction(NetworkVpnService.ACTION_APPLY_PROXIES))
                    } catch (e: IllegalStateException) {
                        // Android refused a start from the background: the next settle carries it.
                    } catch (e: SecurityException) {
                        // Likewise.
                    }
                }
            }
        }
    }
}
