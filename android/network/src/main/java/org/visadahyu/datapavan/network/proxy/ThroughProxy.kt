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
 * a setting saved on this phone for that network, so the choice follows the setting. Each choice on keeps the day its
 * setting was last seen at a settle, and one not seen for [FORGET_DAYS] days is forgotten (S2's review, m3): once a
 * network's setting changes or the network is forgotten, the switch is never drawn for it again, and its key, a proxy's
 * host and port, would otherwise stay until the app's data is cleared.
 */
class ThroughProxy private constructor(private val prefs: SharedPreferences, private val changed: () -> Unit) {
    /** Whether the user chose to send apps through the proxy of [key]. */
    fun on(key: String): Boolean = key in prefs.getStringSet(KEYS, emptySet()).orEmpty()

    /** Sets the choice for the proxy of [key], and has the running service hand it to the engine. */
    fun set(key: String, on: Boolean) {
        val keys = prefs.getStringSet(KEYS, emptySet()).orEmpty()
        prefs.edit {
            putStringSet(KEYS, if (on) keys + key else keys - key)
            if (on) putLong(SEEN + key, today()) else remove(SEEN + key)
        }
        changed()
    }

    /**
     * At each settle (S2's review, m3): the choice for [key], the setting the settle found, if on, is seen on [day]; the
     * choices whose settings were not seen for [FORGET_DAYS] days are forgotten ([kept]). Writes only what changed.
     */
    fun seen(key: String?, day: Long = today()) {
        val keys = prefs.getStringSet(KEYS, emptySet()).orEmpty().toSet()
        if (keys.isEmpty()) return
        val stored = keys.associateWith { prefs.getLong(SEEN + it, -1L) }
        // A choice with no day yet counts as seen today.
        val days = stored.mapValues { (each, seen) -> if (each == key || seen < 0) day else seen }
        val kept = kept(days, day)
        if (kept == keys && days == stored) return
        prefs.edit {
            putStringSet(KEYS, kept)
            for (gone in keys - kept) remove(SEEN + gone)
            for (each in kept) if (days[each] != stored[each]) putLong(SEEN + each, days.getValue(each))
        }
    }

    companion object {
        private const val PREFS = "network_proxy"
        private const val KEYS = "through"

        /** The prefix of the day a choice's setting was last seen, by its key. */
        private const val SEEN = "seen "

        /** How many days a choice is kept after its setting was last seen. */
        const val FORGET_DAYS = 90L

        /** Today, as days since 1970 in UTC. */
        fun today(now: Long = System.currentTimeMillis()): Long = Math.floorDiv(now, 86_400_000L)

        /** The keys of [days] (each choice's last day seen) seen within [FORGET_DAYS] days of [today], as a pure function. */
        fun kept(days: Map<String, Long>, today: Long): Set<String> = days.filterValues { today - it < FORGET_DAYS }.keys.toSet()

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
