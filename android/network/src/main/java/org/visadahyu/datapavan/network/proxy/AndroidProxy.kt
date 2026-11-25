package org.visadahyu.datapavan.network.proxy

import org.visadahyu.datapavan.network.dns.Exchanger
import org.visadahyu.datapavan.network.dns.NetworkProxy

/**
 * What the network part read of Android's own proxy settings (the proxy record's unit B, B7; measurements 7.1 and 7.2):
 * the proxy or PAC file set for the whole phone ([global]: a device owner's, a profile's or one set over adb, which
 * Android's own Wi-Fi screens never show), and the current network's own ([network], from its link properties). A pure
 * value the JVM tests hold; [of] reads Android's `ProxyInfo` into it. It keeps no PAC file's address: no line shows it.
 */
data class AndroidProxy(val global: Setting? = null, val network: Setting? = null) {
    /** One of Android's proxy settings: a proxy server at [Server.host] and [Server.port], or a PAC file. */
    sealed interface Setting {
        data class Server(val host: String, val port: Int) : Setting

        /** A PAC file, which Android's PAC proxy (`com.android.proxyhandler`) evaluates for each connection. */
        data object Pac : Setting
    }

    /** Whether any of Android's proxy settings is set. */
    val any: Boolean get() = global != null || network != null

    companion object {
        /**
         * The setting a `ProxyInfo` gives, as [NetworkProxy.of] reads it: a PAC file whatever its host and port (Android
         * reports one as `localhost` and its handler's port), a server with a host and a port, or none.
         */
        fun setting(read: NetworkProxy.Setting?): Setting? = when {
            read == null -> null
            read.pac -> Setting.Pac
            read.host.isBlank() || read.port !in 1..65535 -> null
            else -> Setting.Server(NetworkProxy.bare(read.host), read.port)
        }

        /**
         * What Android gives: [global], `ConnectivityManager.getDefaultProxy()` read while the network part is inside its
         * own VPN, which has no proxy of its own, so that only the whole phone's comes back (measurements 7.1, point 1);
         * [network], the current network beneath's `LinkProperties.getHttpProxy()`.
         */
        fun of(global: android.net.ProxyInfo?, network: android.net.ProxyInfo?): AndroidProxy =
            AndroidProxy(setting(NetworkProxy.of(global)), setting(NetworkProxy.of(network)))

        /**
         * The proxies handed to the engine (`Engine.nativeProxies`, one `host port` a line, the same once): every server
         * Android's settings name, never a PAC file, whose `localhost` and handler's port are not an address, and never a
         * server on the loopback, which never enters the tunnel (the proxy record's unit B, B5).
         */
        fun engineLines(read: List<NetworkProxy.Setting?>): List<String> = read
            .mapNotNull { setting(it) as? Setting.Server }
            .filterNot { loopback(it.host) }
            .map { "${it.host} ${it.port}" }
            .distinct()

        /** Whether [host] is the phone itself: `localhost`, or a loopback address written out. Nothing is looked up. */
        private fun loopback(host: String): Boolean =
            host.equals("localhost", ignoreCase = true) || Exchanger.numeric(host)?.isLoopbackAddress == true
    }
}
