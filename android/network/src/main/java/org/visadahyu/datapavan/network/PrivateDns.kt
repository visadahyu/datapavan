package org.visadahyu.datapavan.network

import android.net.LinkProperties

/**
 * Private DNS as Android applies it to the apps on the network part's network (W3, docs/DESIGN.md 13.2). Android
 * applies the setting to a VPN's network too: in strict mode it sends every app's lookups encrypted
 * to the chosen provider, through the network part's tunnel but past the network part's resolver, so the network part
 * reads no names from them. The network part does not undo that, since it never lowers what the phone had; it says so
 * instead.
 */
sealed interface PrivateDns {
    /** The network part reads the lookups: Private DNS is off, or on "automatic" without a server that encrypts. */
    data object Plain : PrivateDns

    /**
     * On "automatic", and the network's DNS server answers DNS over TLS: Android's lookups pass
     * through the network part still encrypted, on to that server.
     */
    data object Network : PrivateDns

    /** Set to the provider [host]: Android's lookups go there encrypted. */
    data class Strict(val host: String) : PrivateDns

    companion object {
        /** What the link properties of the network part's own network say. */
        fun of(properties: LinkProperties): PrivateDns {
            val host = properties.privateDnsServerName
            return when {
                host != null -> Strict(host)
                properties.isPrivateDnsActive -> Network
                else -> Plain
            }
        }
    }
}
