package org.visadahyu.datapavan.network.dns

import android.net.Network
import java.net.Socket
import java.security.cert.X509Certificate
import org.visadahyu.datapavan.network.WatchVpnService

/**
 * The screen's check of the user's own resolver before Watch saves it (W8's fix round, review R-M1): one query, by
 * the running service's [Exchanger], from a socket protected from Watch's tunnel and bound to the network beneath, as
 * the engine's own exchanges go; while Watch is off, from an exchanger of its own, on the phone's default network.
 */
object DnsProbe {
    private val standalone by lazy {
        Exchanger(
            object : Exchanger.Host {
                override fun protect(socket: Socket) = true
                override val network: Network? = null
                override val generation = 0
                override val extraRoots = emptyList<X509Certificate>()
            },
        )
    }

    /** Asks [choice]; [done] gets the milliseconds the answer took, or null with how it failed ([Exchanger.outcomeOf]). */
    fun check(choice: DnsSettings.Choice.Custom, done: (Long?, Int) -> Unit) =
        (WatchVpnService.exchangerNow ?: standalone).probe(choice, done)
}
