package org.visadahyu.datapavan.network.proxy

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.visadahyu.datapavan.network.dns.NetworkProxy

/**
 * What the service knows of the proxies around the apps, for "Now" and each app's history (the proxy record's unit B,
 * B5 to B7), in the network process, which both run in: Android's own proxy settings, the UID of Android's PAC proxy,
 * and the circumvention tools installed, by UID, with those whose own connections follow R10 (unit D). The service publishes; the screens read. Nothing of it is kept on
 * disk, and it is empty while the tunnel does not run.
 */
object ProxyContext {
    data class State(
        /** Android's own proxy settings, as the service last read them. */
        val android: AndroidProxy = AndroidProxy(),
        /** The UID of Android's PAC proxy, where it is Android's own app with a UID of its own ([PacHandler.uid]). */
        val pacHandler: Int? = null,
        /**
         * The circumvention tools installed, by UID, each with the table's name for it (`chain.Tools.uids`): judged by
         * their signing key, never by package name, and the tool the user chose for the chain. Their proxy rows say they
         * are a tool's own connection (unit B, B6).
         */
        val tools: Map<Int, String> = emptyMap(),
        /**
         * Those of [tools] that can carry traffic inside Datapavan's VPN (`chain.Tools.carriers`; unit D, audit-D M3):
         * the tools whose own connections "Now" shows for their window and the log keeps only by the switch or the
         * user's choice (R10). The engine is handed these as the tools, and the choice of one app's proxy (unit C) never
         * covers them.
         */
        val carriers: Map<Int, String> = emptyMap(),
        /**
         * Whether the last hand-over could hand the apps and tools the user chose: the tools were read in this run and,
         * under strict Private DNS, the setting's addresses are known (unit D; review D-rest n8). The screens show a
         * tool chosen as the engine has it: none while this is false.
         */
        val handReady: Boolean = false,
        /** The network beneath's own proxy as the engine has it (the proxy record's unit S2), for "Now"'s line. */
        val beneath: Beneath = Beneath(),
    )

    /**
     * The network's own proxy as the engine has it (the proxy record's unit S2): [why] it has it
     * ([NetworkProxy.Why.NETWORK]) or none; the key of the user's choice "Send apps through this proxy" ([key],
     * [ThroughProxy.key]) and the choice ([always]); whether its addresses are on the local network ([local]); and, for
     * a proxy on the phone itself, the circumvention tool installed whose known port it names ([tool]), if one.
     */
    data class Beneath(
        val why: NetworkProxy.Why = NetworkProxy.Why.NONE,
        val key: String? = null,
        val always: Boolean = false,
        val local: Boolean = false,
        val tool: String? = null,
    )

    private val held = MutableStateFlow(State())

    /** The latest of what the service published. */
    val state: StateFlow<State> = held.asStateFlow()

    /** Android's settings and the PAC proxy's UID, at each reading of Android's proxy settings. Any thread. */
    fun publish(android: AndroidProxy, pacHandler: Int?) = held.update { it.copy(android = android, pacHandler = pacHandler) }

    /** The tools' UIDs, read off the main thread at the tunnel's start and at each change of the apps. Any thread. */
    fun publishTools(tools: Map<Int, String>, carriers: Map<Int, String>) = held.update { it.copy(tools = tools, carriers = carriers) }

    /** The network's own proxy as the engine has it, at each settle (S2). Any thread. */
    fun publishBeneath(beneath: Beneath) = held.update { it.copy(beneath = beneath) }

    /** Whether the hand-over could hand the choices, at each hand-over. Any thread. */
    fun publishReady(ready: Boolean) = held.update { it.copy(handReady = ready) }

    /** Forgets everything, when the tunnel stops. */
    fun clear() {
        held.value = State()
    }
}
