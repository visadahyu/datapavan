package org.visadahyu.datapavan.watch

/**
 * What of a tunnel's setup decides whether the running engine may take the tunnel when Watch sets it up
 * again (ADR 0044, unit 12b): the tunnel's [addresses], to which the apps' connections and the engine's
 * listeners are bound, and the apps Watch handed Android's `Builder`, in the order it handed them.
 *
 * Android keeps the VPN network, and updates it in place, only when `allowBypass` and the allowed and
 * disallowed apps are as before, the apps compared as ordered lists (AOSP's
 * `Vpn.updateLinkPropertiesInPlaceIfPossible`, read in review, not measured on a device); Watch never calls
 * `allowBypass`, so only the lists can differ. Otherwise Android connects a new network, with a new netId,
 * before the old one goes, and netd marks the packets that arrive on the tunnel with the network's netId,
 * which the connections Watch's engine accepted keep (`tcp_fwmark_accept`): once the old network goes they
 * route nowhere, and a new engine, whose connections reset at once, is the better end for them.
 */
internal data class TunnelSetup(
    val addresses: TunnelAddresses.Set,
    /** The apps only allowed in the tunnel, in the order Watch added them; debug builds' test only. */
    val allowedApps: List<String>,
    /** The apps left out of the tunnel, in the order Watch added them. */
    val disallowedApps: List<String>,
) {
    companion object {
        /**
         * Hands [packages] to [add] in sorted order, and gives the ones it took, in that order. The same
         * set so gives Android the same list at each setup, whatever order the set comes in, as from
         * `SharedPreferences.getStringSet`'s `HashSet`, which was what changed the list when the apps had
         * not. AOSP's `Builder` takes a package no longer installed too, and keeps its name in the list
         * (its `verifyApp` ignores a missing one); [add] says false where a `Builder` refused one, as an
         * Android maker's might, with `NameNotFoundException`, so that the list kept is the one Android
         * has either way.
         */
        fun added(packages: Iterable<String>, add: (String) -> Boolean): List<String> {
            val taken = mutableListOf<String>()
            for (app in packages.toSortedSet()) {
                if (add(app)) taken += app
            }
            return taken
        }
    }
}
