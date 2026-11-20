package org.visadahyu.datapavan.watch.tunnel

/**
 * Each app's one route (ADR 0035, routes decided on 2026-11-19; W7, part 2): directly, through the user's tool
 * (W6's chain), or through one WireGuard configuration. An app's tunnel wins over the chain's "every app but the
 * tool" (the maintainer's answer 3): the app's own route is the more specific choice. An app left out of Watch
 * (ADR 0041) passes through none of them. Pure, for the JVM tests; the screen and the service read it.
 */
object Routes {
    /** Where an app's traffic goes. */
    sealed interface Route {
        /** To the internet directly, through Watch. */
        data object Direct : Route

        /** Through the user's circumvention tool. */
        data object Tool : Route

        /** Through the configuration in [slot]. */
        data class Tunnel(val slot: Int) : Route

        /** Routed to a configuration since removed, whose apps the user chose to keep waiting: nothing goes out. */
        data class Waiting(val slot: Int) : Route

        /** Left out of Watch: outside its tunnel, through none of these. */
        data object LeftOut : Route
    }

    /** The chain as it bears on the routes: whether it is on, for every app or a list, and the tool's package. */
    data class Chain(val on: Boolean, val allApps: Boolean, val apps: Set<String>, val tool: String?) {
        /** Whether the chain covers [app], tunnels aside. */
        fun covers(app: String): Boolean = on && app != tool && (allApps || app in apps)
    }

    /** The route of [app], given the chain, the tunnels' routes, the slots that hold a configuration, and the apps left out. */
    fun of(app: String, chain: Chain, tunnels: Map<String, Int>, slots: Collection<Int>, leftOut: Set<String>): Route {
        if (app in leftOut) return Route.LeftOut
        tunnels[app]?.let { slot -> return if (slot in slots) Route.Tunnel(slot) else Route.Waiting(slot) }
        return if (chain.covers(app)) Route.Tool else Route.Direct
    }

    /**
     * The routes [app] may be given now, in the order the screen offers them: directly where the chain would not take
     * it anyway (off, or a list of apps), through the tool while the chain is on, and through each configuration.
     */
    fun choices(app: String, chain: Chain, slots: List<Int>): List<Route> = buildList {
        if (!chain.on || !chain.allApps || app == chain.tool) add(Route.Direct)
        if (chain.on && app != chain.tool) add(Route.Tool)
        slots.forEach { add(Route.Tunnel(it)) }
    }

    /** What choosing [route] for [app] changes: the chain's list of apps, and the app's tunnel (null for none). */
    data class Change(val chainApps: Set<String>, val tunnel: Int?)

    fun choose(app: String, route: Route, chain: Chain): Change = when (route) {
        is Route.Tunnel -> Change(chain.apps - app, route.slot)
        is Route.Waiting -> Change(chain.apps - app, route.slot)
        Route.Tool -> Change(if (chain.allApps) chain.apps else chain.apps + app, null)
        Route.Direct, Route.LeftOut -> Change(chain.apps - app, null)
    }

    /**
     * The routes the engine gets, by UID, each app routed to a slot, waiting ones included, so that they wait;
     * apps left out never reach the engine, and an app no longer installed has no UID. Packages that share a UID
     * share a route: the first by name decides.
     */
    fun forEngine(tunnels: Map<String, Int>, leftOut: Set<String>, uidOf: (String) -> Int?): List<Pair<Int, Int>> {
        val routes = linkedMapOf<Int, Int>()
        for ((app, slot) in tunnels.toSortedMap()) {
            if (app in leftOut) continue
            val uid = uidOf(app) ?: continue
            routes.putIfAbsent(uid, slot)
        }
        return routes.toList()
    }
}
