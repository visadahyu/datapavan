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

    /**
     * What choosing [route] for [app] changes: the chain's list of apps, and the app's tunnel (null for none).
     *
     * The order it is applied in (fix round, security review M2): the engine lets an app's tunnel win over the
     * chain, so a change that gives the app a tunnel ([tunnelFirst]) sets the tunnel's route first and takes the app
     * off the chain's list only once that is in the engine; one that takes its tunnel away puts it on the chain's
     * list first. Either way the app's new route is in the engine before its old one goes, and it never goes
     * directly in between.
     */
    data class Change(val chainApps: Set<String>, val tunnel: Int?) {
        val tunnelFirst: Boolean get() = tunnel != null
    }

    fun choose(app: String, route: Route, chain: Chain): Change = when (route) {
        is Route.Tunnel -> Change(chain.apps - app, route.slot)
        is Route.Waiting -> Change(chain.apps - app, route.slot)
        Route.Tool -> Change(if (chain.allApps) chain.apps else chain.apps + app, null)
        Route.Direct, Route.LeftOut -> Change(chain.apps - app, null)
    }

    /**
     * The apps routed to a slot, apps left out aside, split into those that go through a configuration that holds
     * the slot and those that wait for one since removed (fix round, screens review m1): a waiting app goes nowhere,
     * and is never counted or described as going through a configuration.
     */
    fun split(tunnels: Map<String, Int>, slots: Collection<Int>, leftOut: Set<String>): Pair<Map<String, Int>, Map<String, Int>> =
        tunnels.filterKeys { it !in leftOut }.entries.partition { it.value in slots }
            .let { (through, waiting) -> through.associate { it.key to it.value } to waiting.associate { it.key to it.value } }

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
