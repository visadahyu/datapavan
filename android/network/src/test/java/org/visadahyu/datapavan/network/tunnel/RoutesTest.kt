package org.visadahyu.datapavan.network.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.tunnel.Routes.Route

/**
 * Each app's one route (W7, part 2): a tunnel wins over the chain's "every app but the tool", a removed slot holds
 * its apps, an app left out passes through nothing of Watch's, the choices the screen offers, what a choice changes
 * in the chain beside it, and what the engine gets.
 */
class RoutesTest {
    private val tool = "org.example.tool"
    private val everyApp = Routes.Chain(on = true, allApps = true, apps = emptySet(), tool = tool)
    private val some = Routes.Chain(on = true, allApps = false, apps = setOf("org.example.mail"), tool = tool)
    private val off = Routes.Chain(on = false, allApps = true, apps = setOf("org.example.mail"), tool = tool)

    @Test
    fun one_route_per_app() {
        val tunnels = mapOf("org.example.mail" to 1, "org.example.chat" to 4)
        val slots = listOf(1, 2)
        val left = setOf("org.example.bank")
        assertEquals(Route.Tunnel(1), Routes.of("org.example.mail", everyApp, tunnels, slots, left))
        assertEquals("its tunnel wins over every app but the tool", Route.Tunnel(1), Routes.of("org.example.mail", some, tunnels, slots, left))
        assertEquals("a slot removed holds its app", Route.Waiting(4), Routes.of("org.example.chat", everyApp, tunnels, slots, left))
        assertEquals(Route.Tool, Routes.of("org.example.maps", everyApp, tunnels, slots, left))
        assertEquals(Route.Direct, Routes.of("org.example.maps", some, tunnels, slots, left))
        assertEquals("the tool itself goes directly", Route.Direct, Routes.of(tool, everyApp, tunnels, slots, left))
        assertEquals(Route.Direct, Routes.of("org.example.mail", off, emptyMap(), slots, left))
        assertEquals(Route.LeftOut, Routes.of("org.example.bank", everyApp, mapOf("org.example.bank" to 1), slots, left))
    }

    @Test
    fun the_choices_follow_the_chain() {
        val slots = listOf(2, 1)
        assertEquals(listOf(Route.Tool, Route.Tunnel(2), Route.Tunnel(1)), Routes.choices("org.example.maps", everyApp, slots))
        assertEquals(listOf(Route.Direct, Route.Tool, Route.Tunnel(2), Route.Tunnel(1)), Routes.choices("org.example.maps", some, slots))
        assertEquals(listOf(Route.Direct, Route.Tunnel(2), Route.Tunnel(1)), Routes.choices("org.example.maps", off, slots))
        assertEquals(listOf(Route.Direct, Route.Tunnel(2), Route.Tunnel(1)), Routes.choices(tool, everyApp, slots))
    }

    @Test
    fun a_choice_takes_the_app_out_of_its_other_way() {
        assertEquals(Routes.Change(emptySet(), 2), Routes.choose("org.example.mail", Route.Tunnel(2), some))
        assertEquals(Routes.Change(setOf("org.example.mail", "org.example.maps"), null), Routes.choose("org.example.maps", Route.Tool, some))
        assertEquals("every app already", Routes.Change(emptySet(), null), Routes.choose("org.example.maps", Route.Tool, everyApp))
        assertEquals(Routes.Change(emptySet(), null), Routes.choose("org.example.mail", Route.Direct, some))
    }

    @Test
    fun the_engine_gets_each_routed_app_by_uid_waiting_ones_included() {
        val uids = mapOf("org.example.mail" to 10_100, "org.example.chat" to 10_101, "org.example.a" to 10_200, "org.example.b" to 10_200, "org.example.bank" to 10_300)
        val routes = Routes.forEngine(
            mapOf("org.example.mail" to 1, "org.example.chat" to 4, "org.example.gone" to 1, "org.example.bank" to 2, "org.example.b" to 2, "org.example.a" to 1),
            leftOut = setOf("org.example.bank"),
        ) { uids[it] }
        assertEquals(listOf(10_200 to 1, 10_101 to 4, 10_100 to 1), routes)
    }

    /**
     * The order a change is applied in (fix round, security review M2): a change that gives the app a tunnel sets the
     * tunnel's route first and the chain's list after; one that takes it away, the chain first.
     */
    @Test
    fun a_new_tunnel_goes_in_before_the_old_way_is_taken_away() {
        assertTrue("the tool to a tunnel", Routes.choose("org.example.mail", Route.Tunnel(2), some).tunnelFirst)
        assertTrue("a waiting route", Routes.choose("org.example.mail", Route.Waiting(4), some).tunnelFirst)
        assertFalse("a tunnel to the tool", Routes.choose("org.example.mail", Route.Tool, some).tunnelFirst)
        assertFalse("a tunnel to directly", Routes.choose("org.example.mail", Route.Direct, some).tunnelFirst)
    }

    /** An app waiting for a removed configuration is told apart from one that goes through one (screens review m1). */
    @Test
    fun waiting_apps_are_told_apart_from_tunnelled_ones() {
        val (through, waiting) = Routes.split(
            mapOf("org.example.mail" to 1, "org.example.chat" to 4, "org.example.bank" to 4),
            slots = listOf(1, 2),
            leftOut = setOf("org.example.bank"),
        )
        assertEquals(mapOf("org.example.mail" to 1), through)
        assertEquals(mapOf("org.example.chat" to 4), waiting)
    }
}
