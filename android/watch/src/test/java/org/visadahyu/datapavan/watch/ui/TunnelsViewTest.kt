package org.visadahyu.datapavan.watch.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.visadahyu.datapavan.watch.R
import org.visadahyu.datapavan.watch.tunnel.Import
import org.visadahyu.datapavan.watch.tunnel.TunnelStates
import org.visadahyu.datapavan.watch.tunnel.TunnelStore

/** What the WireGuard part of Watch's screen shows (W7, part 2, fix round). */
class TunnelsViewTest {
    private fun configuration(slot: Int) =
        ConfigurationView(slot, TunnelStore.Name.Known("c$slot"), local = false, apps = 0, shown = TunnelStates.Shown.Idle, plainDns = false)

    /** The default tunnel is said whenever a configuration exists, the single one included (screens review M4). */
    @Test
    fun the_default_is_said_whenever_a_configuration_exists() {
        assertNull(TunnelsView().defaultNote)
        assertEquals(R.string.tunnels_default_note_one, TunnelsView(configurations = listOf(configuration(1))).defaultNote)
        assertEquals(R.string.tunnels_default_note, TunnelsView(configurations = listOf(configuration(2), configuration(1))).defaultNote)
    }

    /** Apps that wait for a removed configuration are said apart, apps left out aside (screens review m1). */
    @Test
    fun the_apps_waiting_for_a_removed_configuration_are_counted_apart() {
        val view = TunnelsView(
            configurations = listOf(configuration(1)),
            routes = mapOf("org.example.mail" to 1, "org.example.chat" to 3, "org.example.bank" to 3),
        )
        assertEquals(mapOf("org.example.chat" to 3), view.waiting(leftOut = setOf("org.example.bank")))
    }

    /**
     * The apps arriving after the confirmation opened set its ticks the first time only; a name, a switch and ticks
     * the user changed meanwhile, or before the screen was made anew, stay (screens review m3).
     */
    @Test
    fun the_proposal_read_again_keeps_what_the_user_changed() {
        val described = Import.read(
            "ok\nendpoint 192.0.2.1 51820\naddress 10.0.0.2/32\ndns 10.0.0.1\nallowed 0.0.0.0/0\neverything 1\npreshared 0\nmtu 1420\nonly org.example.mail",
        ) as Import.Described
        val proposal = Import.Proposal(listOf("org.example.mail"), setOf("org.example.mail"), emptyList(), emptyList(), emptyList(), emptyList())
        val opened = PendingView(described, "file", replacing = null, replacingName = null, chosen = emptySet(), local = false)
        val edited = opened.copy(name = "Work", local = true)
        val first = edited.with(proposal)
        assertEquals("Work", first.name)
        assertEquals(true, first.local)
        assertEquals(setOf("org.example.mail"), first.chosen)
        val unticked = first.copy(chosen = emptySet())
        assertEquals("the user's own ticks stay", emptySet<String>(), unticked.with(proposal).chosen)
    }
}
