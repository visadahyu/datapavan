package org.visadahyu.datapavan.watch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class TunnelSetupTest {
    private val installed = setOf("org.example.bank", "org.example.chat", "org.example.game")

    /** The packages handed to the Builder, in order, as Android's `VpnConfig` lists them. */
    private fun handed(packages: Iterable<String>): Pair<List<String>, List<String>> {
        val builder = mutableListOf<String>()
        val taken = TunnelSetup.added(packages) { app -> (app in installed).also { if (it) builder += app } }
        return builder to taken
    }

    @Test
    fun theSameAppsGoToTheBuilderInTheSameOrderWhateverOrderTheSetGives() {
        val one = linkedSetOf("org.example.game", "org.example.bank", "org.example.chat")
        val other = linkedSetOf("org.example.chat", "org.example.game", "org.example.bank")
        val (builder, taken) = handed(one)
        assertEquals(listOf("org.example.bank", "org.example.chat", "org.example.game"), builder)
        assertEquals("what the setup keeps is what the Builder took", builder, taken)
        assertEquals("the same list for the same set, so Android keeps the network", taken, handed(other).second)
    }

    /**
     * AOSP's `Builder` takes a package no longer installed and keeps its name; a maker's might refuse it,
     * with `NameNotFoundException`, as this fake `Builder` does: the list kept is then the one the
     * `Builder` took, without it.
     */
    @Test
    fun anAppABuilderRefusesLeavesTheListAsAndroidHasIt() {
        val (builder, taken) = handed(setOf("org.example.chat", "org.example.removed", "org.example.bank"))
        assertEquals(listOf("org.example.bank", "org.example.chat"), builder)
        assertEquals(builder, taken)
    }

    @Test
    fun theEngineTakesTheTunnelOnlyWhereAddressesAndListsAreTheSame() {
        val apps = listOf("org.example.bank", "org.example.chat")
        val setup = TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps)
        assertEquals(setup, TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps.toList()))
        assertNotEquals("other addresses", setup, TunnelSetup(TunnelAddresses.SPARE, emptyList(), apps))
        assertNotEquals("an app left out more", setup, TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps + "org.example.game"))
        assertNotEquals("Android compares ordered lists", setup, TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps.reversed()))
        assertNotEquals("the test's apps instead", setup, TunnelSetup(TunnelAddresses.COMMON, apps, emptyList()))
    }
}
