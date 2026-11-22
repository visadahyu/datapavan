package org.visadahyu.datapavan.watch

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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

    /**
     * The decision setUpAgain takes: the running engine takes the new tunnel only on the VPN network Android
     * keeps, its ordered lists of apps unchanged, with the same addresses; else a new engine starts.
     */
    @Test
    fun theRunningEngineTakesTheTunnelOnlyOnTheSameNetworkWithTheSameAddresses() {
        val apps = listOf("org.example.bank", "org.example.chat")
        val before = TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps)
        fun swaps(after: TunnelSetup) = TunnelSetup.canSwap(before, after)
        assertTrue("the same setup", swaps(TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps.toList())))
        assertFalse("no setup before", TunnelSetup.canSwap(null, before))
        assertFalse("other addresses", swaps(TunnelSetup(TunnelAddresses.SPARE, emptyList(), apps)))
        assertFalse("an app left out more", swaps(TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps + "org.example.game")))
        assertFalse("an app taken back", swaps(TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps.take(1))))
        assertFalse("Android compares ordered lists", swaps(TunnelSetup(TunnelAddresses.COMMON, emptyList(), apps.reversed())))
        assertFalse("the test's allowed apps instead", swaps(TunnelSetup(TunnelAddresses.COMMON, apps, emptyList())))
        val allowed = TunnelSetup(TunnelAddresses.COMMON, apps, emptyList())
        assertTrue("the same allowed apps", TunnelSetup.canSwap(allowed, TunnelSetup(TunnelAddresses.COMMON, apps.toList(), emptyList())))
        assertFalse("other allowed apps", TunnelSetup.canSwap(allowed, TunnelSetup(TunnelAddresses.COMMON, apps.reversed(), emptyList())))
    }
}
