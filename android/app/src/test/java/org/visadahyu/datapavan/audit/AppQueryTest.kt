package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppQueryTest {
    private val day = UsageFacts.DAY
    private val now = 1_000 * day

    private fun app(
        packageName: String,
        label: String? = packageName,
        isSystem: Boolean = false,
        launcherIcon: Boolean = true,
        special: Set<SpecialAccess> = emptySet(),
        isVpnApp: Boolean = false,
        firstInstall: Long = 0,
        uid: Int = 10_000,
    ) = AppFacts(
        packageName = packageName, label = label, isSystem = isSystem, enabled = true, installer = null,
        firstInstall = firstInstall, lastUpdate = firstInstall, grantedDangerous = emptyList(), sensors = emptySet(),
        special = special, isVpnApp = isVpnApp, vpnAuthorised = false, uid = uid, launcherIcon = launcherIcon,
    )

    private val vpn = ListedApp(app("org.example.vpn", "Tunnel", isVpnApp = true, special = setOf(SpecialAccess.ACCESSIBILITY), uid = 10_001), listOf(FindingKind.VPN_WITH_REMOTE_CONTROL))
    private val game = ListedApp(app("com.example.game", "Game", firstInstall = 900 * day, uid = 10_002), listOf(FindingKind.TRACKERS, FindingKind.UNKNOWN_SOURCE), AppTrackers(listOf(1), emptyList()))
    private val proxy = ListedApp(app("com.example.proxy", "Proxy", firstInstall = 950 * day, uid = 10_003), listOf(FindingKind.UNKNOWN_SOURCE), carriesOthers = true)
    private val settings = ListedApp(app("com.android.settings", "Settings", isSystem = true, uid = 1_000), emptyList())
    private val all = listOf(vpn, game, proxy, settings)
    private val usage = UsageFacts(
        readAt = now,
        network = mapOf(30 to mapOf(10_002 to NetworkUse(wifi = Traffic(received = 5_000)), 10_003 to NetworkUse(wifi = Traffic(received = 9_000))), 7 to emptyMap()),
        lastUsed = mapOf("org.example.vpn" to now, "com.example.game" to now - 100 * day, "com.example.proxy" to now, "com.android.settings" to now),
        recordsSince = 0,
    )

    @Test
    fun eachFilterHoldsItsApps() {
        fun names(filter: AppFilter, usage: UsageFacts? = this.usage) = AppQuery.list(all, filter, "", AppSort.NAME, usage).map { it.app.label }
        // Unknown source alone is information, not something to look at.
        assertEquals(listOf("Game", "Tunnel"), names(AppFilter.WITH_FINDINGS))
        assertEquals(listOf("Game"), names(AppFilter.TRACKERS))
        assertEquals(listOf("Tunnel"), names(AppFilter.CONTROL))
        assertEquals(listOf("Game"), names(AppFilter.NOT_OPENED))
        assertEquals(emptyList<String>(), names(AppFilter.NOT_OPENED, usage = null))
        assertEquals(listOf("Settings"), names(AppFilter.PREINSTALLED))
        assertEquals(listOf("Proxy", "Tunnel"), names(AppFilter.VPN_PROXY))
        assertEquals(4, names(AppFilter.ALL).size)
        assertEquals(2, AppQuery.counts(all, usage).getValue(AppFilter.WITH_FINDINGS))
    }

    @Test
    fun searchLooksAtTheNameAndThePackage() {
        assertTrue(AppQuery.search("tun", vpn.app))
        assertTrue(AppQuery.search("EXAMPLE.VPN", vpn.app))
        assertTrue(AppQuery.search("  ", vpn.app))
        assertFalse(AppQuery.search("game", vpn.app))
        assertTrue(AppQuery.search("رسان", app("ir.example.chat", "پیام‌رسان")))
    }

    @Test
    fun theOrdersSortAsTheirNamesSay() {
        fun order(sort: AppSort) = AppQuery.list(all, AppFilter.ALL, "", sort, usage).map { it.app.label }
        assertEquals(listOf("Tunnel", "Game", "Proxy", "Settings"), order(AppSort.URGENCY))
        assertEquals(listOf("Game", "Proxy", "Settings", "Tunnel"), order(AppSort.NAME))
        assertEquals(listOf("Proxy", "Game", "Settings", "Tunnel"), order(AppSort.DATA_USE))
        assertEquals(listOf("Proxy", "Game", "Settings", "Tunnel"), order(AppSort.INSTALLED))
    }
}
