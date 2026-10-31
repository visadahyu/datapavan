package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UsageTest {
    private val day = UsageFacts.DAY
    private val now = 1_000 * day

    private fun app(
        packageName: String,
        uid: Int,
        isSystem: Boolean = false,
        launcherIcon: Boolean = true,
        dangerous: List<String> = emptyList(),
        special: Set<SpecialAccess> = emptySet(),
        vpnAuthorised: Boolean = false,
        firstInstall: Long = 0,
        enabled: Boolean = true,
    ) = AppFacts(
        packageName = packageName,
        label = packageName,
        isSystem = isSystem,
        enabled = enabled,
        installer = null,
        firstInstall = firstInstall,
        lastUpdate = firstInstall,
        grantedDangerous = dangerous,
        sensors = emptySet(),
        special = special,
        isVpnApp = false,
        vpnAuthorised = vpnAuthorised,
        uid = uid,
        launcherIcon = launcherIcon,
    )

    private fun usage(lastUsed: Map<String, Long>, background: Map<Int, Long> = emptyMap(), recordsSince: Long = 0) = UsageFacts(
        readAt = now,
        network = mapOf(30 to background.mapValues { (_, bytes) -> NetworkUse(wifi = Traffic(received = bytes, backgroundReceived = bytes)) }),
        lastUsed = lastUsed,
        recordsSince = recordsSince,
    )

    @Test
    fun countsFromTheLastUseOrFromTheLaterOfInstallAndRecords() {
        val used = Dormancy.notOpened(app("a", 1), usage(mapOf("a" to now - 100 * day)))
        assertEquals(100, used.days)
        assertEquals(now - 100 * day, used.lastUsed)
        // No record: from the oldest record, or from the install when that is later.
        val never = Dormancy.notOpened(app("b", 2, firstInstall = now - 400 * day), usage(emptyMap(), recordsSince = now - 900 * day))
        assertEquals(400, never.days)
        assertNull(never.lastUsed)
        assertEquals(now - 30 * day, Dormancy.notOpened(app("c", 3), usage(emptyMap(), recordsSince = now - 30 * day)).since)
    }

    @Test
    fun listsAppsNotOpenedForNinetyDaysThatStillHoldSomething() {
        val apps = listOf(
            app("old.camera", 10, dangerous = listOf("android.permission.CAMERA")),
            app("old.keyboard", 11, special = setOf(SpecialAccess.ACCESSIBILITY)),
            app("old.vpn", 12, vpnAuthorised = true),
            app("old.plain", 13),
            app("recent.camera", 14, dangerous = listOf("android.permission.CAMERA")),
            app("old.disabled", 15, dangerous = listOf("android.permission.CAMERA"), enabled = false),
            app("system.part", 16, isSystem = true, launcherIcon = false, dangerous = listOf("android.permission.CAMERA")),
            app("system.app", 17, isSystem = true, dangerous = listOf("android.permission.CAMERA")),
            app("org.visadahyu.datapavan", 18, special = setOf(SpecialAccess.USAGE_ACCESS)),
        )
        val old = now - 120 * day
        val last = apps.associate { it.packageName to old } + ("recent.camera" to now - 10 * day) + ("old.camera" to now - 200 * day)
        val dormant = Dormancy.dormant(apps, usage(last), "org.visadahyu.datapavan")
        assertEquals(listOf("old.camera", "old.keyboard", "old.vpn", "system.app"), dormant.map { it.app.packageName })
        assertEquals(200, dormant.first().notOpened.days)
        assertEquals(setOf(StillHolds.SPECIAL_ACCESS), dormant[1].holds)
        assertEquals(setOf(StillHolds.VPN_PERMISSION), dormant[2].holds)
    }

    @Test
    fun countsBackgroundDataOnlyWhenNoAppOfTheUidWasUsed() {
        val apps = listOf(app("alone", 20), app("shared.idle", 21), app("shared.busy", 21))
        val last = mapOf("alone" to now - 100 * day, "shared.idle" to now - 100 * day, "shared.busy" to now - day)
        val dormant = Dormancy.dormant(apps, usage(last, background = mapOf(20 to 5_000L, 21 to 9_000L)), "own")
        assertEquals(listOf("alone"), dormant.map { it.app.packageName })
        assertEquals(setOf(StillHolds.BACKGROUND_DATA), dormant.single().holds)
    }

    @Test
    fun addsTrafficByDirectionAndState() {
        val sum = Traffic(1, 2, 1, 0) + Traffic(10, 20, 0, 20)
        assertEquals(Traffic(11, 22, 1, 20), sum)
        assertEquals(33, sum.total)
        assertEquals(21, sum.background)
        assertEquals(66, NetworkUse(sum, sum).total)
    }
}
