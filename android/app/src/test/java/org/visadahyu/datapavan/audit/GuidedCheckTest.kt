package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GuidedCheckTest {
    private val day = UsageFacts.DAY
    private val hour = 60 * 60 * 1000L

    private fun app(
        packageName: String = "app",
        uid: Int = 10_100,
        isSystem: Boolean = false,
        launcherIcon: Boolean = true,
        isVpnApp: Boolean = false,
        firstInstall: Long = 0,
        worksUnopened: Boolean = false,
        quietRole: QuietRole? = null,
    ) = AppFacts(
        packageName = packageName,
        label = packageName,
        isSystem = isSystem,
        enabled = true,
        installer = null,
        firstInstall = firstInstall,
        lastUpdate = firstInstall,
        grantedDangerous = emptyList(),
        sensors = emptySet(),
        special = emptySet(),
        isVpnApp = isVpnApp,
        vpnAuthorised = false,
        uid = uid,
        launcherIcon = launcherIcon,
        worksUnopened = worksUnopened,
        quietRole = quietRole,
    )

    private fun reading(at: Long, received: Long, sent: Long, all: Long, live: Long?) =
        CheckReading(at, NetworkUse(wifi = Traffic(received, sent)), all, live)

    @Test
    fun periodStartsOnABoundaryADayEarlierAndEndsInTheFuture() {
        val first = 20_000 * day + 5 * hour + 123
        val (start, end) = GuidedCheck.period(first)
        assertEquals(0, start % GuidedCheck.BUCKET_MS)
        assertTrue(start <= first - day)
        assertTrue(start > first - day - GuidedCheck.BUCKET_MS)
        assertEquals(first + 2 * day, end)
    }

    @Test
    fun waitsFifteenSecondsAfterTheLastQuery() {
        assertEquals(0, GuidedCheck.wait(now = 50_000, lastQuery = null))
        assertEquals(5_000, GuidedCheck.wait(now = 50_000, lastQuery = 40_000))
        assertEquals(0, GuidedCheck.wait(now = 60_000, lastQuery = 40_000))
    }

    @Test
    fun aReadingThatFallsShortOfTheLiveTotalsIsBehind() {
        val first = reading(0, 0, 0, all = 1_000_000, live = 5_000_000)
        // The spike's stale reading: nothing counted while about 1 MB moved.
        assertEquals(Freshness.BEHIND, GuidedCheck.freshness(first, reading(1, 0, 0, all = 1_000_000, live = 6_091_166), vpnActive = false))
        // Fresh: equal, or within 5 % or 64 KB.
        assertEquals(Freshness.UP_TO_DATE, GuidedCheck.freshness(first, reading(1, 0, 0, all = 2_091_166, live = 6_091_166), vpnActive = false))
        assertEquals(Freshness.UP_TO_DATE, GuidedCheck.freshness(first, reading(1, 0, 0, all = 2_040_000, live = 6_091_166), vpnActive = false))
        assertEquals(Freshness.UP_TO_DATE, GuidedCheck.freshness(first, reading(1, 0, 0, all = 1_000_000, live = 5_060_000), vpnActive = false))
        // More counted than moved: the first reading was behind.
        assertEquals(Freshness.FIRST_BEHIND, GuidedCheck.freshness(first, reading(1, 0, 0, all = 3_000_000, live = 6_000_000), vpnActive = false))
        assertEquals(Freshness.NOT_CHECKED_VPN, GuidedCheck.freshness(first, reading(1, 0, 0, all = 1_000_000, live = 9_000_000), vpnActive = true))
        assertEquals(Freshness.NOT_CHECKED, GuidedCheck.freshness(first, reading(1, 0, 0, all = 1_000_000, live = null), vpnActive = false))
    }

    @Test
    fun theResultIsTheDifferenceAndTheShareOnlyForActivitiesThatReceive() {
        val first = reading(1_000, received = 500, sent = 100, all = 600, live = 600)
        val second = reading(61_000, received = 10_625_896 + 500, sent = 324_541 + 100, all = 10_950_437 + 600, live = 10_950_437 + 600)
        val result = GuidedCheck.result(CheckActivity.DOWNLOAD, first, second, vpnActive = false) { null }
        assertEquals(60_000, result.millis)
        assertEquals(10_625_896, result.use.received)
        assertEquals(324_541, result.use.sent)
        assertEquals(Freshness.UP_TO_DATE, result.freshness)
        assertEquals(0.0305, result.sentShare!!, 0.0001)
        assertNull(GuidedCheck.result(CheckActivity.SEND, first, second, vpnActive = false) { null }.sentShare)
        assertNull(GuidedCheck.result(CheckActivity.DOWNLOAD, first, second, vpnActive = false) { NotCompared.OLD_KERNEL }.sentShare)
    }

    @Test
    fun saysWhyTheShareIsNotCompared() {
        val enough = 5_000_000L
        assertEquals(NotCompared.PROXY_OR_VPN, GuidedCheck.notCompared(app(), carriesOthers = true, sharedUid = false, enough, "6.1.0"))
        assertEquals(NotCompared.PROXY_OR_VPN, GuidedCheck.notCompared(app(isVpnApp = true), carriesOthers = false, sharedUid = false, enough, "6.1.0"))
        assertEquals(NotCompared.SHARED_UID, GuidedCheck.notCompared(app(), carriesOthers = false, sharedUid = true, enough, "6.1.0"))
        assertEquals(
            NotCompared.SYSTEM_COMPONENT,
            GuidedCheck.notCompared(app(isSystem = true, launcherIcon = false), carriesOthers = false, sharedUid = false, enough, "6.1.0"),
        )
        assertEquals(NotCompared.LITTLE_RECEIVED, GuidedCheck.notCompared(app(), carriesOthers = false, sharedUid = false, 999_999, "6.1.0"))
        assertEquals(NotCompared.OLD_KERNEL, GuidedCheck.notCompared(app(), carriesOthers = false, sharedUid = false, enough, "4.4.177-25902526"))
        assertNull(GuidedCheck.notCompared(app(isSystem = true, launcherIcon = true), carriesOthers = false, sharedUid = false, enough, "4.19.191"))
    }

    @Test
    fun kernelsOlderThan49CountWithTheOldModule() {
        assertTrue(GuidedCheck.olderThan49("4.4.177-25902526"))
        assertTrue(GuidedCheck.olderThan49("3.18.140"))
        assertFalse(GuidedCheck.olderThan49("4.9.337-g1234"))
        assertFalse(GuidedCheck.olderThan49("4.14.302"))
        assertFalse(GuidedCheck.olderThan49("6.6.50-android15-8"))
        assertFalse(GuidedCheck.olderThan49("unknown"))
    }

    private fun usage(lastUsed: Map<String, Long> = emptyMap(), use: Map<Int, NetworkUse> = emptyMap(), recordsSince: Long = 0) =
        UsageFacts(readAt = 1_000 * day, network = mapOf(30 to use), lastUsed = lastUsed, recordsSince = recordsSince)

    @Test
    fun anAppNeverOpenedSinceItsInstallThatUsedDataIsAFact() {
        val use = mapOf(10_100 to NetworkUse(wifi = Traffic(received = 2_000, sent = 500)))
        val installed = 990 * day
        val fact = TrafficFacts.neverOpened(app(firstInstall = installed), usage(use = use, recordsSince = 900 * day), sharedUid = false)
        assertEquals(NeverOpenedUse(installed, use.getValue(10_100)), fact)
        // Opened since, or no data, or a reason that makes the fact say little: nothing.
        assertNull(TrafficFacts.neverOpened(app(firstInstall = installed), usage(mapOf("app" to installed + 1), use), sharedUid = false))
        assertNull(TrafficFacts.neverOpened(app(firstInstall = installed), usage(), sharedUid = false))
        assertNull(TrafficFacts.neverOpened(app(firstInstall = installed, isSystem = true), usage(use = use), sharedUid = false))
        assertNull(TrafficFacts.neverOpened(app(firstInstall = installed, worksUnopened = true), usage(use = use), sharedUid = false))
        assertNull(TrafficFacts.neverOpened(app(firstInstall = installed), usage(use = use), sharedUid = true))
        // Installed before the oldest record: Android may have forgotten a use.
        assertNull(TrafficFacts.neverOpened(app(firstInstall = installed), usage(use = use, recordsSince = 995 * day), sharedUid = false))
        // A use recorded before a reinstall does not count.
        assertEquals(fact, TrafficFacts.neverOpened(app(firstInstall = installed), usage(mapOf("app" to installed - 1), use), sharedUid = false))
    }

    @Test
    fun backgroundSendingByAQuietRoleIsAFactFromOneMegabyte() {
        val keyboard = app(quietRole = QuietRole.KEYBOARD)
        val sending = mapOf(10_100 to NetworkUse(wifi = Traffic(sent = 1_200_000, backgroundSent = 700_000), mobile = Traffic(sent = 300_000, backgroundSent = 300_000)))
        assertEquals(1_000_000L, TrafficFacts.quietRoleSent(keyboard, usage(use = sending)))
        val little = mapOf(10_100 to NetworkUse(wifi = Traffic(received = 50_000_000, sent = 2_000_000, backgroundSent = 999_999)))
        assertNull(TrafficFacts.quietRoleSent(keyboard, usage(use = little)))
        assertNull(TrafficFacts.quietRoleSent(app(), usage(use = sending)))
    }
}
