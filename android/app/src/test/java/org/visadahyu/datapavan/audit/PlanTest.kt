package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PlanTest {
    private val day = UsageFacts.DAY
    private val now = 1_000 * day

    private fun app(
        packageName: String,
        isSystem: Boolean = false,
        launcherIcon: Boolean = true,
        firstInstall: Long = 0,
        granted: List<String> = emptyList(),
        sensors: Set<Sensor> = emptySet(),
        special: Set<SpecialAccess> = emptySet(),
        isVpnApp: Boolean = false,
        vpnAuthorised: Boolean = false,
        enabled: Boolean = true,
    ) = AppFacts(
        packageName = packageName,
        label = packageName,
        isSystem = isSystem,
        enabled = enabled,
        installer = null,
        firstInstall = firstInstall,
        lastUpdate = firstInstall,
        grantedDangerous = granted,
        sensors = sensors,
        special = special,
        isVpnApp = isVpnApp,
        vpnAuthorised = vpnAuthorised,
        uid = 10_000 + packageName.hashCode().mod(10_000),
        launcherIcon = launcherIcon,
    )

    private fun usage(lastUsed: Map<String, Long> = emptyMap(), network: Map<Int, NetworkUse> = emptyMap()) =
        UsageFacts(readAt = now, network = mapOf(30 to network, 7 to emptyMap()), lastUsed = lastUsed, recordsSince = 0)

    private fun input(
        apps: List<Pair<AppFacts, List<FindingKind>>>,
        device: List<FindingKind> = emptyList(),
        usage: UsageFacts? = usage(),
        trackers: Map<String, AppTrackers>? = null,
        floor: Map<String, FloorReason> = emptyMap(),
    ) = PlanInput(
        device, apps, usage, trackers,
        mapOf(1 to TrackerInfo(1, "Ads", listOf("Advertisement"), ""), 2 to TrackerInfo(2, "Crashes", listOf("Crash reporting"), "")),
        floor, ownPackage = "org.visadahyu.datapavan",
    )

    private val camera = "android.permission.CAMERA"
    private val contacts = "android.permission.READ_CONTACTS"

    @Test
    fun theLevelsDifferInWhatTheyInclude() {
        assertTrue(PlanReason.entries.filter { PlanLevel.LIGHT.includes(it) }.all { it.planClass == PlanClass.A || it == PlanReason.NOT_OPENED_SENSITIVE })
        assertEquals(PlanReason.entries - PlanReason.PREINSTALLED, PlanReason.entries.filter { PlanLevel.MEDIUM.includes(it) })
        assertEquals(PlanReason.entries, PlanReason.entries.filter { PlanLevel.STRICT.includes(it) })
    }

    @Test
    fun thePhonesItemsOpenItsScreens() {
        val all = listOf(FindingKind.USB_DEBUGGING, FindingKind.WIRELESS_DEBUGGING, FindingKind.USER_CERTIFICATE_AUTHORITY, FindingKind.OLD_SECURITY_PATCH)
        val items = Plan.items(input(emptyList(), device = all), PlanLevel.MEDIUM).items
        assertEquals(listOf(PlanReason.WIRELESS_DEBUGGING, PlanReason.CERTIFICATE_AUTHORITY, PlanReason.USB_DEBUGGING), items.map { it.reason })
        assertEquals(listOf(Screen.DEVELOPER_OPTIONS), items[0].screens)
        assertEquals(listOf(Screen.SECURITY), items[1].screens)
        // USB debugging is class B, so the light level leaves it out.
        assertEquals(2, Plan.items(input(emptyList(), device = all), PlanLevel.LIGHT).items.size)
    }

    @Test
    fun controlAccessOpensTheScreensOfWhatTheAppHoldsWithCare() {
        val spy = app("spy", special = setOf(SpecialAccess.NOTIFICATION_LISTENER, SpecialAccess.ACCESSIBILITY, SpecialAccess.OVERLAY))
        val item = Plan.items(input(listOf(spy to listOf(FindingKind.REMOTE_CONTROL)), usage = usage(lastUsed = mapOf("spy" to now))), PlanLevel.LIGHT).items.single()
        assertEquals(PlanReason.CONTROL_ACCESS, item.reason)
        assertEquals(listOf(Screen.ACCESSIBILITY, Screen.NOTIFICATION_LISTENER), item.screens)
        assertEquals(Care.CONTROL, item.care)
    }

    @Test
    fun appsNotOpenedFor90DaysAreSplitBySensitivity() {
        val cameraApp = app("camera", granted = listOf(camera), sensors = setOf(Sensor.CAMERA))
        val contactsApp = app("contacts", granted = listOf(contacts))
        val recent = app("recent", granted = listOf(camera), sensors = setOf(Sensor.CAMERA))
        val apps = listOf(cameraApp, contactsApp, recent).map { it to emptyList<FindingKind>() }
        val used = usage(lastUsed = mapOf("camera" to now - 120 * day, "contacts" to now - 200 * day, "recent" to now - 10 * day))

        val light = Plan.items(input(apps, usage = used), PlanLevel.LIGHT).items
        assertEquals(listOf("camera"), light.map { it.app?.packageName })
        assertEquals(PlanReason.NOT_OPENED_SENSITIVE, light[0].reason)
        assertEquals(listOf(Screen.APP_INFO, Screen.UNUSED_APP_SETTING), light[0].screens)
        assertEquals(120L, light[0].notOpenedDays)

        val medium = Plan.items(input(apps, usage = used), PlanLevel.MEDIUM).items
        assertEquals(listOf("camera", "contacts"), medium.map { it.app?.packageName })
        assertEquals(PlanReason.NOT_OPENED_OTHER, medium[1].reason)
        // Without usage access there is nothing to say about opening.
        assertTrue(Plan.items(input(apps, usage = null), PlanLevel.STRICT).items.isEmpty())
    }

    @Test
    fun specialAccessAndVpnPermissionOpenTheirOwnScreens() {
        val vpn = app("vpn", special = setOf(SpecialAccess.BATTERY_EXEMPT), isVpnApp = true, vpnAuthorised = true)
        val item = Plan.items(input(listOf(vpn to emptyList()), usage = usage(lastUsed = mapOf("vpn" to now - 95 * day))), PlanLevel.LIGHT).items.single()
        assertEquals(listOf(Screen.BATTERY, Screen.VPN), item.screens)
    }

    @Test
    fun preinstalledAppsComeOnlyAtTheStrictLevelAndNeedCare() {
        val collector = app("com.facebook.services", isSystem = true, launcherIcon = false)
        val game = app("vendor.game", isSystem = true)
        val hidden = app("vendor.part", isSystem = true, launcherIcon = false)
        val apps = listOf(collector to listOf(FindingKind.PREINSTALLED_COLLECTOR), game to emptyList(), hidden to emptyList())
        val used = usage(lastUsed = mapOf("com.facebook.services" to now - day))
        assertTrue(Plan.items(input(apps, usage = used), PlanLevel.MEDIUM).items.isEmpty())
        val strict = Plan.items(input(apps, usage = used), PlanLevel.STRICT).items
        assertEquals(setOf("com.facebook.services", "vendor.game"), strict.map { it.app?.packageName }.toSet())
        assertTrue(strict.all { it.reason == PlanReason.PREINSTALLED && it.care == Care.UNTESTED && it.screens == listOf(Screen.APP_INFO) })
        assertEquals(1000L, strict.first { it.app?.packageName == "vendor.game" }.notOpenedDays)
        assertNull(strict.first { it.app?.packageName == "com.facebook.services" }.notOpenedDays)
    }

    @Test
    fun oneCardPerAppWithItsMostUrgentReasonFirst() {
        val installer = app("installer", granted = listOf(camera), sensors = setOf(Sensor.CAMERA), special = setOf(SpecialAccess.INSTALL_UNKNOWN_APPS))
        val item = Plan.items(input(listOf(installer to listOf(FindingKind.INSTALLS_APPS)), usage = usage(lastUsed = mapOf("installer" to now - 100 * day))), PlanLevel.MEDIUM)
            .items.single()
        assertEquals(PlanReason.NOT_OPENED_SENSITIVE, item.reason)
        assertEquals(listOf(PlanReason.INSTALLS_APPS), item.also)
        assertEquals(listOf(Screen.APP_INFO, Screen.UNUSED_APP_SETTING, Screen.INSTALL_UNKNOWN_APPS), item.screens)
    }

    @Test
    fun theQueueGoesByClassThenTrackersThenTimeNotOpenedThenName() {
        val names = listOf("b-old", "a-old", "older", "ads", "copy")
        val apps = names.map { app(it, granted = listOf(camera), sensors = setOf(Sensor.CAMERA)) to emptyList<FindingKind>() } +
            (app("crashes", granted = listOf(camera), sensors = setOf(Sensor.CAMERA)) to emptyList())
        val used = usage(lastUsed = mapOf("b-old" to now - 100 * day, "a-old" to now - 100 * day, "older" to now - 300 * day, "ads" to now - 91 * day, "copy" to now, "crashes" to now - 99 * day))
        val trackers = mapOf("ads" to AppTrackers(listOf(1), emptyList()), "crashes" to AppTrackers(listOf(2), emptyList()))
        val withCopy = apps.map { (app, findings) -> app to if (app.packageName == "copy") listOf(FindingKind.MODIFIED_APP) else findings }
        val items = Plan.items(input(withCopy, usage = used, trackers = trackers), PlanLevel.LIGHT).items
        assertEquals(listOf("copy", "ads", "older", "a-old", "b-old", "crashes"), items.map { it.app?.packageName })
    }

    @Test
    fun theFloorLeavesAppsAloneAndSaysWhich() {
        val keyboard = app("keyboard", granted = listOf(camera), sensors = setOf(Sensor.CAMERA))
        val own = app("org.visadahyu.datapavan", special = setOf(SpecialAccess.USAGE_ACCESS))
        val used = usage(lastUsed = mapOf("keyboard" to now - 200 * day))
        val result = Plan.items(input(listOf(keyboard to emptyList(), own to emptyList()), usage = used, floor = mapOf("keyboard" to FloorReason.KEYBOARD)), PlanLevel.STRICT)
        assertTrue(result.items.isEmpty())
        assertEquals(listOf(keyboard to FloorReason.KEYBOARD), result.leftAlone)
    }

    @Test
    fun aSessionSkipsWhatWasKeptWhileItStaysAsItWasAndShowsFiveCards() {
        val apps = (1..7).map { app("app$it", granted = listOf(camera), sensors = setOf(Sensor.CAMERA)) to emptyList<FindingKind>() }
        val items = Plan.items(input(apps, usage = usage()), PlanLevel.LIGHT).items
        val first = items.first()
        val kept = mapOf(first.key to ItemState.of(first.app))
        val session = Plan.session(items, kept) { ItemState.of(it.app) }
        assertEquals(Plan.SESSION_CARDS, session.size)
        assertTrue(first !in session)
        // Once its state changes, the kept item comes back.
        val changed = Plan.session(items, kept) { if (it == first) ItemState.of(it.app).copy(permissions = setOf(contacts)) else ItemState.of(it.app) }
        assertEquals(first, changed.first())
    }

    @Test
    fun theDenyListMatchesPackagesPrefixesAndVendors() {
        val floor = SafetyFloor.parse(
            listOf(
                "# comment",
                "android\t*\tcore\thttps://example.org\t2026-11-03",
                "com.android.networkstack*\t*\tconnectivity\thttps://example.org\t2026-11-03",
                "com.samsung.android.kgclient\tsamsung\tdevice-lock\thttps://example.org\t2026-11-03",
                "com.example.future\t*\tsomething-new\thttps://example.org\t2026-11-03",
            ).joinToString("\n"),
        )
        assertEquals(FloorReason.CORE, floor.reason("android", "Google"))
        assertNull(floor.reason("android.ext", "Google"))
        assertEquals(FloorReason.CONNECTIVITY, floor.reason("com.android.networkstack.tethering.inprocess", "Xiaomi"))
        assertEquals(FloorReason.DEVICE_LOCK, floor.reason("com.samsung.android.kgclient", "samsung"))
        assertNull(floor.reason("com.samsung.android.kgclient", "Google"))
        assertNull(floor.reason("com.example.future", "Google"))
    }
}
