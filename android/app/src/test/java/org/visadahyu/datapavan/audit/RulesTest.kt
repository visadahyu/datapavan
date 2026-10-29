package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RulesTest {
    private fun app(
        packageName: String = "org.example.app",
        isSystem: Boolean = false,
        enabled: Boolean = true,
        installer: String? = "com.android.vending",
        sensors: Set<Sensor> = emptySet(),
        special: Set<SpecialAccess> = emptySet(),
        isVpnApp: Boolean = false,
    ) = AppFacts(
        packageName = packageName,
        label = packageName,
        isSystem = isSystem,
        enabled = enabled,
        installer = installer,
        firstInstall = 0,
        lastUpdate = 0,
        grantedDangerous = emptyList(),
        sensors = sensors,
        special = special,
        isVpnApp = isVpnApp,
        vpnAuthorised = false,
    )

    private fun device(
        usb: Boolean = false,
        wireless: Boolean = false,
        cas: List<String> = emptyList(),
        integrity: Integrity? = Integrity(securityLevel = 1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_609),
    ) = DeviceFacts(usb, wireless, cas, vpnActive = false, integrity = integrity)

    @Test
    fun `a clean app from a store has no findings`() {
        assertEquals(emptyList<FindingKind>(), Rules.forApp(app()))
    }

    @Test
    fun `a VPN app with accessibility is the most urgent finding`() {
        val findings = Rules.forApp(app(isVpnApp = true, special = setOf(SpecialAccess.ACCESSIBILITY), installer = null))
        assertEquals(FindingKind.VPN_WITH_REMOTE_CONTROL, findings.first())
        assertTrue(FindingKind.REMOTE_CONTROL !in findings)
    }

    @Test
    fun `drawing over other apps is not remote control, not even for a VPN app`() {
        assertTrue(FindingKind.REMOTE_CONTROL !in Rules.forApp(app(special = setOf(SpecialAccess.OVERLAY))))
        assertTrue(FindingKind.VPN_WITH_REMOTE_CONTROL !in Rules.forApp(app(isVpnApp = true, special = setOf(SpecialAccess.OVERLAY))))
    }

    @Test
    fun `enabled preinstalled Meta apps are collectors, disabled ones are not`() {
        val manager = app(packageName = "com.facebook.appmanager", isSystem = true, installer = null)
        assertEquals(listOf(FindingKind.PREINSTALLED_COLLECTOR), Rules.forApp(manager))
        assertEquals(emptyList<FindingKind>(), Rules.forApp(manager.copy(enabled = false)))
    }

    @Test
    fun `system apps are not reported for sensors or an unknown source`() {
        assertEquals(emptyList<FindingKind>(), Rules.forApp(app(isSystem = true, installer = null, sensors = setOf(Sensor.MICROPHONE))))
    }

    @Test
    fun `sideloaded apps and sensor access are reported, most severe first`() {
        val findings = Rules.forApp(app(installer = "com.google.android.packageinstaller", sensors = setOf(Sensor.CAMERA), special = setOf(SpecialAccess.INSTALL_UNKNOWN_APPS)))
        assertEquals(listOf(FindingKind.INSTALLS_APPS, FindingKind.SENSORS, FindingKind.UNKNOWN_SOURCE), findings)
    }

    @Test
    fun `a locked, verified, patched phone has no device findings`() {
        assertEquals(emptyList<FindingKind>(), Rules.forDevice(device(), nowYearMonth = 202_610))
    }

    @Test
    fun `device risks are reported, most severe first`() {
        val findings = Rules.forDevice(
            device(usb = true, cas = listOf("CN=Test"), integrity = Integrity(1, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_303)),
            nowYearMonth = 202_610,
        )
        assertEquals(
            listOf(FindingKind.USER_CERTIFICATE_AUTHORITY, FindingKind.BOOTLOADER_UNLOCKED, FindingKind.USB_DEBUGGING, FindingKind.OLD_SECURITY_PATCH),
            findings,
        )
    }

    @Test
    fun `a patch exactly twelve months old is still accepted`() {
        val integrity = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_510)
        assertTrue(FindingKind.OLD_SECURITY_PATCH !in Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
        assertTrue(FindingKind.OLD_SECURITY_PATCH in Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_611))
    }

    @Test
    fun `emulators attest in software only`() {
        val integrity = Integrity(0, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608)
        val findings = Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610)
        assertEquals(listOf(FindingKind.INTEGRITY_SOFTWARE_ONLY), findings)
    }

    @Test
    fun `apps are ordered by their most severe finding, then by label`() {
        val quiet = app(packageName = "a.quiet") to emptyList<FindingKind>()
        val camera = app(packageName = "b.camera") to listOf(FindingKind.SENSORS)
        val vpn = app(packageName = "c.vpn") to listOf(FindingKind.VPN_WITH_REMOTE_CONTROL)
        assertEquals(listOf(vpn, camera, quiet), listOf(quiet, camera, vpn).sortedWith(Rules.byUrgency))
    }

    @Test
    fun `review status follows sensor access since the review`() {
        val mic = setOf(Sensor.MICROPHONE)
        assertEquals(ReviewStatus.NOT_REVIEWED, Rules.reviewStatus(mic, reviewed = null))
        assertEquals(ReviewStatus.REVIEWED, Rules.reviewStatus(mic, reviewed = mic))
        assertEquals(ReviewStatus.REVIEWED, Rules.reviewStatus(emptySet(), reviewed = mic))
        assertEquals(ReviewStatus.CHANGED, Rules.reviewStatus(mic + Sensor.CAMERA, reviewed = mic))
        assertEquals(ReviewStatus.CHANGED, Rules.reviewStatus(mic, reviewed = emptySet()))
    }
}
