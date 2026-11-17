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
        integrity: Integrity? = Integrity(securityLevel = 1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_609, trust = AttestationTrust.GOOGLE_ROOT),
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
            device(usb = true, cas = listOf("CN=Test"), integrity = Integrity(1, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_303, trust = AttestationTrust.GOOGLE_ROOT)),
            nowYearMonth = 202_610,
        )
        assertEquals(
            listOf(FindingKind.USER_CERTIFICATE_AUTHORITY, FindingKind.BOOTLOADER_UNLOCKED, FindingKind.USB_DEBUGGING, FindingKind.OLD_SECURITY_PATCH),
            findings,
        )
    }

    @Test
    fun `a patch exactly twelve months old is still accepted`() {
        val integrity = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_510, trust = AttestationTrust.GOOGLE_ROOT)
        assertTrue(FindingKind.OLD_SECURITY_PATCH !in Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
        assertTrue(FindingKind.OLD_SECURITY_PATCH in Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_611))
    }

    @Test
    fun `a software answer where no secure hardware is declared has no hardware check`() {
        val integrity = Integrity(0, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608, trust = AttestationTrust.GOOGLE_ROOT)
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

    @Test
    fun `a revoked attestation key is reported first, with the state it reports`() {
        val integrity = Integrity(1, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608, trust = AttestationTrust.REVOKED)
        val findings = Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610)
        assertEquals(listOf(FindingKind.ATTESTATION_REVOKED, FindingKind.BOOTLOADER_UNLOCKED), findings)
    }

    @Test
    fun `hardware attestation that Google does not vouch for is unconfirmed, or broken`() {
        val integrity = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_608, trust = AttestationTrust.OTHER_ROOT)
        assertEquals(listOf(FindingKind.ATTESTATION_UNCONFIRMED), Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
        val broken = integrity.copy(trust = AttestationTrust.BROKEN_CHAIN)
        assertEquals(listOf(FindingKind.ATTESTATION_BROKEN), Rules.forDevice(device(integrity = broken), nowYearMonth = 202_610))
    }

    @Test
    fun `a hardware claim under AOSP's published software root is reported alone`() {
        // Anyone can sign under that root: nothing the claim says is used, not even its unlocked bootloader.
        val integrity = Integrity(1, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 201_001, trust = AttestationTrust.SOFTWARE_ROOT)
        assertEquals(listOf(FindingKind.ATTESTATION_PUBLIC_ROOT), Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
    }

    @Test
    fun `a software answer on a phone with secure hardware for keys is as loud as what it could hide`() {
        // The third review's probe: a hooked keystore answers in software, with the app's challenge and the
        // TEE's own public key, under a chain it signs itself or under AOSP's software root. Neither is forged.
        val unlocked = Integrity(1, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608, trust = AttestationTrust.GOOGLE_ROOT)
        val worst = { facts: DeviceFacts -> Rules.forDevice(facts, nowYearMonth = 202_610).minOf { it.severity } }
        val withHardware = device(integrity = unlocked).copy(hardwareKeystore = true)
        assertEquals(Severity.HIGH, worst(withHardware))
        for (trust in listOf(AttestationTrust.BROKEN_CHAIN, AttestationTrust.SOFTWARE_ROOT, AttestationTrust.OTHER_ROOT)) {
            val hooked = withHardware.copy(integrity = unlocked.copy(securityLevel = 0, trust = trust))
            assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_ANSWER), Rules.forDevice(hooked, nowYearMonth = 202_610))
            assertEquals(Severity.HIGH, worst(hooked))
        }
    }

    @Test
    fun `an emulator says it is one, even where it declares a hardware keystore`() {
        // Android 15's emulator (the CI image dp-api35-ci) declares android.hardware.hardware_keystore=300 for a
        // KeyMint that runs in software and signs under AOSP's software root.
        val emulator = DeviceFacts(
            false, false, emptyList(), vpnActive = false,
            integrity = Integrity(0, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608, trust = AttestationTrust.SOFTWARE_ROOT),
            hardwareKeystore = true, emulator = true,
        )
        assertEquals(listOf(FindingKind.INTEGRITY_EMULATOR), Rules.forDevice(emulator, nowYearMonth = 202_610))
        // The same answer on a phone that does not call itself an emulator is as loud as what it could hide.
        assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_ANSWER), Rules.forDevice(emulator.copy(emulator = false), nowYearMonth = 202_610))
        // Calling itself an emulator changes nothing of what hardware-backed attestation says.
        val unlocked = Integrity(1, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608, trust = AttestationTrust.GOOGLE_ROOT)
        assertEquals(listOf(FindingKind.BOOTLOADER_UNLOCKED), Rules.forDevice(emulator.copy(integrity = unlocked), nowYearMonth = 202_610))
        assertEquals(
            listOf(FindingKind.ATTESTATION_PUBLIC_ROOT),
            Rules.forDevice(emulator.copy(integrity = unlocked.copy(trust = AttestationTrust.SOFTWARE_ROOT)), nowYearMonth = 202_610),
        )
    }

    @Test
    fun `a software answer is judged by its chain where the phone declares no secure hardware`() {
        val software = Integrity(0, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_608, trust = AttestationTrust.SOFTWARE_ROOT)
        assertEquals(listOf(FindingKind.INTEGRITY_SOFTWARE_ONLY), Rules.forDevice(device(integrity = software), nowYearMonth = 202_610))
        for ((trust, finding) in listOf(
            AttestationTrust.BROKEN_CHAIN to FindingKind.ATTESTATION_BROKEN,
            AttestationTrust.OTHER_ROOT to FindingKind.ATTESTATION_UNCONFIRMED,
            AttestationTrust.REVOKED to FindingKind.ATTESTATION_REVOKED,
        )) {
            assertEquals(listOf(finding), Rules.forDevice(device(integrity = software.copy(trust = trust)), nowYearMonth = 202_610))
        }
    }

    @Test
    fun `each finding of the hardware check is as severe as what it could hide`() {
        // What could hide an unlocked bootloader or a system not verified is high, as they are; what cannot be
        // confirmed, or failed, is medium, as is every other answer a system with root can give, an emulator's
        // claim included; only a software answer on Android 10 or 11 where the phone declares no secure hardware,
        // as phones launched before Android 8 give, is low.
        val expected = mapOf(
            FindingKind.BOOTLOADER_UNLOCKED to Severity.HIGH,
            FindingKind.BOOT_NOT_VERIFIED to Severity.HIGH,
            FindingKind.ATTESTATION_REVOKED to Severity.HIGH,
            FindingKind.ATTESTATION_FORGED to Severity.HIGH,
            FindingKind.ATTESTATION_SOFTWARE_ANSWER to Severity.HIGH,
            FindingKind.ATTESTATION_PUBLIC_ROOT to Severity.HIGH,
            FindingKind.ATTESTATION_TEST_ROOT to Severity.HIGH,
            FindingKind.ATTESTATION_UNCONFIRMED to Severity.MEDIUM,
            FindingKind.ATTESTATION_INCOMPLETE to Severity.MEDIUM,
            FindingKind.ATTESTATION_OUT_OF_DATE to Severity.MEDIUM,
            FindingKind.ATTESTATION_BROKEN to Severity.MEDIUM,
            FindingKind.ATTESTATION_KEYS_UNAVAILABLE to Severity.MEDIUM,
            FindingKind.ATTESTATION_UPDATE_REQUIRED to Severity.MEDIUM,
            FindingKind.ATTESTATION_KEYS_REFUSED to Severity.MEDIUM,
            FindingKind.ATTESTATION_SOFTWARE_UNDECLARED to Severity.MEDIUM,
            FindingKind.ATTESTATION_FAILED to Severity.MEDIUM,
            FindingKind.SYSTEM_OWN_KEY to Severity.MEDIUM,
            FindingKind.OLD_SECURITY_PATCH to Severity.MEDIUM,
            FindingKind.INTEGRITY_EMULATOR to Severity.MEDIUM,
            FindingKind.INTEGRITY_SOFTWARE_ONLY to Severity.LOW,
        )
        assertEquals(expected, expected.keys.associateWith { it.severity })
        // A new kind of the check is given a severity here too.
        val ofTheCheck = FindingKind.entries.filter { it.name.startsWith("ATTESTATION_") || it.name.startsWith("INTEGRITY_") }
        assertTrue(expected.keys.containsAll(ofTheCheck))
    }

    @Test
    fun `the emulator's claim stands only for the answer Android's emulator gives`() {
        // Android's emulator signs under AOSP's software root, whether or not its image declares a hardware
        // keystore (the Android 11 image does not; Android 15's does). Any other software chain on a device that
        // calls itself one is judged as on any other device.
        val software = Integrity(0, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_608, trust = AttestationTrust.SOFTWARE_ROOT)
        val emulator = DeviceFacts(false, false, emptyList(), vpnActive = false, integrity = software, emulator = true)
        assertEquals(listOf(FindingKind.INTEGRITY_EMULATOR), Rules.forDevice(emulator, nowYearMonth = 202_610))
        assertEquals(listOf(FindingKind.INTEGRITY_EMULATOR), Rules.forDevice(emulator.copy(hardwareKeystore = true, sdk = 35), nowYearMonth = 202_610))
        for ((trust, finding) in listOf(
            AttestationTrust.REVOKED to FindingKind.ATTESTATION_REVOKED,
            AttestationTrust.BROKEN_CHAIN to FindingKind.ATTESTATION_BROKEN,
            AttestationTrust.OTHER_ROOT to FindingKind.ATTESTATION_UNCONFIRMED,
        )) {
            val claimed = emulator.copy(integrity = software.copy(trust = trust))
            assertEquals("$trust", listOf(finding), Rules.forDevice(claimed, nowYearMonth = 202_610))
            assertEquals(
                "$trust",
                listOf(FindingKind.ATTESTATION_SOFTWARE_ANSWER),
                Rules.forDevice(claimed.copy(hardwareKeystore = true), nowYearMonth = 202_610),
            )
        }
        // The claim leaves a check that failed, or waits, as it is.
        for ((failure, finding) in listOf(
            IntegrityFailure.FAILED to FindingKind.ATTESTATION_FAILED,
            IntegrityFailure.KEYS_UNAVAILABLE to FindingKind.ATTESTATION_KEYS_UNAVAILABLE,
            IntegrityFailure.UPDATE_REQUIRED to FindingKind.ATTESTATION_UPDATE_REQUIRED,
            IntegrityFailure.KEYS_REFUSED to FindingKind.ATTESTATION_KEYS_REFUSED,
        )) {
            val failed = emulator.copy(integrity = null, integrityFailure = failure, hardwareKeystore = true)
            assertEquals("$failure", listOf(finding), Rules.forDevice(failed, nowYearMonth = 202_610))
        }
    }

    @Test
    fun `the emulator's claim stands under Google's test root as under AOSP's`() {
        // Android 15's emulator (dp-api35-ci) attests in software under Google's test root for unregistered
        // devices, with keys from Google's provisioning service; Android 11's under AOSP's software root.
        val test = Integrity(0, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 202_609, trust = AttestationTrust.TEST_ROOT)
        val emulator = DeviceFacts(
            false, false, emptyList(), vpnActive = false, integrity = test, hardwareKeystore = true, emulator = true, sdk = 35,
        )
        assertEquals(listOf(FindingKind.INTEGRITY_EMULATOR), Rules.forDevice(emulator, nowYearMonth = 202_611))
        // Without the claim: a phone that declares secure hardware is answered by software; Android 12 or later
        // without the declaration is the medium finding that names Android on a computer and uncertified phones.
        assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_ANSWER), Rules.forDevice(emulator.copy(emulator = false), nowYearMonth = 202_611))
        val undeclared = emulator.copy(emulator = false, hardwareKeystore = false)
        assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_UNDECLARED), Rules.forDevice(undeclared, nowYearMonth = 202_611))
        // Before Android 12 there was no key provisioning: only a system that fakes it answers so.
        assertEquals(listOf(FindingKind.ATTESTATION_TEST_ROOT), Rules.forDevice(undeclared.copy(sdk = 30), nowYearMonth = 202_611))
        assertEquals(Severity.HIGH, FindingKind.ATTESTATION_TEST_ROOT.severity)
        // A claim of secure hardware under it: an unregistered device on a test build, or a forgery; anyone can
        // obtain keys under it, so, as under AOSP's published root, nothing it says is used.
        val hardware = test.copy(securityLevel = 1, deviceLocked = false, osPatchLevel = 201_001)
        for (device in listOf(undeclared, emulator)) {
            assertEquals(listOf(FindingKind.ATTESTATION_TEST_ROOT), Rules.forDevice(device.copy(integrity = hardware), nowYearMonth = 202_611))
        }
    }

    @Test
    fun `Android 12 or later is a second declaration of secure hardware`() {
        // Every phone that meets Android's requirements and runs Android 12 or later has secure hardware for its
        // keys, so a software answer there, without the feature declared, is medium: Android on a computer, a phone
        // that does not meet the requirements, or a system that hid the declaration.
        val software = Integrity(0, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_608, trust = AttestationTrust.SOFTWARE_ROOT)
        val android12 = DeviceFacts(false, false, emptyList(), vpnActive = false, integrity = software, sdk = 31)
        assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_UNDECLARED), Rules.forDevice(android12, nowYearMonth = 202_610))
        assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_UNDECLARED), Rules.forDevice(android12.copy(sdk = 37), nowYearMonth = 202_610))
        // Android 10 and 11 run on phones that launched before attestation was required.
        assertEquals(listOf(FindingKind.INTEGRITY_SOFTWARE_ONLY), Rules.forDevice(android12.copy(sdk = 30), nowYearMonth = 202_610))
        // The declared feature, a chain's own verdict and the emulator's answer are judged as before.
        assertEquals(listOf(FindingKind.ATTESTATION_SOFTWARE_ANSWER), Rules.forDevice(android12.copy(hardwareKeystore = true), nowYearMonth = 202_610))
        assertEquals(
            listOf(FindingKind.ATTESTATION_REVOKED),
            Rules.forDevice(android12.copy(integrity = software.copy(trust = AttestationTrust.REVOKED)), nowYearMonth = 202_610),
        )
        assertEquals(listOf(FindingKind.INTEGRITY_EMULATOR), Rules.forDevice(android12.copy(emulator = true), nowYearMonth = 202_610))
        // A hardware attestation is judged by its chain, whatever the version.
        val hardware = software.copy(securityLevel = 1, trust = AttestationTrust.GOOGLE_ROOT)
        assertEquals(emptyList<FindingKind>(), Rules.forDevice(android12.copy(integrity = hardware), nowYearMonth = 202_610))
    }

    @Test
    fun `a system update required, and keys refused, are told apart from a failed check`() {
        val update = DeviceFacts(false, false, emptyList(), vpnActive = false, integrity = null, integrityFailure = IntegrityFailure.UPDATE_REQUIRED)
        assertEquals(listOf(FindingKind.ATTESTATION_UPDATE_REQUIRED), Rules.forDevice(update, nowYearMonth = 202_610))
        val refused = update.copy(integrityFailure = IntegrityFailure.KEYS_REFUSED)
        assertEquals(listOf(FindingKind.ATTESTATION_KEYS_REFUSED), Rules.forDevice(refused, nowYearMonth = 202_610))
    }

    @Test
    fun `a phone waiting for keys from Google is told apart from a failed check`() {
        val waiting = DeviceFacts(false, false, emptyList(), vpnActive = false, integrity = null, integrityFailure = IntegrityFailure.KEYS_UNAVAILABLE)
        assertEquals(listOf(FindingKind.ATTESTATION_KEYS_UNAVAILABLE), Rules.forDevice(waiting, nowYearMonth = 202_610))
        assertEquals(Severity.MEDIUM, FindingKind.ATTESTATION_KEYS_UNAVAILABLE.severity)
    }

    @Test
    fun `a failed check is a finding, and no check made is none`() {
        val failed = DeviceFacts(false, false, emptyList(), vpnActive = false, integrity = null, integrityFailure = IntegrityFailure.FAILED)
        assertEquals(listOf(FindingKind.ATTESTATION_FAILED), Rules.forDevice(failed, nowYearMonth = 202_610))
        assertEquals(emptyList<FindingKind>(), Rules.forDevice(failed.copy(integrityFailure = null), nowYearMonth = 202_610))
    }

    @Test
    fun `a system locked with its owner's key is a medium fact`() {
        val ownKey = Integrity(1, deviceLocked = true, verifiedBoot = 1, osPatchLevel = 202_608, trust = AttestationTrust.GOOGLE_ROOT)
        assertEquals(listOf(FindingKind.SYSTEM_OWN_KEY), Rules.forDevice(device(integrity = ownKey), nowYearMonth = 202_610))
        // A software attestation's word on it is not taken.
        assertEquals(listOf(FindingKind.INTEGRITY_SOFTWARE_ONLY), Rules.forDevice(device(integrity = ownKey.copy(securityLevel = 0)), nowYearMonth = 202_610))
    }

    @Test
    fun `a vendor patch level is shown, not judged`() {
        // A Pixel 3 in Google's test data, patched in August 2019, still stated its vendor level as September
        // 2018: a phone can patch its vendor image and leave the level behind.
        val integrity = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_608, trust = AttestationTrust.GOOGLE_ROOT)
        assertEquals(emptyList<FindingKind>(), Rules.forDevice(device(integrity = integrity.copy(vendorPatchLevel = 202_001)), nowYearMonth = 202_610))
    }

    @Test
    fun `a forged attestation is reported alone, whatever it says`() {
        // Not its unlocked bootloader, not its old patch: nothing a forged attestation says is used.
        val integrity = Integrity(2, deviceLocked = false, verifiedBoot = 2, osPatchLevel = 201_001, trust = AttestationTrust.FORGED, vendorPatchLevel = 201_001)
        assertEquals(listOf(FindingKind.ATTESTATION_FORGED), Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
        assertEquals(listOf(FindingKind.ATTESTATION_FORGED), Rules.forDevice(device(integrity = Integrity.forged()), nowYearMonth = 202_610))
    }

    @Test
    fun `a hardware attestation out of date cannot be confirmed`() {
        val integrity = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_608, trust = AttestationTrust.OUT_OF_DATE)
        assertEquals(listOf(FindingKind.ATTESTATION_OUT_OF_DATE), Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
    }

    @Test
    fun `hardware attestation without the bootloader state is incomplete`() {
        // The engine reads these only from the hardware-enforced list, so null means the hardware left them out.
        val integrity = Integrity(1, deviceLocked = null, verifiedBoot = null, osPatchLevel = null, trust = AttestationTrust.GOOGLE_ROOT)
        assertEquals(listOf(FindingKind.ATTESTATION_INCOMPLETE), Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
        val unconfirmed = integrity.copy(securityLevel = 2, trust = AttestationTrust.OTHER_ROOT)
        assertEquals(
            listOf(FindingKind.ATTESTATION_UNCONFIRMED, FindingKind.ATTESTATION_INCOMPLETE),
            Rules.forDevice(device(integrity = unconfirmed), nowYearMonth = 202_610),
        )
    }

    @Test
    fun `software attestation without the bootloader state is reported only as software`() {
        val integrity = Integrity(0, deviceLocked = null, verifiedBoot = null, osPatchLevel = null, trust = AttestationTrust.SOFTWARE_ROOT)
        assertEquals(listOf(FindingKind.INTEGRITY_SOFTWARE_ONLY), Rules.forDevice(device(integrity = integrity), nowYearMonth = 202_610))
    }

    @Test
    fun `embedded trackers are a finding, referenced ones are not`() {
        val app = app()
        assertTrue(FindingKind.TRACKERS !in Rules.forApp(app))
        assertTrue(FindingKind.TRACKERS !in Rules.forApp(app, AppTrackers(emptyList(), listOf(52))))
        assertTrue(FindingKind.TRACKERS in Rules.forApp(app, AppTrackers(listOf(447), emptyList())))
        assertTrue(FindingKind.TRACKERS !in Rules.forApp(app, AppTrackers(emptyList(), emptyList(), unreadable = true)))
    }
}
