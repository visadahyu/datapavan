package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SystemKeysTest {
    private val leaked = "3".repeat(64)
    private val test = "c".repeat(64)
    private val maker = "a".repeat(64)
    private val other = "b".repeat(64)
    private val keys = SystemKeys.parse(
        """
        # comment
        $test	aosp-test	platform	subject	url	digest	2026-10-31
        $leaked	leaked	apvi-3		url		2026-10-31
        ${"d".repeat(64)}	unknown-kind	x
        not-a-hash	leaked	x
        """.trimIndent(),
    )

    private fun app(
        packageName: String = "com.example",
        signers: List<String> = listOf(other),
        isSystem: Boolean = false,
        updated: Boolean = false,
        installer: String? = null,
        uid: Int = 10_100,
    ) = AppFacts(
        packageName = packageName,
        label = packageName,
        isSystem = isSystem,
        enabled = true,
        updatedSystemApp = updated,
        installer = installer,
        firstInstall = 0,
        lastUpdate = 0,
        grantedDangerous = emptyList(),
        sensors = emptySet(),
        special = emptySet(),
        isVpnApp = false,
        vpnAuthorised = false,
        signing = AppSigning(signers, emptyList(), debug = false),
        uid = uid,
    )

    private val platform = AppSigning(listOf(maker), emptyList(), debug = false)

    @Test
    fun readsKnownKindsOnly() {
        assertEquals(KeyKind.AOSP_TEST, keys.kind(test))
        assertEquals(KeyKind.LEAKED, keys.kind(leaked))
        assertNull(keys.kind("d".repeat(64)))
        assertEquals(KeyKind.LEAKED, keys.untrusted(AppSigning(listOf(other), listOf(leaked, other), debug = false)))
    }

    @Test
    fun describesSignerOriginAndSystemUser() {
        val system = keys.facts(app(signers = listOf(maker), isSystem = true, uid = SystemKeys.SYSTEM_UID), platform, "samsung")
        assertTrue(system.systemKey)
        assertTrue(system.runsAsSystem)
        assertEquals(Origin.SYSTEM_IMAGE, system.origin)
        assertEquals(Origin.UPDATED_SYSTEM_APP, keys.facts(app(isSystem = true, updated = true), platform, "samsung").origin)
        val later = keys.facts(app(installer = "com.sec.android.app.samsungapps"), platform, "Samsung")
        assertFalse(later.systemKey)
        assertEquals(Origin.INSTALLED_LATER, later.origin)
        assertTrue(later.fromTrustedStore)
        // Another maker's store is not trusted on a Samsung phone.
        assertFalse(keys.facts(app(installer = "com.xiaomi.market"), platform, "samsung").fromTrustedStore)
    }

    @Test
    fun warnsOnlyAboutUntrustedKeysFromOutsideTheSystemAndTheStores() {
        fun findings(app: AppFacts, manufacturer: String = "samsung") =
            Rules.forApp(app, keys = keys.facts(app, platform, manufacturer))
        // Shipped in the system image: what the phone came with.
        assertFalse(FindingKind.UNTRUSTED_SYSTEM_KEY in findings(app(signers = listOf(leaked), isSystem = true)))
        // Installed from a file, or updated from elsewhere: high.
        assertTrue(FindingKind.UNTRUSTED_SYSTEM_KEY in findings(app(signers = listOf(test), installer = "com.google.android.packageinstaller")))
        assertTrue(FindingKind.UNTRUSTED_SYSTEM_KEY in findings(app(signers = listOf(leaked), isSystem = true, updated = true)))
        // From the maker's store or Google Play: a leaked key is only a note.
        val store = findings(app(signers = listOf(leaked), installer = "com.sec.android.app.samsungapps"))
        assertEquals(listOf(FindingKind.LEAKED_KEY_FROM_STORE), store)
        assertEquals(emptyList<FindingKind>(), findings(app(installer = "com.android.vending")))
    }

    @Test
    fun takesAppsThePhonesSetupInstalledWithItsOwnKeyAsTheMakers() {
        // On the A40, Samsung's setup installed apps with no installer, signed with its leaked system key.
        val leakedPlatform = AppSigning(listOf(leaked), emptyList(), debug = false)
        fun findings(app: AppFacts) = Rules.forApp(app, keys = keys.facts(app, leakedPlatform, "samsung"))
        val setup = app(signers = listOf(leaked), installer = null)
        assertTrue(keys.facts(setup, leakedPlatform, "samsung").fromSetup)
        assertTrue(FindingKind.LEAKED_KEY_FROM_STORE in findings(setup))
        assertFalse(FindingKind.UNTRUSTED_SYSTEM_KEY in findings(setup))
        // The same key from a file still is high; so is another public key with no installer.
        assertTrue(FindingKind.UNTRUSTED_SYSTEM_KEY in findings(app(signers = listOf(leaked), installer = "com.google.android.packageinstaller")))
        assertTrue(FindingKind.UNTRUSTED_SYSTEM_KEY in findings(app(signers = listOf(test), installer = null)))
    }

    @Test
    fun namesThePhonesOwnKeyAsAPhoneWideFinding() {
        val device = DeviceFacts(usbDebugging = false, wirelessDebugging = false, userCertificateAuthorities = emptyList(), vpnActive = false, integrity = null)
        assertEquals(listOf(FindingKind.SYSTEM_KEY_PUBLIC), Rules.forDevice(device, 202_610, KeyKind.AOSP_TEST))
        assertEquals(listOf(FindingKind.SYSTEM_KEY_LEAKED), Rules.forDevice(device, 202_610, KeyKind.LEAKED))
        assertEquals(listOf(FindingKind.SYSTEM_KEY_DEVELOPMENT), Rules.forDevice(device, 202_610, KeyKind.GOOGLE_DEV))
        assertEquals(emptyList<FindingKind>(), Rules.forDevice(device, 202_610, null))
    }

    @Test
    fun readsTheShippedData() {
        val shipped = SystemKeys.parse(File("../../data/system-keys/keys.tsv").readText())
        // The A40's platform key, on Google's 2022 list; the emulator's, Google's development key; AOSP's.
        assertEquals(KeyKind.LEAKED, shipped.kind("34df0e7a9f1cf1892e45c056b4973cd81ccf148a4050d11aea4ac5a65f900a42"))
        assertEquals(KeyKind.GOOGLE_DEV, shipped.kind("301aa3cb081134501c45f1422abc66c24224fd5ded5fdc8f17e697176fd866aa"))
        assertEquals(KeyKind.AOSP_TEST, shipped.kind("c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8"))
    }
}
