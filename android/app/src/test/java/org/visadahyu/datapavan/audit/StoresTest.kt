package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Test

class StoresTest {
    @Test
    fun anAppFromAStoreNamesTheStoreNotItsPackage() {
        assertEquals(InstallSource.FromStore("Google Play"), InstallSource.of(false, "com.android.vending", "Google Play Store"))
        assertEquals(InstallSource.FromStore("Galaxy Store"), InstallSource.of(false, "com.sec.android.app.samsungapps", null))
        assertEquals(InstallSource.FromStore("F-Droid"), InstallSource.of(false, "org.fdroid.basic", null))
    }

    @Test
    fun anotherInstallerKeepsItsPackageNextToItsOwnLabel() {
        assertEquals(InstallSource.ByApp("Files", "com.google.android.documentsui"), InstallSource.of(false, "com.google.android.documentsui", "Files"))
        // A label is the app's own choice: one that names a store still comes with the real package.
        assertEquals(InstallSource.ByApp("Google Play", "com.example.fake"), InstallSource.of(false, "com.example.fake", "Google Play"))
        assertEquals(InstallSource.ByApp(null, "com.example.gone"), InstallSource.of(false, "com.example.gone", null))
        assertEquals(InstallSource.ByApp(null, "com.example.bare"), InstallSource.of(false, "com.example.bare", "com.example.bare"))
    }

    @Test
    fun noInstallerIsAnUnknownSourceForUserAppsAndTheFactoryForSystemApps() {
        assertEquals(InstallSource.Unknown, InstallSource.of(false, null, null))
        assertEquals(InstallSource.Preinstalled, InstallSource.of(true, null, null))
        assertEquals(InstallSource.PreinstalledWith("Google Play"), InstallSource.of(true, "com.android.vending", null))
        assertEquals(InstallSource.PreinstalledWith("com.example.setup"), InstallSource.of(true, "com.example.setup", "Setup"))
    }

    private fun app(installer: String?) = AppFacts(
        packageName = "org.example.app", label = "Example", isSystem = false, enabled = true, installer = installer,
        firstInstall = 0, lastUpdate = 0, grantedDangerous = emptyList(), sensors = emptySet(), special = emptySet(),
        isVpnApp = false, vpnAuthorised = false,
    )

    @Test
    fun theStoresThatNameAnAppAreTheStoresTheRulesTrust() {
        Stores.names.keys.forEach { assertEquals(it, false, FindingKind.UNKNOWN_SOURCE in Rules.forApp(app(it))) }
        assertEquals(true, FindingKind.UNKNOWN_SOURCE in Rules.forApp(app("com.example.files")))
        assertEquals(true, FindingKind.UNKNOWN_SOURCE in Rules.forApp(app(null)))
    }
}
