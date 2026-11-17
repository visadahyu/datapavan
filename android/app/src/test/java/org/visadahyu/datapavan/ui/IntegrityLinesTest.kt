package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AttestationTrust
import org.visadahyu.datapavan.audit.DeviceFacts
import org.visadahyu.datapavan.audit.Integrity

class IntegrityLinesTest {
    private fun device(integrity: Integrity?, failed: Boolean = false) =
        DeviceFacts(false, false, emptyList(), vpnActive = false, integrity = integrity, integrityFailed = failed)

    private val locked = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_607, trust = AttestationTrust.GOOGLE_ROOT)

    @Test
    fun `a sound phone shows the check and the patch`() {
        assertEquals(listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07"), integrityLines(device(locked)))
    }

    @Test
    fun `a software attestation's patch level is the system's own word`() {
        val software = locked.copy(securityLevel = 0)
        assertEquals(listOf(R.string.device_patch_system to "2026-07"), integrityLines(device(software)))
    }

    @Test
    fun `a failed check has a line of its own`() {
        assertEquals(listOf(R.string.device_integrity_failed to null), integrityLines(device(null, failed = true)))
        assertEquals(listOf(R.string.device_integrity_unavailable to null), integrityLines(device(null)))
    }

    @Test
    fun `nothing a forged attestation says is shown`() {
        assertEquals(emptyList<Pair<Int, String?>>(), integrityLines(device(locked.copy(trust = AttestationTrust.FORGED, vendorPatchLevel = 202_001))))
    }

    @Test
    fun `a lagging vendor patch and an owner's boot key are shown`() {
        val own = locked.copy(verifiedBoot = 1, verifiedBootKey = "ab12", vendorPatchLevel = 202_605)
        assertEquals(
            listOf(R.string.device_patch to "2026-07", R.string.device_vendor_patch to "2026-05", R.string.device_boot_key to "ab12"),
            integrityLines(device(own)),
        )
        // A vendor patch as recent as the system's is not repeated, and the maker's key is not shown.
        assertEquals(
            listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07"),
            integrityLines(device(locked.copy(verifiedBootKey = "cd34", vendorPatchLevel = 202_607))),
        )
    }
}
