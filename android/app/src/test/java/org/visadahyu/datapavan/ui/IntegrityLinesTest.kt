package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.audit.AttestationTrust
import org.visadahyu.datapavan.audit.DeviceFacts
import org.visadahyu.datapavan.audit.Integrity
import org.visadahyu.datapavan.audit.IntegrityFailure
import java.time.LocalDate

class IntegrityLinesTest {
    private fun device(integrity: Integrity?, failure: IntegrityFailure? = null) = DeviceFacts(
        false, false, emptyList(), vpnActive = false, integrity = integrity, integrityFailure = failure,
    )

    private val today = LocalDate.of(2026, 11, 17)
    private fun lines(integrity: Integrity?, failure: IntegrityFailure? = null) = integrityLines(device(integrity, failure), today)

    private val locked = Integrity(1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_607, trust = AttestationTrust.GOOGLE_ROOT)

    @Test
    fun `a sound phone shows the check and the patch`() {
        assertEquals(listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07"), lines(locked))
    }

    @Test
    fun `the check says how old its revocation list is`() {
        // Under every value it confirms, after them.
        val fresh = locked.copy(revocationListDate = LocalDate.of(2026, 10, 29))
        assertEquals(
            listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07", R.string.device_revocation_list to "2026-10-29"),
            lines(fresh),
        )
        // Ninety days is the last day the list is not called old.
        assertEquals(R.string.device_revocation_list, lines(locked.copy(revocationListDate = today.minusDays(90))).last().first)
        val old = locked.copy(revocationListDate = today.minusDays(91))
        assertEquals(R.string.device_revocation_list_old to today.minusDays(91).toString(), lines(old).last())
    }

    @Test
    fun `values confirmed on a phone that is not locked and verified carry the list's date too`() {
        // A system locked with its owner's key, such as GrapheneOS: its boot key is confirmed, so the date of the
        // revocation list it was confirmed against is shown with it.
        val own = locked.copy(verifiedBoot = 1, verifiedBootKey = "ab12", revocationListDate = LocalDate.of(2026, 10, 29))
        assertEquals(
            listOf(R.string.device_patch to "2026-07", R.string.device_boot_key to "ab12", R.string.device_revocation_list to "2026-10-29"),
            lines(own),
        )
        // An unlocked phone's patch level, confirmed by Google's key.
        val unlocked = locked.copy(deviceLocked = false, verifiedBoot = 2, revocationListDate = LocalDate.of(2026, 10, 29))
        assertEquals(listOf(R.string.device_patch to "2026-07", R.string.device_revocation_list to "2026-10-29"), lines(unlocked))
        // Nothing confirmed, nothing to date; and nothing unconfirmed is dated.
        assertEquals(emptyList<Pair<Int, String?>>(), lines(unlocked.copy(osPatchLevel = null)))
        assertEquals(listOf(R.string.device_patch_system to "2026-07"), lines(own.copy(trust = AttestationTrust.OTHER_ROOT)))
    }

    @Test
    fun `a software attestation's patch level is the system's own word`() {
        val software = locked.copy(securityLevel = 0, trust = AttestationTrust.SOFTWARE_ROOT)
        assertEquals(listOf(R.string.device_patch_system to "2026-07"), lines(software))
    }

    @Test
    fun `an unconfirmed attestation's values are the system's word too`() {
        // The third review's probes: a patch level, a lagging vendor level and an owner's boot key under another
        // root, a broken chain, a revoked key or out-of-date certificates, or from software.
        val claims = locked.copy(verifiedBoot = 1, verifiedBootKey = "ab12", vendorPatchLevel = 202_501)
        for (trust in listOf(AttestationTrust.OTHER_ROOT, AttestationTrust.BROKEN_CHAIN, AttestationTrust.REVOKED, AttestationTrust.OUT_OF_DATE)) {
            assertEquals("$trust", listOf(R.string.device_patch_system to "2026-07"), lines(claims.copy(trust = trust)))
        }
        assertEquals(listOf(R.string.device_patch_system to "2026-07"), lines(claims.copy(securityLevel = 0, trust = AttestationTrust.SOFTWARE_ROOT)))
    }

    @Test
    fun `a failed check, and one waiting for Google, have lines of their own`() {
        assertEquals(listOf(R.string.device_integrity_failed to null), lines(null, IntegrityFailure.FAILED))
        assertEquals(listOf(R.string.device_integrity_waiting to null), lines(null, IntegrityFailure.KEYS_UNAVAILABLE))
        // No check made, which the app never shows: nothing to say.
        assertEquals(emptyList<Pair<Int, String?>>(), lines(null))
    }

    @Test
    fun `nothing a forged attestation, or a hardware claim anyone could make, says is shown`() {
        assertEquals(emptyList<Pair<Int, String?>>(), lines(locked.copy(trust = AttestationTrust.FORGED, vendorPatchLevel = 202_001)))
        assertEquals(emptyList<Pair<Int, String?>>(), lines(locked.copy(trust = AttestationTrust.SOFTWARE_ROOT)))
    }

    @Test
    fun `a lagging vendor patch and an owner's boot key are shown where the hardware states them`() {
        val own = locked.copy(verifiedBoot = 1, verifiedBootKey = "ab12", vendorPatchLevel = 202_605)
        assertEquals(
            listOf(R.string.device_patch to "2026-07", R.string.device_vendor_patch to "2026-05", R.string.device_boot_key to "ab12"),
            lines(own),
        )
        // A vendor patch as recent as the system's is not repeated, and the maker's key is not shown.
        assertEquals(
            listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07"),
            lines(locked.copy(verifiedBootKey = "cd34", vendorPatchLevel = 202_607)),
        )
    }
}
