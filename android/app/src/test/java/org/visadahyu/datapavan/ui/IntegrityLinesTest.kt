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

    private val locked = Integrity(
        1, deviceLocked = true, verifiedBoot = 0, osPatchLevel = 202_607, trust = AttestationTrust.GOOGLE_ROOT,
        revocationListDate = LocalDate.of(2026, 10, 29),
    )
    private val dated = R.string.device_revocation_list to "2026-10-29"

    @Test
    fun `a sound phone shows the check and the patch`() {
        assertEquals(listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07", dated), lines(locked))
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
    fun `a list of unknown date is called so, as an old one would be`() {
        // A pack whose SOURCE gives no date for the list: its age cannot be told, so it cannot be called fresh.
        assertEquals(
            listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07", R.string.device_revocation_list_undated to null),
            lines(locked.copy(revocationListDate = null)),
        )
        // Not for values nothing confirmed.
        assertEquals(listOf(R.string.device_patch_system to "2026-07"), lines(locked.copy(trust = AttestationTrust.OTHER_ROOT)))
    }

    @Test
    fun `a clock set back does not make the list younger than the confirmed patch level allows`() {
        // A phone whose system Google's key confirms as patched in July 2026 cannot be running long before July
        // 2026, whatever its clock says: makers ship a month's patch up to a few weeks early, so the list's age is
        // counted from 1 June at the least.
        val list = LocalDate.of(2026, 2, 1)
        val setBack = integrityLines(device(locked.copy(revocationListDate = list)), LocalDate.of(2026, 3, 1))
        assertEquals(R.string.device_revocation_list_old to "2026-02-01", setBack.last())
        // 90 days before the first day of the month before the patch month is still fresh; 91 is old.
        val june = LocalDate.of(2026, 6, 1)
        assertEquals(R.string.device_revocation_list, integrityLines(device(locked.copy(revocationListDate = june.minusDays(90))), list).last().first)
        assertEquals(R.string.device_revocation_list_old, integrityLines(device(locked.copy(revocationListDate = june.minusDays(91))), list).last().first)
        // The fifth review's probe: on 2026-11-27, with the clock right, a phone given December's patch early and
        // a list 88 days old: fresh.
        val early = locked.copy(osPatchLevel = 202_612, revocationListDate = LocalDate.of(2026, 11, 27).minusDays(88))
        assertEquals(R.string.device_revocation_list, integrityLines(device(early), LocalDate.of(2026, 11, 27)).last().first)
        // Without a confirmed patch level, the phone's date is all there is.
        val noPatch = locked.copy(osPatchLevel = null, revocationListDate = list)
        assertEquals(R.string.device_revocation_list, integrityLines(device(noPatch), LocalDate.of(2026, 3, 1)).last().first)
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
        assertEquals(listOf(R.string.device_integrity_update to null), lines(null, IntegrityFailure.UPDATE_REQUIRED))
        assertEquals(listOf(R.string.device_integrity_refused to null), lines(null, IntegrityFailure.KEYS_REFUSED))
        // No check made, which the app never shows: nothing to say.
        assertEquals(emptyList<Pair<Int, String?>>(), lines(null))
    }

    @Test
    fun `nothing a forged attestation, or a hardware claim anyone could make, says is shown`() {
        assertEquals(emptyList<Pair<Int, String?>>(), lines(locked.copy(trust = AttestationTrust.FORGED, vendorPatchLevel = 202_001)))
        assertEquals(emptyList<Pair<Int, String?>>(), lines(locked.copy(trust = AttestationTrust.SOFTWARE_ROOT)))
        assertEquals(emptyList<Pair<Int, String?>>(), lines(locked.copy(trust = AttestationTrust.TEST_ROOT)))
        // In software under Google's test root, as on Android 15's emulator: the patch level is the system's word.
        assertEquals(listOf(R.string.device_patch_system to "2026-07"), lines(locked.copy(securityLevel = 0, trust = AttestationTrust.TEST_ROOT)))
    }

    @Test
    fun `a lagging vendor patch and an owner's boot key are shown where the hardware states them`() {
        val own = locked.copy(verifiedBoot = 1, verifiedBootKey = "ab12", vendorPatchLevel = 202_605)
        assertEquals(
            listOf(R.string.device_patch to "2026-07", R.string.device_vendor_patch to "2026-05", R.string.device_boot_key to "ab12", dated),
            lines(own),
        )
        // A vendor patch as recent as the system's is not repeated, and the maker's key is not shown.
        assertEquals(
            listOf(R.string.device_integrity_ok to null, R.string.device_patch to "2026-07", dated),
            lines(locked.copy(verifiedBootKey = "cd34", vendorPatchLevel = 202_607)),
        )
    }
}
