package org.visadahyu.datapavan.audit

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class JournalTest {
    private val day = UsageFacts.DAY
    private val camera = "android.permission.CAMERA"
    private val location = "android.permission.ACCESS_FINE_LOCATION"
    private val before = ItemState(permissions = setOf(camera, location), special = setOf(SpecialAccess.ACCESSIBILITY, SpecialAccess.OVERLAY), vpn = true)

    private fun entry(session: Long, at: Long, outcome: Outcome, after: ItemState = before, packageName: String? = "app", reason: PlanReason = PlanReason.NOT_OPENED_SENSITIVE) =
        JournalEntry(session, at, reason, packageName, listOf(Screen.APP_INFO), before, after, outcome)

    @Test
    fun recordsWhatTheUserRemoved() {
        val after = before.copy(permissions = setOf(location), special = setOf(SpecialAccess.OVERLAY), vpn = false)
        assertEquals(
            listOf(Change(ChangeKind.PERMISSION_REMOVED, camera), Change(ChangeKind.SPECIAL_REMOVED, "ACCESSIBILITY"), Change(ChangeKind.VPN_REMOVED)),
            Journal.changes(before, after),
        )
        assertEquals(listOf(Change(ChangeKind.DISABLED)), Journal.changes(before, before.copy(enabled = false)))
        // An uninstall says it all.
        assertEquals(listOf(Change(ChangeKind.UNINSTALLED)), Journal.changes(before, ItemState.UNINSTALLED))
        // Something the user granted is not a change of the plan.
        assertTrue(Journal.changes(before, before.copy(permissions = before.permissions + "android.permission.RECORD_AUDIO")).isEmpty())
        val phone = ItemState(usbDebugging = true, wirelessDebugging = true, authorities = 2)
        assertEquals(
            listOf(Change(ChangeKind.USB_DEBUGGING_OFF), Change(ChangeKind.WIRELESS_DEBUGGING_OFF), Change(ChangeKind.AUTHORITY_REMOVED)),
            Journal.changes(phone, ItemState(authorities = 1)),
        )
    }

    @Test
    fun saysWhenAChangeHasComeBack() {
        val after = before.copy(permissions = setOf(location), enabled = false)
        assertTrue(Journal.cameBack(Change(ChangeKind.PERMISSION_REMOVED, camera), after, before))
        assertFalse(Journal.cameBack(Change(ChangeKind.PERMISSION_REMOVED, camera), after, after))
        assertTrue(Journal.cameBack(Change(ChangeKind.DISABLED), after, before))
        assertFalse(Journal.cameBack(Change(ChangeKind.DISABLED), after, ItemState.UNINSTALLED))
        assertTrue(Journal.cameBack(Change(ChangeKind.UNINSTALLED), ItemState.UNINSTALLED, before))
        assertTrue(Journal.cameBack(Change(ChangeKind.AUTHORITY_REMOVED), ItemState(authorities = 0), ItemState(authorities = 1)))
        assertFalse(Journal.cameBack(Change(ChangeKind.AUTHORITY_REMOVED), ItemState(authorities = 1), ItemState(authorities = 1)))
    }

    @Test
    fun anItemStaysKeptUntilALaterEntrySaysOtherwise() {
        val kept = Journal().withEntry(entry(1, 10, Outcome.KEPT))
        assertEquals(mapOf(PlanItem.key(PlanReason.NOT_OPENED_SENSITIVE, "app") to before), kept.kept())
        assertTrue(kept.withEntry(entry(2, 20, Outcome.SKIPPED)).kept().isEmpty())
        // The same card again in the same session replaces its entry.
        val replaced = Journal().withEntry(entry(1, 10, Outcome.NOTHING_CHANGED)).withEntry(entry(1, 11, Outcome.KEPT))
        assertEquals(listOf(Outcome.KEPT), replaced.entries.map { it.outcome })
    }

    @Test
    fun asksOnceThreeDaysAfterASessionThatChangedSomething() {
        val start = 100 * day
        val journal = Journal()
            .withSession(JournalSession(start, PlanLevel.LIGHT))
            .withEntry(entry(start, start + 60_000, Outcome.CHANGED, after = before.copy(vpn = false)))
            .withSession(JournalSession(start + day, PlanLevel.MEDIUM))
            .withEntry(entry(start + day, start + day, Outcome.KEPT, packageName = "other"))
        assertNull(journal.healthCheckDue(start + 2 * day))
        assertEquals(start, journal.healthCheckDue(start + 60_000 + 3 * day)?.start)
        assertNull(journal.answered(start, HealthAnswer.WORKS).healthCheckDue(start + 10 * day))
    }

    @Test
    fun theFileKeepsEverythingAndSkipsWhatItDoesNotKnow() {
        val odd = "com.example/odd,name%\tx"
        val journal = Journal()
            .withSession(JournalSession(5, PlanLevel.STRICT, HealthAnswer.SOMETHING_WRONG))
            .withSession(JournalSession(6, PlanLevel.LIGHT))
            .withEntry(entry(5, 7, Outcome.CHANGED, after = ItemState.UNINSTALLED, packageName = odd))
            .withEntry(JournalEntry(6, 8, PlanReason.USB_DEBUGGING, null, listOf(Screen.DEVELOPER_OPTIONS), ItemState(usbDebugging = true), ItemState(), Outcome.CHANGED))
            .withEntry(entry(6, 9, Outcome.SKIPPED).copy(opened = emptyList(), before = before.copy(permissions = setOf("x,y/z"))))
        val text = JournalCodec.encode(journal)
        assertEquals(journal, JournalCodec.decode(text))
        val future = text + "entry\t6\t10\tSOMETHING_NEW\t-\t\tCHANGED\t11000/0//\t11000/0//\nnew-record\t1\n"
        assertEquals(journal, JournalCodec.decode(future))
        assertEquals(Journal(), JournalCodec.decode("datapavan-journal 99\n"))
        assertEquals(Journal(), JournalCodec.decode(""))
    }
}
