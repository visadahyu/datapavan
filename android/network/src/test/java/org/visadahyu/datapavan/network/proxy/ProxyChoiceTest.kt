package org.visadahyu.datapavan.network.proxy

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rule of the user's choice for one app (the proxy record's unit C, R3) as the screens read it, held to the engine's
 * own vectors (core/net/testdata/logged-apps.tsv), which the engine's `LoggedApps::covers` and `app_of` read too.
 */
class ProxyChoiceTest {
    private fun uids(column: String): List<Int> = if (column == "-") emptyList() else column.split(',').map(String::toInt)

    /** Every row of the engine's vectors, read as the engine reads them. */
    @Test
    fun theRuleMatchesTheEnginesVectors() {
        val rows = File("../../core/net/testdata/logged-apps.tsv").readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .map { it.split('\t') }
        assertTrue(rows.size.toString(), rows.size >= 13)
        for (row in rows) {
            assertEquals(row.toString(), 7, row.size)
            val covers = ProxyChoice.covers(
                uid = row[0].toInt(),
                logged = uids(row[1]),
                tools = uids(row[2]),
                pacHandler = uids(row[3]).firstOrNull(),
                setting = row[4] == "1",
                local = row[5] == "1",
            )
            assertEquals(row.toString(), row[6] == "1", covers)
        }
    }

    /**
     * An SDK Runtime UID follows its app, in each user's range; Android's own UIDs and those past the sandboxes' range
     * are never an app's; no app is no one's.
     */
    @Test
    fun anSdkRuntimeUidFollowsItsApp() {
        assertEquals(10_123, ProxyChoice.appOf(20_123))
        assertEquals(1_010_123, ProxyChoice.appOf(1_020_123))
        assertEquals(30_000, ProxyChoice.appOf(30_000))
        assertEquals(10_123, ProxyChoice.appOf(10_123))
        assertEquals(listOf(false, true, true, false, false), listOf(9_999, 10_000, 19_999, 20_000, 30_000).map(ProxyChoice::application))
        assertTrue(ProxyChoice.application(1_010_123))
        assertFalse(ProxyChoice.covers(null, listOf(10_123), emptyList(), null, setting = false, local = false))
    }

    /**
     * The link is offered where choosing the row's app would cover it, and only on this user's rows (audit-C 22): never on
     * Android's setting, a local proxy, a tool's row, the PAC handler's or Android's own; a record that never said
     * whether it was local (before log version 7) is not local for the link.
     */
    @Test
    fun theLinkIsOfferedWhereTheChoiceCouldCoverTheRow() {
        fun offered(uid: Int?, setting: Boolean = false, local: Boolean? = false, tools: List<Int> = emptyList(), pac: Int? = null, user: Int = 0) =
            ProxyChoice.offered(uid, tools, pac, setting, local, user)
        assertTrue(offered(10_123))
        assertTrue(offered(20_123))
        assertTrue(offered(10_123, local = null))
        assertFalse(offered(10_123, setting = true))
        assertFalse(offered(10_123, local = true))
        assertFalse(offered(10_123, tools = listOf(10_123)))
        assertFalse(offered(20_123, tools = listOf(10_123)))
        assertFalse(offered(10_123, pac = 10_123))
        assertFalse(offered(1_000))
        assertFalse(offered(null))
        // Another user's copy of an app (a dual app, the clone profile): not offered in this user, offered in its own.
        assertFalse(offered(1_010_123))
        assertTrue(offered(1_010_123, user = 10))
    }
}
