package org.visadahyu.datapavan.network.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.proxy.LoggedApps.Ended
import org.visadahyu.datapavan.network.proxy.LoggedApps.Entry

/**
 * The store of the user's choice for one app (the proxy record's unit C, C6 and C7): kept by package and first install
 * time, never by UID; handed by the UIDs the packages hold now, a shared UID only while every package of it was chosen,
 * never a tool's or the PAC handler's, and nothing before the tools were read; memory only under ADR 0047's profile,
 * which writes nothing when turned off; and the wipe.
 */
class LoggedAppsTest {
    /** The preferences, in memory. */
    private class Disk : LoggedApps.Store {
        var lines: Set<String> = emptySet()
        var memoryOnly = false
        var writes = 0
        var durable = 0
        override fun lines() = lines
        override fun memoryOnly() = memoryOnly
        override fun write(lines: Set<String>, memoryOnly: Boolean, durable: Boolean) {
            this.lines = lines
            this.memoryOnly = memoryOnly
            writes++
            if (durable) this.durable++
        }
    }

    /** Android's package manager, as a table: each package's UID and first install time. */
    private class Phone : LoggedApps.Packages {
        val installed = HashMap<String, Pair<Int, Long>>()
        override fun uidOf(packageName: String) = installed[packageName]?.first
        override fun firstInstallOf(packageName: String) = installed[packageName]?.second
        override fun packagesOf(uid: Int) = installed.filterValues { it.first == uid }.keys.toList()
    }

    private val disk = Disk()
    private val session = LoggedApps.Session()
    private var asked = 0
    private val store = LoggedApps(disk, session) { asked++ }
    private val phone = Phone().apply {
        installed["com.example.messenger"] = 10_123 to 1_000L
        installed["com.example.other"] = 10_124 to 2_000L
    }

    private fun handed(tools: Set<Int> = emptySet(), pac: Int? = null, toolsRead: Boolean = true) =
        LoggedApps.handed(store.entries(), phone, tools, pac, toolsRead, store.ended())

    /** Hands as the service does: the UIDs, with what was stale forgotten. */
    private fun hand(tools: Set<Int> = emptySet(), pac: Int? = null, toolsRead: Boolean = true): List<Int> =
        handed(tools, pac, toolsRead).also(store::drop).uids

    /** One app chosen and its choice ended: by package and first install time, no UID on disk; each asks for a hand-over. */
    @Test
    fun anAppIsChosenAndStopped() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        assertEquals(setOf(Entry("com.example.messenger", 1_000)), store.entries())
        assertEquals(setOf("app\tcom.example.messenger\t1000"), disk.lines)
        assertTrue(disk.lines.none { "10123" in it })
        assertEquals(listOf(10_123), hand())
        store.stop(listOf("com.example.messenger"))
        assertEquals(emptyList<Int>(), hand())
        assertEquals(2, asked)
        // Nothing to choose asks nothing.
        store.choose(emptyList())
        assertEquals(2, asked)
    }

    /**
     * A shared UID is chosen with every package of it (the sheet names them), and handed only while every package that
     * holds it now was chosen (K2): one of them alone is not.
     */
    @Test
    fun aSharedUidIsChosenWithEveryPackageOfIt() {
        phone.installed["com.example.companion"] = 10_123 to 1_500L
        assertEquals(
            listOf(Entry("com.example.companion", 1_500), Entry("com.example.messenger", 1_000)),
            LoggedApps.entriesOfUid(phone, 10_123),
        )
        store.choose(listOf(Entry("com.example.messenger", 1_000)))
        assertEquals(emptySet<Int>(), store.chosen(phone, emptySet(), null))
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        assertEquals(setOf(10_123), store.chosen(phone, emptySet(), null))
        assertEquals(listOf(10_123), hand())
    }

    /**
     * A package that joins the UID later ends the choice for it, the safe direction, and says why on that app's rows; a
     * reinstall ends it too, though Android gives the same name a new UID (K1); a package removed goes, saying nothing
     * until it comes back.
     */
    @Test
    fun aJoiningPackageOrAReinstallEndsTheChoice() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.choose(LoggedApps.entriesOfUid(phone, 10_124))
        assertEquals(listOf(10_123, 10_124), hand())
        phone.installed["com.example.companion"] = 10_123 to 3_000L
        phone.installed["com.example.other"] = 10_200 to 4_000L
        assertEquals(emptyList<Int>(), hand())
        assertEquals(emptySet<Entry>(), store.entries())
        assertEquals(mapOf("com.example.messenger" to Ended.SHARED, "com.example.other" to Ended.INSTALLED_AGAIN), store.ended())
        // Chosen again, the reason goes.
        store.choose(LoggedApps.entriesOfUid(phone, 10_200))
        assertEquals(mapOf("com.example.messenger" to Ended.SHARED), store.ended())
        assertEquals(listOf(10_200), hand())
        phone.installed.remove("com.example.other")
        assertEquals(emptyList<Int>(), hand())
        assertEquals(emptySet<Entry>(), store.entries())
        assertEquals(mapOf("com.example.messenger" to Ended.SHARED, "com.example.other" to Ended.REMOVED), store.ended())
    }

    /**
     * A reinstall the network part follows (review C-rest 1): the removal's hand-over finds the package gone and drops
     * it, and the install's finds it back, which says "installed again" as a first install time that changed does.
     * Until it comes back nothing is said, and a package chosen again forgets it.
     */
    @Test
    fun aReinstallSeenAsARemovalThenAnInstallSaysInstalledAgain() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        assertEquals(listOf(10_123), hand())
        phone.installed.remove("com.example.messenger")
        assertEquals(emptyList<Int>(), hand())
        assertEquals(emptySet<Entry>(), store.entries())
        assertEquals(mapOf("com.example.messenger" to Ended.REMOVED), store.ended())
        assertEquals(emptyList<Int>(), hand())
        assertEquals(mapOf("com.example.messenger" to Ended.REMOVED), store.ended())
        phone.installed["com.example.messenger"] = 10_300 to 6_000L
        assertEquals(emptyList<Int>(), hand())
        assertEquals(mapOf("com.example.messenger" to Ended.INSTALLED_AGAIN), store.ended())
        assertEquals(emptySet<Entry>(), store.entries())
        store.choose(LoggedApps.entriesOfUid(phone, 10_300))
        assertEquals(emptyMap<String, Ended>(), store.ended())
        assertEquals(listOf(10_300), hand())
        // Nothing of it reaches the disk but the choice itself.
        assertEquals(setOf("app\tcom.example.messenger\t6000"), disk.lines)
    }

    /**
     * The yes chooses the packages its confirmation named, never one that joined the UID while it was open (review
     * C-rest 9): that choice then ends as shared. A confirmation that named none chooses a UID of one package alone.
     */
    @Test
    fun theYesChoosesOnlyThePackagesTheConfirmationNamed() {
        assertEquals(listOf(Entry("com.example.messenger", 1_000)), LoggedApps.entriesNamed(phone, 10_123, emptyList()))
        phone.installed["com.example.companion"] = 10_123 to 1_500L
        assertEquals(emptyList<Entry>(), LoggedApps.entriesNamed(phone, 10_123, emptyList()))
        val named = LoggedApps.entriesNamed(phone, 10_123, listOf("com.example.messenger"))
        assertEquals(listOf(Entry("com.example.messenger", 1_000)), named)
        store.choose(named)
        assertEquals(emptyList<Int>(), hand())
        assertEquals(mapOf("com.example.messenger" to Ended.SHARED), store.ended())
        assertEquals(
            LoggedApps.entriesOfUid(phone, 10_123),
            LoggedApps.entriesNamed(phone, 10_123, listOf("com.example.companion", "com.example.messenger", "com.example.gone")),
        )
    }

    /** An update keeps the first install time, and so the choice, whatever its UID (K8). */
    @Test
    fun anUpdateKeepsTheChoice() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        phone.installed["com.example.messenger"] = 10_123 to 1_000L
        assertEquals(listOf(10_123), hand())
        assertEquals(setOf(Entry("com.example.messenger", 1_000)), store.entries())
        assertEquals(emptyMap<String, Ended>(), store.ended())
    }

    /**
     * A UID that is a tool by its signing key, or Android's PAC handler, is never handed, and its choice ends (K6); one
     * that is not an application's never is either.
     */
    @Test
    fun aToolOrThePacHandlerIsNeverHanded() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.choose(LoggedApps.entriesOfUid(phone, 10_124))
        assertEquals(listOf(10_124), hand(tools = setOf(10_123)))
        assertEquals(mapOf("com.example.messenger" to Ended.TOOL), store.ended())
        assertEquals(emptyList<Int>(), hand(pac = 10_124))
        assertEquals(emptySet<Entry>(), store.entries())
        phone.installed["com.example.system"] = 1_000 to 5_000L
        store.choose(LoggedApps.entriesOfUid(phone, 1_000))
        assertEquals(emptyList<Int>(), hand())
        assertEquals(Ended.SHARED, store.ended()["com.example.system"])
    }

    /**
     * Before the tools were read once in this run, no UID is handed and no tool's choice ends (K7); but a package
     * removed, installed again or joined by another needs no tools, and goes at once (audit-C 19).
     */
    @Test
    fun nothingIsHandedBeforeTheToolsAreRead() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.choose(LoggedApps.entriesOfUid(phone, 10_124))
        phone.installed["com.example.other"] = 10_124 to 9_000L
        assertEquals(emptyList<Int>(), hand(tools = setOf(10_123), toolsRead = false))
        assertEquals(setOf(Entry("com.example.messenger", 1_000)), store.entries())
        assertEquals(mapOf("com.example.other" to Ended.INSTALLED_AGAIN), store.ended())
        assertEquals(listOf(10_123), hand(toolsRead = true))
    }

    /**
     * Under the profile nothing is written (K3): the lines on disk go to memory when it is turned on, and the session's
     * choices go when it is turned off, with nothing written then either and nothing handed after (audit-C major 2, K10).
     */
    @Test
    fun theProfileKeepsTheChoiceInMemoryAndTurningItOffWritesNothing() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.setProfile(true)
        assertTrue(store.memoryOnly)
        assertEquals(emptySet<String>(), disk.lines)
        // On disk before it returns (review C-rest 12).
        assertEquals(1, disk.durable)
        assertEquals(listOf(10_123), hand())
        val writes = disk.writes
        store.choose(LoggedApps.entriesOfUid(phone, 10_124))
        store.stop(listOf("com.example.messenger"))
        phone.installed.remove("com.example.other")
        assertEquals(emptyList<Int>(), hand())
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        assertEquals(writes, disk.writes)
        assertEquals(emptySet<String>(), disk.lines)
        assertEquals(listOf(10_123), hand())
        store.setProfile(false)
        assertFalse(store.memoryOnly)
        assertEquals(emptySet<String>(), disk.lines)
        assertEquals(emptySet<Entry>(), store.entries())
        assertEquals(emptyList<Int>(), hand())
        // Turned off twice: the disk's choices, made after, stay.
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.setProfile(false)
        assertEquals(listOf(10_123), hand())
    }

    /**
     * W9's screen-off under the profile empties the session (and asks for a hand-over, audit-C 4); outside it, it does
     * nothing. The wipe empties disk and memory and the reasons, the profile's flag kept (K4).
     */
    @Test
    fun theScreenOffAndTheWipeLeaveNothing() {
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        val before = asked
        store.clearSession()
        assertEquals(before, asked)
        assertEquals(listOf(10_123), hand())
        store.setProfile(true)
        store.choose(LoggedApps.entriesOfUid(phone, 10_124))
        store.drop(LoggedApps.Handed(emptyList(), emptySet(), mapOf("com.example.gone" to Ended.SHARED)))
        val asks = asked
        store.clearSession()
        assertEquals(asks + 1, asked)
        assertEquals(emptySet<Entry>(), store.entries())
        assertEquals(emptyMap<String, Ended>(), store.ended())
        assertTrue(store.memoryOnly)
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.wipe()
        assertEquals(emptySet<Entry>(), store.entries())
        assertTrue(store.memoryOnly)
        store.setProfile(false)
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.drop(LoggedApps.Handed(emptyList(), emptySet(), mapOf("com.example.gone" to Ended.SHARED)))
        val wipes = asked
        val durable = disk.durable
        store.wipe()
        assertEquals(wipes + 1, asked)
        assertEquals(durable + 1, disk.durable)
        assertEquals(emptySet<String>(), disk.lines)
        assertEquals(emptyMap<String, Ended>(), store.ended())
        assertFalse(store.memoryOnly)
        assertEquals(emptyList<Int>(), hand())
    }

    /** The lines of a kind this build does not know (unit D's tools) stay as they are, and are never read as an app's. */
    @Test
    fun anotherKindsLinesStayAsTheyAre() {
        disk.lines = setOf("tool\tcom.example.tool\t7000", "app\tcom.example.other\t2000", "app\tbroken", "app\t\t3")
        assertEquals(setOf(Entry("com.example.other", 2_000)), store.entries())
        store.choose(LoggedApps.entriesOfUid(phone, 10_123))
        store.stop(listOf("com.example.other"))
        assertTrue("tool\tcom.example.tool\t7000" in disk.lines)
        assertEquals(setOf(Entry("com.example.messenger", 1_000)), store.entries())
    }

    /** The debug builds' `proxy-log` takes only this project's own packages, never a real app's (K9). */
    @Test
    fun theDebugCommandTakesOnlyTheProjectsOwnPackages() {
        assertTrue(LoggedApps.debugAllowed("org.visadahyu.datapavan.proxyfixture"))
        assertFalse(LoggedApps.debugAllowed("org.telegram.messenger"))
        assertFalse(LoggedApps.debugAllowed("org.visadahyu.datapavanx"))
        assertFalse(LoggedApps.debugAllowed(""))
    }
}
