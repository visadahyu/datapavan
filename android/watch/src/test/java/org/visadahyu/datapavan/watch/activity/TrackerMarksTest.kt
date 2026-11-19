package org.visadahyu.datapavan.watch.activity

import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.audit.AppSigning
import org.visadahyu.datapavan.audit.Owners
import org.visadahyu.datapavan.watch.activity.TrackerMarks.Mark
import org.visadahyu.datapavan.watch.activity.TrackerMarks.Match

class TrackerMarksTest {
    private val facebook = "https://developers.facebook.com/docs/android"
    private fun match(id: Int, name: String, website: String, alternative: String) = Match(id, name, website, alternative)
    private val groups = mapOf(facebook to "meta", "https://admob.google.com" to "alphabet")
    private fun marks(matches: List<Match>, app: String?) =
        TrackerMarks.marks(matches, app, { groups[it.website] }, { mapOf("meta" to "Meta Platforms, Inc.", "alphabet" to "Alphabet Inc.")[it] ?: it })

    private val sixOfFacebook = (65..70).map { match(it, "Facebook $it", facebook, "\\.facebook\\.com") }

    /**
     * Several trackers of one company named by one broad signature are one mark naming the company; a tracker
     * of an unknown company, or one alone on its alternative, is marked by its name (the maintainer, 2026-11-19).
     */
    @Test
    fun oneBroadSignatureIsOneMarkNamingTheCompany() {
        assertEquals(listOf(Mark.Company("Meta Platforms, Inc.")), marks(sixOfFacebook, app = null))
        val graph = match(67, "Facebook 67", facebook, "graph\\.facebook\\.com")
        assertEquals(listOf(Mark.Company("Meta Platforms, Inc.")), marks(sixOfFacebook + graph, app = null))
        val unknown = listOf(match(1, "One", "https://one.example", "\\.ads\\.example"), match(2, "Two", "https://two.example", "\\.ads\\.example"))
        assertEquals(listOf(Mark.Tracker("One"), Mark.Tracker("Two")), marks(unknown, app = null))
        val alone = match(312, "Google AdMob", "https://admob.google.com", "doubleclick\\.net")
        assertEquals(listOf(Mark.Tracker("Google AdMob")), marks(listOf(alone), app = null))
        // Two companies on one alternative: no company to name, each tracker by its name.
        val mixed = listOf(match(5, "Google DoubleClick", "https://admob.google.com", "x\\.net"), match(47, "Facebook Audience", facebook, "x\\.net"))
        assertEquals(listOf(Mark.Tracker("Google DoubleClick"), Mark.Tracker("Facebook Audience")), marks(mixed, app = null))
    }

    /** No tracker mark for the app's own company group, but the company's name; others keep theirs. */
    @Test
    fun theAppsOwnCompanyIsNoTracker() {
        assertEquals(listOf(Mark.SameCompany("Meta Platforms, Inc.")), marks(sixOfFacebook, app = "meta"))
        val admob = match(312, "Google AdMob", "https://admob.google.com", "doubleclick\\.net")
        assertEquals(listOf(Mark.SameCompany("Alphabet Inc."), Mark.Company("Meta Platforms, Inc.")), marks(sixOfFacebook + admob, app = "alphabet"))
        // An app whose company the table does not know is never the same company as anything.
        assertEquals(listOf(Mark.Tracker("Google AdMob")), marks(listOf(admob), app = null))
        assertEquals(emptyList<Mark>(), marks(emptyList(), app = "meta"))
    }

    /** One line of the library's answer, its malformed entries skipped. */
    @Test
    fun aLineOfMatchesReadsBack() {
        val line = "65\u001fFacebook Ads\u001f$facebook\u001f\\.facebook\\.com\tbad\t7\u001fX\u001f\u001fx\\.net"
        assertEquals(listOf(match(65, "Facebook Ads", facebook, "\\.facebook\\.com"), match(7, "X", "", "x\\.net")), TrackerMarks.parse(line))
        assertEquals(emptyList<Match>(), TrackerMarks.parse(""))
    }

    private val owners = Owners.parse(
        """
        alphabet	Alphabet Inc.	Q1	-				s	d
        google	Google LLC	Q2	alphabet	whole	2015-10-02		s	d
        meta	Meta Platforms, Inc.	Q3	-				s	d
        telegram-group	Telegram Group Inc	Q4	-				s	d
        telegram	Telegram Messenger Inc.	Q5	telegram-group	joint	2014-01-01		s	d
        """.trimIndent(),
        "",
        "org.example.maps\t${"a".repeat(64)}\tgoogle\t1\ts\th\td\norg.example.chat\t${"b".repeat(64)}\tmeta\t1\ts\th\td",
    )
    private val sources = "# c\ngoogle\tasset-links\thttps://www.google.com/.well-known/assetlinks.json\n" +
        "meta\tasset-links\thttps://www.facebook.com/.well-known/assetlinks.json\ngoogle\tsdk-needs\tgoogle-play-services"
    private val companies = Companies(owners, sources, "2026-11-19")

    /**
     * A tracker's company is the entity whose own domain holds its website's host, up to the top of its group;
     * an app's is its publisher's group, where its packages agree; nothing the table does not record.
     */
    @Test
    fun companiesComeFromTheOwnersTable() {
        assertEquals("alphabet", companies.groupOfWebsite("https://admob.google.com"))
        assertEquals("alphabet", companies.groupOfWebsite("http://www.google.com/analytics/"))
        assertEquals("meta", companies.groupOfWebsite(facebook))
        assertEquals(null, companies.groupOfWebsite("https://notgoogle.com"))
        assertEquals(null, companies.groupOfWebsite("https://www.yandex.com/"))
        assertEquals(null, companies.groupOfWebsite("not a url"))
        val maps = AppSigning(listOf("a".repeat(64)), emptyList(), false)
        val chat = AppSigning(listOf("b".repeat(64)), emptyList(), false)
        assertEquals("alphabet", companies.groupOfApp(listOf("org.example.maps" to maps)))
        assertEquals("alphabet", companies.groupOfApp(listOf("org.example.maps" to maps, "org.example.other" to null)))
        assertEquals("two groups", null, companies.groupOfApp(listOf("org.example.maps" to maps, "org.example.chat" to chat)))
        assertEquals("another signer", null, companies.groupOfApp(listOf("org.example.maps" to chat)))
        assertEquals("Alphabet Inc.", companies.name("alphabet"))
        assertEquals("unknown", companies.name("unknown"))
    }
}
