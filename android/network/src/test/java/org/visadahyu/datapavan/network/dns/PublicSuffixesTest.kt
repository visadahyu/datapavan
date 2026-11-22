package org.visadahyu.datapavan.network.dns

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Review S-C1: a network's search domain that is a public suffix, or one label, is never taken as its own. */
class PublicSuffixesTest {
    private val shipped = PublicSuffixes.parse(File("../../data/public-suffix/icann.dat").readText())

    @Test
    fun theListReadsRulesWildcardsAndExceptions() {
        for (suffix in listOf("com", "net", "co.uk", "ac.uk", "foo.ck", "anything.kawasaki.jp", "xn--55qx5d.cn", "org", "ir", "co.ir")) {
            assertTrue(suffix, shipped.isSuffix(suffix))
        }
        for (domain in listOf("example.com", "corp.example.co.uk", "www.ck", "city.kawasaki.jp", "bbc.co.uk", "home.example")) {
            assertFalse(domain, shipped.isSuffix(domain))
        }
    }

    @Test
    fun aNetworkKeepsOnlyItsOwnDomains() {
        assertEquals(
            "corp.example example.org",
            SearchDomains.accepted("com net. corp.example. Example.ORG co.uk lan corp.example uk", shipped),
        )
        assertEquals("", SearchDomains.accepted("bad..example .example ex *.example", shipped))
        // Without the list Watch cannot tell, and takes none.
        assertEquals("", SearchDomains.accepted("corp.example", PublicSuffixes.parse("")))
        assertEquals(16, SearchDomains.accepted((1..20).joinToString(" ") { "d$it.example" }, shipped).split(' ').size)
    }
}
