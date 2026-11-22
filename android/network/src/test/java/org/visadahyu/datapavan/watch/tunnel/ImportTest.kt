package org.visadahyu.datapavan.watch.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The import's confirmation (W7, part 2): what the engine's description reads into, the choice of apps a file
 * proposes from both of WireGuard's application lists, the apps it names that are not installed, the name it
 * starts with, and the bytes zeroed once the import is done.
 */
class ImportTest {
    /** What `nativeTunnelParse` answers for a Proton-like file with WireGuard's app's list of apps. */
    private val answer = """
        ok
        endpoint 198.51.100.7 51820
        address 10.2.0.2/32
        address fd00::2/128
        dns 10.2.0.1
        allowed 0.0.0.0/0
        allowed ::/0
        everything 1
        preshared 1
        mtu 1420
        keepalive 25
        only org.example.mail
        only org.example.gone
        only org.visadahyu.datapavan.advanced
    """.trimIndent()

    @Test
    fun the_description_reads_every_field() {
        val read = Import.read(answer) as Import.Described
        assertEquals("198.51.100.7", read.host)
        assertEquals(51_820, read.port)
        assertEquals(listOf("10.2.0.2/32", "fd00::2/128"), read.addresses)
        assertTrue(read.ipv6)
        assertEquals(listOf("10.2.0.1"), read.dns)
        assertEquals(listOf("0.0.0.0/0", "::/0"), read.allowed)
        assertTrue(read.everything)
        assertTrue(read.preshared)
        assertEquals(1_420, read.mtu)
        assertEquals(25, read.keepalive)
        assertEquals(listOf("org.example.mail", "org.example.gone", "org.visadahyu.datapavan.advanced"), read.only)
        assertEquals(emptyList<String>(), read.except)
    }

    @Test
    fun a_narrower_file_without_ipv6_or_keepalive_reads_so() {
        val read = Import.read(
            "ok\nendpoint vpn.example.net 443\naddress 10.0.0.2/32\ndns 10.0.0.1\nallowed 10.0.0.0/8\neverything 0\npreshared 0\nmtu 1280",
        ) as Import.Described
        assertEquals("vpn.example.net", read.host)
        assertFalse(read.ipv6)
        assertFalse(read.everything)
        assertFalse(read.preshared)
        assertNull(read.keepalive)
        assertEquals(IPV6_ENDPOINT, (Import.read("ok\nendpoint 2001:db8::7 51820\naddress 10.0.0.2/32\ndns 10.0.0.1\nallowed 0.0.0.0/0\neverything 1\npreshared 0\nmtu 1280") as Import.Described).host)
    }

    @Test
    fun an_answer_the_engine_never_gives_is_not_read() {
        assertNull(Import.read(""))
        assertNull(Import.read("maybe"))
        assertNull(Import.read("ok\nendpoint 192.0.2.1 51820"), )
        assertNull(Import.read("ok\nsecret yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="))
    }

    /** Every app the test's phone has installed, the choosable ones and one without an icon to open it. */
    private val installed = setOf("org.example.mail", "org.example.chat", "org.example.maps", "org.example.out", "org.example.noicon", "org.visadahyu.datapavan.advanced")

    private fun propose(read: Import.Described, choosable: List<String>, leftOut: Set<String> = setOf("org.example.out"), elsewhere: Set<String> = emptySet()) =
        Import.propose(read, choosable, "org.visadahyu.datapavan.advanced", leftOut, { it in installed }, { it !in elsewhere })

    @Test
    fun included_applications_propose_those_installed_and_say_why_not_the_others() {
        val read = Import.read(answer.replace("only org.example.gone", "only org.example.gone\nonly org.example.noicon\nonly org.example.out")) as Import.Described
        val choosable = listOf("org.example.chat", "org.example.mail", "org.visadahyu.datapavan.advanced", "org.example.out")
        val proposal = propose(read, choosable)
        assertEquals(listOf("org.example.mail"), proposal.proposed)
        assertEquals(setOf("org.example.mail"), proposal.ticked)
        assertEquals(listOf("org.example.gone"), proposal.notInstalled)
        // Installed but not among the apps the user can choose, and left out of Watch: each said apart (m2).
        assertEquals(listOf("org.example.noicon"), proposal.notChoosable)
        assertEquals(listOf("org.example.out"), proposal.leftOut)
        assertEquals(emptyList<String>(), proposal.excluded)
    }

    /**
     * The proposed apps come first, in the file's order, and an app that goes another way now (the tool, another
     * configuration, or waiting for a removed one) is proposed but not ticked, so that Save moves nothing silently
     * (fix round, screens review M2).
     */
    @Test
    fun an_app_that_goes_another_way_is_proposed_but_not_ticked() {
        val read = Import.read(answer.replace("only org.example.gone\n", "only org.example.chat\nonly org.example.maps\n")) as Import.Described
        val choosable = listOf("org.example.chat", "org.example.mail", "org.example.maps")
        val proposal = propose(read, choosable, elsewhere = setOf("org.example.chat", "org.example.maps"))
        assertEquals("the file's order", listOf("org.example.mail", "org.example.chat", "org.example.maps"), proposal.proposed)
        assertEquals(setOf("org.example.mail"), proposal.ticked)
    }

    @Test
    fun excluded_applications_propose_every_app_but_those_and_name_them() {
        val except = answer.replace("only ", "except ")
        val read = Import.read(except) as Import.Described
        val choosable = listOf("org.example.chat", "org.example.mail", "org.example.maps", "org.visadahyu.datapavan.advanced", "org.example.out")
        val proposal = propose(read, choosable, elsewhere = setOf("org.example.maps"))
        assertEquals("never Watch, never an app left out of Watch", listOf("org.example.chat", "org.example.maps"), proposal.proposed)
        assertEquals(setOf("org.example.chat"), proposal.ticked)
        assertEquals("the apps it leaves out, by name", listOf("org.example.mail"), proposal.excluded)
        assertEquals(listOf("org.example.gone"), proposal.notInstalled)
    }

    @Test
    fun a_file_that_names_no_apps_proposes_none() {
        val plain = answer.lines().filterNot { it.startsWith("only ") }.joinToString("\n")
        val proposal = propose(Import.read(plain) as Import.Described, listOf("org.example.mail"))
        assertEquals(emptyList<String>(), proposal.proposed)
        assertEquals(emptySet<String>(), proposal.ticked)
        assertEquals(emptyList<String>(), proposal.notInstalled)
    }

    /**
     * The configuration on its way is held across the screen's recreation and zeroed when another takes its place,
     * when it is dropped, and by whoever takes it to save it (fix round, screens review M1).
     */
    @Test
    fun the_held_configuration_is_zeroed_when_replaced_dropped_or_saved() {
        val read = Import.read(answer) as Import.Described
        val held = Import.Held()
        val first = "one".toByteArray()
        held.hold(Import.Pending(first, read, "one"))
        val second = "two".toByteArray()
        held.hold(Import.Pending(second, read, "two"))
        assertTrue("the one replaced is zeroed", first.all { it == 0.toByte() })
        assertArrayEquals("two".toByteArray(), held.now?.text)
        held.drop()
        assertTrue("dropped", second.all { it == 0.toByte() })
        assertNull(held.now)
        val third = "three".toByteArray()
        held.hold(Import.Pending(third, read, "three"))
        val taken = held.take()
        assertNull("nothing held once taken", held.now)
        held.drop()
        assertArrayEquals("the saver's to zero", "three".toByteArray(), taken?.text)
    }

    @Test
    fun the_name_comes_from_the_file_or_is_the_first_number_free() {
        val default = { n: Int -> "WireGuard $n" }
        assertEquals("nl-free-12", Import.defaultName("nl-free-12.conf", default, emptyList()))
        assertEquals("Work", Import.defaultName("Download/Work.CONF", default, emptyList()))
        assertEquals("WireGuard 1", Import.defaultName(null, default, emptyList()))
        assertEquals("WireGuard 3", Import.defaultName(".conf", default, listOf("WireGuard 1", "WireGuard 2")))
    }

    @Test
    fun a_pending_import_zeroes_its_bytes_when_done() {
        val text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n".toByteArray()
        val pending = Import.Pending(text, Import.read(answer) as Import.Described, "one")
        assertArrayEquals(text, pending.text)
        pending.close()
        assertNull(pending.text)
        assertTrue("zeroed", text.all { it == 0.toByte() })
        pending.close()
    }

    private companion object {
        const val IPV6_ENDPOINT = "2001:db8::7"
    }
}
