package org.visadahyu.datapavan.network.tunnel

import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A change of the configurations from the network screen ends alone when the store throws (W7, part 2, fix round,
 * security review M3): a full disk, a Keystore error and a slot removed while the confirmation was open each give a
 * reason to say, never an exception on the store's worker, which would end the network process and the VPN with it; the
 * store stays as it was, and the configuration's bytes are zeroed whatever happens.
 */
class ChangesTest {
    private val dir: File = Files.createTempDirectory("tunnels").toFile()
    private val wrap = TunnelStoreTest.FakeWrap()
    private var full = false
    private val store = TunnelStore(dir, wrap) { file, bytes ->
        if (full) throw java.io.IOException("No space left on device")
        TunnelStore.Disk.SYNCED.write(file, bytes)
    }
    private val described = Import.read(
        "ok\nendpoint 192.0.2.1 51820\naddress 10.0.0.2/32\ndns 10.0.0.1\nallowed 0.0.0.0/0\neverything 1\npreshared 0\nmtu 1420",
    ) as Import.Described

    private fun pending() = Import.Pending("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n".toByteArray(), described, "one")

    private fun files(): Map<String, List<Byte>> = dir.listFiles().orEmpty().associate { it.name to it.readBytes().toList() }

    @After
    fun clean() {
        dir.deleteRecursively()
    }

    @Test
    fun a_saved_configuration_is_added_with_its_apps_and_its_bytes_zeroed() {
        val pending = pending()
        val text = pending.text!!
        val saved = Changes.save(store, pending, "one", null, local = true, apps = setOf("org.example.mail"))
        assertEquals(Changes.Saved.Added(1), saved)
        assertEquals(mapOf("org.example.mail" to 1), store.state().routes)
        assertTrue("zeroed", text.all { it == 0.toByte() })
        assertNull(pending.text)
    }

    @Test
    fun a_full_disk_is_said_and_changes_nothing() {
        Changes.save(store, pending(), "one", null, local = false, apps = emptySet())
        val before = files()
        full = true
        val pending = pending()
        val text = pending.text!!
        assertEquals(Changes.Saved.Not(Changes.NotSaved.STORAGE), Changes.save(store, pending, "two", null, local = false, apps = setOf("org.example.a")))
        assertEquals(Changes.Saved.Not(Changes.NotSaved.STORAGE), Changes.save(store, pending(), "one", 1, local = false, apps = emptySet()))
        assertEquals(Changes.NotSaved.STORAGE, Changes.run { store.rename(1, "renamed") })
        assertEquals(Changes.NotSaved.STORAGE, Changes.run { store.remove(1, appsWait = true) })
        assertEquals(before, files())
        assertTrue("zeroed", text.all { it == 0.toByte() })
    }

    @Test
    fun a_keystore_error_is_said_and_changes_nothing() {
        Changes.save(store, pending(), "one", null, local = false, apps = emptySet())
        val before = files()
        wrap.failing = true
        val pending = pending()
        val text = pending.text!!
        assertEquals(Changes.Saved.Not(Changes.NotSaved.KEYSTORE), Changes.save(store, pending, "one", 1, local = false, apps = emptySet()))
        assertEquals(Changes.NotSaved.KEYSTORE, Changes.run { store.rename(1, "renamed") })
        assertEquals(before, files())
        assertTrue("zeroed", text.all { it == 0.toByte() })
    }

    @Test
    fun a_slot_removed_while_the_confirmation_was_open_is_said() {
        Changes.save(store, pending(), "one", null, local = false, apps = emptySet())
        store.remove(1, appsWait = false)
        val pending = pending()
        val text = pending.text!!
        assertEquals(Changes.Saved.Not(Changes.NotSaved.GONE), Changes.save(store, pending, "one", 1, local = false, apps = emptySet()))
        assertEquals(Changes.NotSaved.GONE, Changes.run { store.rename(1, "renamed") })
        assertEquals(emptyList<Int>(), store.state().order)
        assertTrue("zeroed", text.all { it == 0.toByte() })
    }

    @Test
    fun the_engines_bound_is_said() {
        repeat(TunnelStore.MAX) { Changes.save(store, pending(), "n$it", null, local = false, apps = emptySet()) }
        assertEquals(Changes.Saved.Not(Changes.NotSaved.FULL), Changes.save(store, pending(), "more", null, local = false, apps = emptySet()))
    }

    @Test
    fun anything_else_the_store_throws_ends_the_change_alone() {
        assertEquals(Changes.NotSaved.OTHER, Changes.run { store.route("not a package", 1) })
        assertEquals(Changes.NotSaved.OTHER, Changes.run { error("unexpected") })
        assertNull(Changes.run { })
    }
}
