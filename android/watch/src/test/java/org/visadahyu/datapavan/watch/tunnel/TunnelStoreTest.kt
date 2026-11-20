package org.visadahyu.datapavan.watch.tunnel

import java.io.File
import java.nio.file.Files
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The configurations' store (W7, part 2) behind a wrap of the test's own, which seals as the Keystore's does in
 * shape: an IV, a tag over the slot, the part and the bytes, then the bytes, so that a wrap moved to another slot or
 * part does not open; its key can be lost, or locked as a key that needs an unlocked phone is.
 */
class TunnelStoreTest {
    private val dir: File = Files.createTempDirectory("tunnels").toFile()

    @After
    fun clean() {
        dir.deleteRecursively()
    }

    /** A wrap of the test's: XOR with a key byte, a tag of the associated data; it remembers what it was given. */
    class FakeWrap : Wrap {
        var key: Byte? = 0x5a
        var locked = false

        /** The Keystore erring as it does when busy or restarting. */
        var failing = false
        val given = mutableListOf<ByteArray>()
        private var iv = 0

        override fun wrap(slot: Int, part: Wrap.Part, plain: ByteArray): ByteArray {
            if (failing) throw java.security.ProviderException("Keystore operation failed")
            given += plain
            val k = key ?: error("no key")
            iv++
            return byteArrayOf(iv.toByte()) + tag(slot, part, plain, iv) + ByteArray(plain.size) { (plain[it].toInt() xor k.toInt() xor iv).toByte() }
        }

        override fun unwrap(slot: Int, part: Wrap.Part, wrapped: ByteArray): Opened {
            if (locked) return Opened.Locked
            val k = key ?: return Opened.Lost
            if (wrapped.size < 5) return Opened.Lost
            val iv = wrapped[0].toInt()
            val plain = ByteArray(wrapped.size - 5) { (wrapped[it + 5].toInt() xor k.toInt() xor iv).toByte() }
            return if (tag(slot, part, plain, iv).contentEquals(wrapped.copyOfRange(1, 5))) Opened.Plain(plain) else Opened.Lost
        }

        private fun tag(slot: Int, part: Wrap.Part, plain: ByteArray, iv: Int): ByteArray {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            digest.update(associated(slot, part))
            digest.update(plain)
            digest.update(iv.toByte())
            return digest.digest().copyOf(4)
        }

        override fun destroy() {
            key = null
        }

        override fun home() = KeyHome.SOFTWARE
    }

    private val wrap = FakeWrap()

    /** A disk that fills up after [room] more files. */
    private var room = Int.MAX_VALUE
    private val disk = TunnelStore.Disk { file, bytes ->
        if (room-- <= 0) throw java.io.IOException("No space left on device")
        TunnelStore.Disk.SYNCED.write(file, bytes)
    }
    private fun store() = TunnelStore(dir, wrap, disk)

    /** Every file of the store and its bytes, to tell a change that left nothing behind. */
    private fun files(): Map<String, List<Byte>> = dir.listFiles().orEmpty().associate { it.name to it.readBytes().toList() }
    private val text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n".toByteArray()

    private fun opened(store: TunnelStore, slot: Int): ByteArray? = (store.text(slot) as? Opened.Plain)?.bytes

    @Test
    fun a_configuration_comes_back_as_it_went_in_and_no_file_holds_it_plain() {
        val store = store()
        val slot = store.add("Proton NL-FREE#1", text)
        assertEquals(1, slot)
        assertArrayEquals(text, opened(store, 1))
        assertEquals(TunnelStore.Name.Known("Proton NL-FREE#1"), store.name(1))
        // A store opened afresh, as after Watch started again, reads the same from the files.
        val again = store()
        assertArrayEquals(text, opened(again, 1))
        assertEquals(TunnelStore.Name.Known("Proton NL-FREE#1"), again.name(1))
        assertEquals(listOf(1), again.state().order)
        for (file in dir.listFiles().orEmpty()) {
            val bytes = file.readBytes()
            assertFalse("${file.name} holds the key", String(bytes, Charsets.ISO_8859_1).contains("yAnz5TF"))
            assertFalse("${file.name} holds the name", String(bytes, Charsets.ISO_8859_1).contains("Proton"))
        }
        assertFalse("no file is left half written", dir.listFiles().orEmpty().any { it.name.endsWith(".new") })
    }

    @Test
    fun a_wrap_moved_to_another_slot_or_part_does_not_open() {
        val store = store()
        store.add("one", text)
        store.add("two", "other".toByteArray())
        File(dir, "1.text").copyTo(File(dir, "2.text"), overwrite = true)
        assertEquals(Opened.Lost, store.text(2))
        File(dir, "1.name").copyTo(File(dir, "1.text"), overwrite = true)
        assertEquals(Opened.Lost, store.text(1))
        File(dir, "2.name").delete()
        assertEquals(TunnelStore.Name.Removed, TunnelStore(dir, wrap).name(2))
    }

    @Test
    fun a_lost_key_or_a_locked_phone_says_so_and_keeps_the_apps_routed() {
        val store = store()
        val slot = store.add("work", text) ?: error("full")
        store.route("org.example.mail", slot)
        wrap.locked = true
        assertEquals(Opened.Locked, store.text(slot))
        assertEquals(TunnelStore.Name.Locked, TunnelStore(dir, wrap).name(slot))
        wrap.locked = false
        wrap.destroy()
        assertEquals(Opened.Lost, store.text(slot))
        assertEquals(TunnelStore.Name.Lost, TunnelStore(dir, wrap).name(slot))
        assertEquals(mapOf("org.example.mail" to slot), store.state().routes)
        assertEquals(listOf(slot), store.state().order)
    }

    @Test
    fun the_store_holds_to_the_engines_bound() {
        val store = store()
        repeat(TunnelStore.MAX) { assertEquals(it + 1, store.add("n$it", text)) }
        assertTrue(store.state().full)
        assertNull(store.add("one more", text))
        assertEquals(TunnelStore.MAX, store.state().order.size)
        store.remove(3, appsWait = false)
        assertEquals("a removed slot's number is not given again", 9, store.add("again", text))
    }

    @Test
    fun removal_keeps_the_apps_waiting_or_sends_them_their_other_way() {
        val store = store()
        val one = store.add("one", text) ?: error("full")
        val two = store.add("two", text) ?: error("full")
        store.route("org.example.a", one)
        store.route("org.example.b", two)
        store.setLocal(one, true)
        store.remove(one, appsWait = true)
        assertEquals(listOf(two), store.state().order)
        assertEquals(one, store.state().routes["org.example.a"])
        assertEquals(emptySet<Int>(), store.state().local)
        assertFalse(File(dir, "$one.text").exists() || File(dir, "$one.name").exists())
        assertEquals(TunnelStore.Name.Removed, store.name(one))
        // A slot an app still waits for is not given to a new configuration, which would carry that app.
        val three = store.add("three", text)
        assertTrue(three != one)
        store.remove(two, appsWait = false)
        assertNull(store.state().routes["org.example.b"])
        assertEquals(one, store.state().routes["org.example.a"])
    }

    @Test
    fun replace_keeps_the_apps_and_the_switches_and_rename_keeps_the_text() {
        val store = store()
        val slot = store.add("old", text) ?: error("full")
        store.route("org.example.a", slot)
        store.setLocal(slot, true)
        val newer = "[Interface]\nPrivateKey = newer\n".toByteArray()
        store.replace(slot, newer, null)
        assertArrayEquals(newer, opened(store, slot))
        assertEquals(TunnelStore.Name.Known("old"), store.name(slot))
        assertEquals(slot, store.state().routes["org.example.a"])
        assertEquals(setOf(slot), store.state().local)
        val before = wrap.given.size
        store.rename(slot, "new")
        assertEquals(TunnelStore.Name.Known("new"), store.name(slot))
        assertEquals("rename wraps the name alone", before + 1, wrap.given.size)
        assertArrayEquals(newer, opened(store, slot))
    }

    @Test
    fun a_slot_an_app_waits_for_is_never_given_again_even_from_a_damaged_count() {
        dir.mkdirs()
        File(dir, "state").writeText("order\nnext 1\nroute org.example.a 1\n")
        assertEquals("the waiting app's slot is passed over", 2, store().add("new", text))
    }

    @Test
    fun the_bound_is_the_engines() {
        val source = File("../../core/net/src/engine/tunnels.rs").readText()
        val engine = Regex("pub const MAX_TUNNELS: usize = (\\d+);").find(source)?.groupValues?.get(1)?.toInt()
        assertEquals("core/net's MAX_TUNNELS", engine, TunnelStore.MAX)
    }

    @Test
    fun the_default_is_the_first_and_can_be_chosen() {
        val store = store()
        val one = store.add("one", text) ?: error("full")
        val two = store.add("two", text) ?: error("full")
        assertEquals(one, store.state().default)
        store.setDefault(two)
        assertEquals(listOf(two, one), store.state().order)
        store.setDefault(99)
        assertEquals(listOf(two, one), store.state().order)
    }

    @Test
    fun names_are_kept_without_control_or_direction_characters() {
        assertEquals("Work VPN", TunnelStore.cleanName("  Work‮\tVPN\n"))
        assertEquals("a".repeat(TunnelStore.NAME_LENGTH), TunnelStore.cleanName("a".repeat(100)))
        val emoji = "a".repeat(TunnelStore.NAME_LENGTH - 1) + "😀"
        assertEquals("never half a character", "a".repeat(TunnelStore.NAME_LENGTH - 1), TunnelStore.cleanName(emoji))
    }

    @Test
    fun a_state_file_that_is_damaged_gives_what_it_can_and_never_a_route_to_nothing() {
        dir.mkdirs()
        File(dir, "state").writeText("order 1 x 2\nroute not-a-package 1\nroute org.example.a 0\nroute org.example.b 2\nnext -4\n")
        val state = store().state()
        assertEquals("no text, no slot", emptyList<Int>(), state.order)
        assertEquals(mapOf("org.example.b" to 2), state.routes)
        assertEquals(1, state.next)
    }

    /**
     * A change that fails leaves the store as it was (fix round, security review M3): the disk filling up at any of
     * the files a change writes, or the Keystore erring, changes no file, leaves no half-written one, and the
     * configuration it would have replaced still opens as it was.
     */
    @Test
    fun a_full_disk_or_a_keystore_error_leaves_the_store_as_it_was() {
        val store = store()
        val one = store.add("one", text, local = true, apps = setOf("org.example.a")) ?: error("full")
        val before = files()
        for (written in 0..2) {
            room = written
            try {
                store.add("two", "other".toByteArray(), apps = setOf("org.example.b"))
                error("the disk took it")
            } catch (e: java.io.IOException) {
                // Expected.
            }
            assertEquals("a new configuration, the disk full after $written files", before, files())
        }
        for (written in 0..1) {
            room = written
            try {
                store.replace(one, "newer".toByteArray(), "renamed")
                error("the disk took it")
            } catch (e: java.io.IOException) {
                // Expected.
            }
            assertEquals("a replacement, the disk full after $written files", before, files())
        }
        room = 0
        for (change in listOf<() -> Unit>({ store.rename(one, "x") }, { store.remove(one, appsWait = false) }, { store.setDefault(one) }, { store.route("org.example.c", one) })) {
            try {
                change()
                error("the disk took it")
            } catch (e: java.io.IOException) {
                // Expected.
            }
            assertEquals(before, files())
        }
        room = Int.MAX_VALUE
        wrap.failing = true
        try {
            store.replace(one, "newer".toByteArray(), "renamed")
            error("the Keystore wrapped it")
        } catch (e: java.security.ProviderException) {
            // Expected.
        }
        assertEquals("a Keystore error", before, files())
        wrap.failing = false
        assertArrayEquals(text, opened(TunnelStore(dir, wrap), one))
        assertEquals(TunnelStore.Name.Known("one"), TunnelStore(dir, wrap).name(one))
        assertEquals(mapOf("org.example.a" to one), store.state().routes)
    }

    /** A configuration's switch and apps go in with it, in one change. */
    @Test
    fun a_new_configuration_keeps_its_switch_and_apps_in_the_same_change() {
        val store = store()
        val slot = store.add("one", text, local = true, apps = setOf("org.example.a", "org.example.b")) ?: error("full")
        assertEquals(setOf(slot), store.state().local)
        assertEquals(mapOf("org.example.a" to slot, "org.example.b" to slot), store.state().routes)
    }

    /** A replacement whose configuration was removed while the confirmation was open says so, and writes nothing. */
    @Test
    fun a_slot_removed_meanwhile_is_said_and_nothing_is_written() {
        val store = store()
        val one = store.add("one", text) ?: error("full")
        store.remove(one, appsWait = false)
        val before = files()
        try {
            store.replace(one, text, "again")
            error("replaced a removed slot")
        } catch (e: TunnelStore.SlotGone) {
            // Expected.
        }
        assertEquals(before, files())
    }

    /** A wrap that cannot be opened now is tried again a few times, after pauses that grow, then waits (m2). */
    @Test
    fun a_configuration_that_cannot_be_opened_now_is_tried_again_a_bounded_number_of_times() {
        val waits = generateSequence(0) { it + 1 }.map { TunnelStore.retryAfterMs(it) }.takeWhile { it != null }.toList()
        assertTrue("tried again at all", waits.isNotEmpty())
        assertTrue("a few times", waits.size <= 10)
        assertEquals("pauses that grow", waits.sortedBy { it }, waits)
        assertNull(TunnelStore.retryAfterMs(waits.size))
    }

    /**
     * What a Keystore error means (fix round, security review m2): lost for good only where the key's alias is gone,
     * the key invalidated or the tag does not match; a busy or restarting Keystore cannot open it now, and it is
     * tried again; a key that needs an unlocked phone, on a locked one, waits for the unlock.
     */
    @Test
    fun only_a_bad_tag_or_an_invalidated_key_reads_as_lost() {
        val never = { false }
        assertEquals(Opened.Lost, KeystoreWrap.opened(javax.crypto.AEADBadTagException(), unlockedOnly = false, lockedNow = never))
        assertEquals(Opened.Unavailable, KeystoreWrap.opened(java.security.ProviderException("Keystore busy"), unlockedOnly = false, lockedNow = never))
        assertEquals(Opened.Unavailable, KeystoreWrap.opened(java.security.KeyStoreException("system error"), unlockedOnly = false, lockedNow = never))
        assertEquals(Opened.Unavailable, KeystoreWrap.opened(java.security.InvalidKeyException(), unlockedOnly = false, lockedNow = { true }))
        assertEquals(Opened.Locked, KeystoreWrap.opened(java.security.InvalidKeyException(), unlockedOnly = true, lockedNow = { true }))
        assertEquals(Opened.Unavailable, KeystoreWrap.opened(java.security.InvalidKeyException(), unlockedOnly = true, lockedNow = never))
        val store = store()
        val slot = store.add("one", text) ?: error("full")
        File(dir, "$slot.text").setReadable(false)
        if (!File(dir, "$slot.text").canRead()) {
            assertEquals("a file that cannot be read now", Opened.Unavailable, store.text(slot))
        }
        File(dir, "$slot.text").setReadable(true)
    }
}
