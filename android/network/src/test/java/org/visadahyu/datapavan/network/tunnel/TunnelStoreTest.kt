package org.visadahyu.datapavan.network.tunnel

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
    class FakeWrap(private val start: Byte = 0x5a) : Wrap {
        var key: Byte? = start
        var locked = false

        /** The Keystore erring as it does when busy or restarting. */
        var failing = false
        val given = mutableListOf<ByteArray>()
        private var iv = 0

        override fun wrap(slot: Int, part: Wrap.Part, plain: ByteArray): ByteArray {
            if (failing) throw java.security.ProviderException("Keystore operation failed")
            // A key that needs an unlocked phone cannot be used on a locked one, to wrap as to open.
            if (locked) throw java.security.InvalidKeyException("Key user not authenticated")
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

    /** Key B, which works only while the phone is unlocked. */
    private val unlocked = FakeWrap(0x33)

    /** A disk that fills up after [room] more files. */
    private var room = Int.MAX_VALUE
    private val disk = TunnelStore.Disk { file, bytes ->
        if (room-- <= 0) throw java.io.IOException("No space left on device")
        TunnelStore.Disk.SYNCED.write(file, bytes)
    }
    private fun store() = TunnelStore(dir, wrap, unlocked, disk)

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
        // A store opened afresh, as after the network part started again, reads the same from the files.
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

    /**
     * A configuration under key B on a locked phone, or whose key is gone, says so, and its apps stay routed to it:
     * what decides the routes is under key A, which opens while the phone is locked (the maintainer's decision of
     * 2026-11-20).
     */
    @Test
    fun a_lost_key_or_a_locked_phone_says_so_and_keeps_the_apps_routed() {
        val store = store()
        store.setProfile(true)
        val slot = store.add("work", text) ?: error("full")
        store.route("org.example.mail", slot)
        unlocked.locked = true
        assertEquals(Opened.Locked, store.text(slot))
        assertEquals(TunnelStore.Name.Locked, TunnelStore(dir, wrap, unlocked).name(slot))
        assertEquals("the routes open while the phone is locked", mapOf("org.example.mail" to slot), TunnelStore(dir, wrap, unlocked).state().routes)
        unlocked.locked = false
        unlocked.destroy()
        assertEquals(Opened.Lost, store.text(slot))
        assertEquals(TunnelStore.Name.Lost, TunnelStore(dir, wrap, unlocked).name(slot))
        assertEquals(mapOf("org.example.mail" to slot), store.state().routes)
        assertEquals(listOf(slot), store.state().order)
    }

    /**
     * What decides a route is wrapped under key A, never in plain and never under key B (the maintainer's decision of
     * 2026-11-20): no file holds an app's package name or the order in plain, and with key B locked or gone the state
     * still gives every route, the order and the default.
     */
    @Test
    fun the_routes_are_wrapped_under_key_a_and_never_depend_on_key_b() {
        val store = store()
        store.setProfile(true)
        val one = store.add("one", text, local = true, apps = setOf("org.example.mail")) ?: error("full")
        val two = store.add("two", text, apps = setOf("org.example.chat")) ?: error("full")
        store.setDefault(two)
        for (file in dir.listFiles().orEmpty()) {
            val plain = String(file.readBytes(), Charsets.ISO_8859_1)
            for (word in listOf("org.example", "order", "route", "profile")) assertFalse("${file.name} holds $word in plain", word in plain)
        }
        for (closed in listOf<() -> Unit>({ unlocked.locked = true }, { unlocked.locked = false; unlocked.destroy() })) {
            closed()
            val state = TunnelStore(dir, wrap, unlocked).state()
            assertEquals(mapOf("org.example.mail" to one, "org.example.chat" to two), state.routes)
            assertEquals(listOf(two, one), state.order)
            assertEquals(two, state.default)
            assertEquals(setOf(one), state.local)
            assertTrue(state.profile)
        }
    }

    /** With ADR 0047's profile on, a configuration's text and name go under key B, and its file says so. */
    @Test
    fun with_the_profile_on_a_configuration_goes_under_key_b() {
        val store = store()
        val before = store.add("before", text) ?: error("full")
        assertEquals(TunnelStore.Key.A, store.keyOf(before))
        store.setProfile(true)
        val after = store.add("after", "after".toByteArray()) ?: error("full")
        assertEquals(TunnelStore.Key.B, store.keyOf(after))
        assertTrue("key B wrapped its text", unlocked.given.any { it.contentEquals("after".toByteArray()) })
        assertFalse("key A did not", wrap.given.any { it.contentEquals("after".toByteArray()) })
        assertArrayEquals("after".toByteArray(), opened(TunnelStore(dir, wrap, unlocked), after))
        assertEquals(TunnelStore.Name.Known("after"), TunnelStore(dir, wrap, unlocked).name(after))
    }

    /**
     * The profile's switch wraps every configuration again under its key, its text and name in one change for the
     * slot: on a locked phone key B cannot be used and nothing moves; a disk that fills at a slot leaves that slot
     * whole under its old key; a later call moves what is left, and turning the profile off brings all back to key A.
     */
    @Test
    fun the_profile_moves_each_configuration_between_the_keys_whole_or_not_at_all() {
        val store = store()
        val one = store.add("one", text) ?: error("full")
        val two = store.add("two", "second".toByteArray()) ?: error("full")
        unlocked.locked = true
        val before = files().filterKeys { it != "state" }
        assertEquals(TunnelStore.Rewrapped(emptyList(), listOf(one, two)), store.setProfile(true))
        assertEquals("locked, no configuration moved", before, files().filterKeys { it != "state" })
        assertTrue(store.state().profile)
        unlocked.locked = false
        // Two files each: the first slot's change fits, the second's does not.
        room = 3
        assertEquals(TunnelStore.Rewrapped(listOf(one), listOf(two)), store.setProfile(true))
        assertEquals(TunnelStore.Key.B, store.keyOf(one))
        assertEquals(TunnelStore.Key.A, store.keyOf(two))
        assertEquals("the second slot as it was", before.filterKeys { it.startsWith("$two.") }, files().filterKeys { it.startsWith("$two.") })
        room = Int.MAX_VALUE
        assertEquals(TunnelStore.Rewrapped(listOf(one, two), emptyList()), store.setProfile(true))
        assertEquals(TunnelStore.Key.B, store.keyOf(two))
        assertArrayEquals("second".toByteArray(), opened(TunnelStore(dir, wrap, unlocked), two))
        assertEquals(TunnelStore.Name.Known("two"), TunnelStore(dir, wrap, unlocked).name(two))
        assertEquals(TunnelStore.Rewrapped(listOf(one, two), emptyList()), store.setProfile(false))
        assertEquals(listOf(TunnelStore.Key.A, TunnelStore.Key.A), listOf(store.keyOf(one), store.keyOf(two)))
        assertArrayEquals(text, opened(TunnelStore(dir, wrap, unlocked), one))
        assertFalse(store.state().profile)
    }

    /** A replacement keeps a slot under one key whole: its kept name moves with its text to the profile's key. */
    @Test
    fun a_replacement_keeps_its_slot_under_one_key() {
        val store = store()
        unlocked.locked = true
        val slot = store.add("kept", text) ?: error("full")
        store.setProfile(true)
        unlocked.locked = false
        store.replace(slot, "newer".toByteArray(), null)
        assertEquals(TunnelStore.Key.B, store.keyOf(slot))
        assertEquals(TunnelStore.Name.Known("kept"), TunnelStore(dir, wrap, unlocked).name(slot))
        assertTrue("the name is under key B too", String(File(dir, "$slot.name").readBytes(), Charsets.ISO_8859_1).startsWith("b"))
    }

    /** A state written in plain before the fix round is read, and wrapped under key A at the next change. */
    @Test
    fun a_state_written_in_plain_before_is_read_and_wrapped_at_the_next_change() {
        val store = store()
        val slot = store.add("one", text) ?: error("full")
        File(dir, "state").writeText("order $slot\nlocal\nnext ${slot + 1}\nroute org.example.mail $slot\n")
        assertEquals(mapOf("org.example.mail" to slot), store.state().routes)
        store.setLocal(slot, true)
        assertFalse("wrapped now", "org.example.mail" in String(File(dir, "state").readBytes(), Charsets.ISO_8859_1))
        assertEquals(mapOf("org.example.mail" to slot), store.state().routes)
    }

    /** Key A erring now leaves nothing to tell of the routes: the state says it is closed, never empty. */
    @Test
    fun a_state_that_cannot_be_opened_now_is_never_read_as_empty() {
        val store = store()
        store.add("one", text, apps = setOf("org.example.mail"))
        wrap.locked = true
        try {
            TunnelStore(dir, wrap, unlocked).state()
            error("read a closed state")
        } catch (e: TunnelStore.StateClosed) {
            // Expected.
        }
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

    /**
     * Beside the wraps, a marker that holds nothing but its presence: it exists while any configuration or route
     * exists, and goes when the user removes the last (the maintainer's word of 2026-11-20).
     */
    @Test
    fun the_marker_exists_while_a_configuration_or_a_route_does() {
        val marker = File(dir, "kept")
        val store = store()
        assertFalse(marker.exists())
        val one = store.add("one", text, apps = setOf("org.example.mail")) ?: error("full")
        assertTrue(marker.exists())
        assertEquals("it holds nothing", 0L, marker.length())
        store.remove(one, appsWait = true)
        assertTrue("an app still waits for it", marker.exists())
        store.route("org.example.mail", null)
        assertFalse("the last route gone", marker.exists())
        store.route("org.example.chat", 9)
        assertTrue("a route alone", marker.exists())
        store.route("org.example.chat", null)
        assertFalse(marker.exists())
    }

    /**
     * Key A gone for good while the marker exists: the state is lost, never read as empty, so that the service holds
     * every app; the state's file deleted likewise. A data clear, which takes the marker too, reads as empty; and
     * the user's choice after a loss forgets everything (the maintainer's word of 2026-11-20).
     */
    @Test
    fun a_state_lost_for_good_is_never_read_as_empty_while_the_marker_exists() {
        val store = store()
        store.add("one", text, apps = setOf("org.example.mail"))
        wrap.destroy()
        for (fresh in listOf(true, false)) {
            try {
                (if (fresh) TunnelStore(dir, wrap, unlocked) else store).state()
                error("a lost state read")
            } catch (e: TunnelStore.StateLost) {
                // Expected.
            }
        }
        File(dir, "state").delete()
        try {
            store.state()
            error("a missing state read with the marker present")
        } catch (e: TunnelStore.StateLost) {
            // Expected.
        }
        store.forget()
        assertEquals("forgotten", TunnelStore.State(), store.state())
        assertEquals(emptyList<String>(), dir.listFiles().orEmpty().map { it.name })
        wrap.key = 0x5a
        store.add("again", text, apps = setOf("org.example.mail"))
        wrap.destroy()
        dir.deleteRecursively()
        assertEquals("a data clear reads as empty", TunnelStore.State(), TunnelStore(dir, wrap, unlocked).state())
    }
}
