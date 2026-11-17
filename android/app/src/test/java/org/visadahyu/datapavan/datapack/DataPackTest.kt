package org.visadahyu.datapavan.datapack

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DataPackTest {
    private fun pack(sequence: Int, keys: List<String> = emptyList(), revoked: List<String> = emptyList()) =
        DataPack(ByteArray(0), 0, sequence, "2026-10-30", keys, revoked, emptyMap())

    @Test
    fun `decodes the engine's layout`() {
        val bytes = "xxkeyAkeyBa/LICENSEtexta/list12".toByteArray()
        // [0, signer, payloadStart, sequence, date, keys, revoked, files], ranges into [bytes].
        val layout = intArrayOf(0, 1, 2, 7, 0, 2, 1, 2, 4, 1, 6, 4, 2, 10, 9, 19, 4, 23, 6, 29, 2)
        val reading = PackReader.decode(bytes, layout) as PackReading.Read
        assertEquals(1, reading.signer)
        val decoded = reading.pack
        assertEquals(7, decoded.sequence)
        assertEquals("xx", decoded.date)
        assertEquals(listOf("keyA"), decoded.keys)
        assertEquals(listOf("keyB"), decoded.revoked)
        assertEquals(listOf("a/LICENSE", "a/list"), decoded.paths)
        assertEquals(listOf("a"), decoded.datasets)
        assertEquals("text", decoded.text("a/LICENSE"))
        assertArrayEquals("12".toByteArray(), decoded.file("a/list"))
        assertNull(decoded.file("a/missing"))
        // SHA-256 of everything from payloadStart: "keyAkeyBa/LICENSEtexta/list12".
        assertEquals(sha256("keyAkeyBa/LICENSEtexta/list12"), decoded.fingerprint)
    }

    private fun sha256(text: String) = java.security.MessageDigest.getInstance("SHA-256")
        .digest(text.toByteArray()).joinToString("") { "%02x".format(it) }

    @Test
    fun `fingerprint of a known payload`() {
        val reading = PackReader.decode("abc".toByteArray(), intArrayOf(0, -1, 0, 1, 0, 1, 0, 0, 0)) as PackReading.Read
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", reading.pack.fingerprint)
    }

    @Test
    fun `data older than six months is stale`() {
        val today = java.time.LocalDate.of(2027, 5, 1)
        assertFalse(DataPackRules.isStale("2026-11-01", today))
        assertTrue(DataPackRules.isStale("2026-10-31", today))
        assertFalse(DataPackRules.isStale("not a date", today))
    }

    @Test
    fun `maps the engine's error codes`() {
        assertEquals(PackReading.Refused(PackRefusal.BAD_SIGNATURE), PackReader.decode(ByteArray(0), intArrayOf(4)))
        assertEquals(PackReading.Refused(PackRefusal.UNKNOWN_KEY), PackReader.decode(ByteArray(0), intArrayOf(3)))
        assertEquals(PackReading.Refused(PackRefusal.INVALID_HEADER), PackReader.decode(ByteArray(0), intArrayOf(99)))
        assertEquals(PackReading.Refused(PackRefusal.INVALID_HEADER), PackReader.decode(ByteArray(0), intArrayOf()))
    }

    @Test
    fun `trusts the pinned keys and those an imported pack announces, minus revoked ones`() {
        val bundled = pack(1, keys = listOf("K1"))
        assertEquals(listOf("K1"), DataPackRules.trustedKeys(bundled, null))
        assertEquals(listOf("K1", "K2"), DataPackRules.trustedKeys(bundled, pack(2, keys = listOf("K2", "K1"))))
        assertEquals(listOf("K2"), DataPackRules.trustedKeys(bundled, pack(3, keys = listOf("K2"), revoked = listOf("K1"))))
        assertEquals(emptyList<String>(), DataPackRules.trustedKeys(pack(1), null))
    }

    /** A pack holding [files], by path. */
    private fun pack(sequence: Int, files: Map<String, String>, date: String = "2026-11-17"): DataPack {
        var bytes = ByteArray(0)
        val ranges = files.mapValues { (_, text) ->
            val start = bytes.size
            bytes += text.toByteArray()
            start until bytes.size
        }
        return DataPack(bytes, 0, sequence, date, emptyList(), emptyList(), ranges)
    }

    @Test
    fun `reads the day a dataset was retrieved`() {
        assertEquals(java.time.LocalDate.of(2026, 10, 29), DataPackRules.retrieved("# x\nretrieved: 2026-10-29T15:10:29Z\n"))
        assertEquals(java.time.LocalDate.of(2026, 11, 9), DataPackRules.retrieved("retrieved: 2026-11-09; 15 rows added on 2026-11-11\n"))
        assertNull(DataPackRules.retrieved("retrieved: 29 October 2026\n"))
        assertNull(DataPackRules.retrieved("retrieved:\n"))
        assertNull(DataPackRules.retrieved("page: https://example.org\n"))
        // Only a line that starts with "retrieved:" dates the dataset, not one that mentions it.
        assertEquals(
            java.time.LocalDate.of(2026, 10, 29),
            DataPackRules.retrieved("what: a list\n  retrieved earlier: 2020-01-01\nretrieved: 2026-10-29\n"),
        )
        // The first retrieved line dates the dataset, as the data sources screen shows it; one SOURCE has one.
        assertEquals(java.time.LocalDate.of(2026, 10, 29), DataPackRules.retrieved("retrieved: 2026-10-29\nretrieved: 2027-01-01\n"))
        // Every dataset in the repository dates itself so, the attestation dataset's among them.
        val sources = java.io.File("../../data").listFiles()!!.map { java.io.File(it, "SOURCE") }.filter { it.isFile }
        assertTrue(sources.map { it.parentFile.name }.containsAll(listOf("attestation", "exodus")))
        for (source in sources) {
            assertTrue(source.path, DataPackRules.retrieved(source.readText()) != null)
        }
    }

    @Test
    fun `refuses a pack whose revocation list is undated`() {
        // The app tells the attestation revocation list's age from its SOURCE (ADR 0040), so a pack must date it.
        val dated = mapOf("attestation/revoked-serials.txt" to "aa\n", "attestation/SOURCE" to "retrieved: 2026-10-29T15:10:29Z\n")
        assertNull(DataPackRules.refusal(pack(4, dated), pack(3)))
        assertEquals(java.time.LocalDate.of(2026, 10, 29), pack(4, dated).retrieved("attestation"))
        for (undated in listOf(
            dated + ("attestation/SOURCE" to "retrieved: 29 October 2026\n"),
            dated - "attestation/SOURCE",
            mapOf("attestation/google-roots.pem" to ""),
        )) {
            assertEquals("$undated", PackRefusal.UNDATED_DATASET, DataPackRules.refusal(pack(4, undated), pack(3)))
        }
        // A list dated after its pack was made (2026-11-17, as these packs are) would stay fresh for ever.
        val later = dated + ("attestation/SOURCE" to "retrieved: 2026-11-18\n")
        assertEquals(PackRefusal.DATED_AFTER_PACK, DataPackRules.refusal(pack(4, later), pack(3)))
        assertNull(DataPackRules.refusal(pack(4, dated + ("attestation/SOURCE" to "retrieved: 2026-11-17\n")), pack(3)))
        // A header date that the engine lets through but no calendar has dates nothing.
        assertEquals(PackRefusal.DATED_AFTER_PACK, DataPackRules.refusal(pack(4, dated, date = "2026-02-31"), pack(3)))
        assertNull(DataPackRules.refusal(pack(4, mapOf("exodus/trackers.tsv" to "x"), date = "2026-02-31"), pack(3)))
        // A pack without the dataset leaves the APK's in use; other datasets' SOURCE is not judged here.
        assertNull(DataPackRules.refusal(pack(4, mapOf("exodus/trackers.tsv" to "x")), pack(3)))
        // An older pack is refused as older first.
        assertEquals(PackRefusal.NOT_NEWER, DataPackRules.refusal(pack(3, dated - "attestation/SOURCE"), pack(3)))
    }

    @Test
    fun `refuses a pack that is not newer`() {
        assertEquals(PackRefusal.NOT_NEWER, DataPackRules.refusal(pack(3), pack(3)))
        assertEquals(PackRefusal.NOT_NEWER, DataPackRules.refusal(pack(2), pack(3)))
        assertNull(DataPackRules.refusal(pack(4), pack(3)))
    }

    @Test
    fun `records the chain of keys back to a pinned one`() {
        val bundled = pack(1, keys = listOf("K1"))
        assertEquals(listOf("K1"), DataPackRules.chainAfter(bundled, listOf("K1", "K2"), "K1"))
        assertEquals(listOf("K1", "K2"), DataPackRules.chainAfter(bundled, listOf("K1"), "K2"))
        assertEquals(listOf("K1", "K2"), DataPackRules.chainAfter(bundled, listOf("K1", "K2", "K3"), "K2"))
    }

    @Test
    fun `keeps an imported pack only while the app's own pack allows it`() {
        val bundled = pack(2, keys = listOf("K1"))
        assertTrue(DataPackRules.keep(bundled, pack(3), listOf("K1", "K2")))
        // An app update brought newer data.
        assertFalse(DataPackRules.keep(bundled, pack(2), listOf("K1")))
        // The new build no longer pins the key the chain started from, or it revokes one on the way.
        assertFalse(DataPackRules.keep(pack(2, keys = listOf("K9")), pack(3), listOf("K1")))
        assertFalse(DataPackRules.keep(pack(2, keys = listOf("K1"), revoked = listOf("K2")), pack(3), listOf("K1", "K2")))
        assertFalse(DataPackRules.keep(bundled, pack(3), emptyList()))
    }

    @Test
    fun `joins wrapped lines of a licence notice`() {
        val notice = "SPDX-License-Identifier: CC0-1.0\n\nFirst line\nsecond line.\n\n\nfile.tsv\n    Indented\n    text.\nnext.py\n"
        assertEquals("SPDX-License-Identifier: CC0-1.0\n\nFirst line second line.\n\nfile.tsv\nIndented text.\nnext.py", reflow(notice))
    }

    @Test
    fun `reads one byte past the limit and no further`() {
        val input = ByteArray(100) { it.toByte() }
        assertEquals(41, DataPackStore.readAtMost(input.inputStream(), 40).size)
        assertArrayEquals(input, DataPackStore.readAtMost(input.inputStream(), 100))
        assertEquals(0, DataPackStore.readAtMost(ByteArray(0).inputStream(), 10).size)
    }
}
