package org.visadahyu.datapavan.datapack

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DataPackStoreTest {
    /** A reader that refuses every pack, as for one whose chain's last key did not sign it. */
    private val refusing = object : PackNative {
        override fun readDataPack(pack: ByteArray, keys: String): IntArray = intArrayOf(PackRefusal.BAD_SIGNATURE.code)
        override fun readDataPayload(payload: ByteArray): IntArray = intArrayOf(PackRefusal.NOT_PACK.code)
    }

    private fun installed(): File = Files.createTempDirectory("datapack").toFile().also {
        File(it, "installed.pack").writeBytes(byteArrayOf(1, 2, 3))
        File(it, "installed.chain").writeText("RWSkey\n")
    }

    /**
     * A pack that no longer applies is deleted only by a store that cleans, the audit's; Watch's process reads
     * without deleting, so that it cannot undo an import the audit is writing that moment (review c1 of W5's
     * third part, engine, m5).
     */
    @Test
    fun onlyAStoreThatCleansDeletesAPackThatNoLongerApplies() {
        val reading = installed()
        assertNull(DataPackStore.loadInstalled(reading, refusing, { error("not asked") }, cleans = false))
        assertTrue(File(reading, "installed.pack").exists() && File(reading, "installed.chain").exists())
        val cleaning = installed()
        assertNull(DataPackStore.loadInstalled(cleaning, refusing, { error("not asked") }, cleans = true))
        assertFalse(File(cleaning, "installed.pack").exists() || File(cleaning, "installed.chain").exists())
        reading.deleteRecursively()
        cleaning.deleteRecursively()
    }
}
