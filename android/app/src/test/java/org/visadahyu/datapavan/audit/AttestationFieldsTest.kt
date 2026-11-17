package org.visadahyu.datapavan.audit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class AttestationFieldsTest {
    /** The record `encodes_the_record_the_app_decodes` in `core/jni` writes: one layout on both sides. */
    private val record = (
        "01" +
            "000000000000012c" +
            "0000000000000001" +
            "0000000000000001" +
            "0000000000000001" +
            "0000000000027100" +
            "000000000003170b" +
            "0000000000031706" +
            "ffffffffffffffff" +
            "00000003" + "616263" +
            "00000002" + "aabb" +
            "ffffffff"
        ).chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `reads the record the engine writes`() {
        val fields = requireNotNull(AttestationFields.decode(record))
        assertEquals(300L, fields.attestationVersion)
        assertEquals(1, fields.securityLevel)
        assertEquals(true, fields.deviceLocked)
        assertEquals(1, fields.verifiedBoot)
        assertEquals(160_000, fields.osVersion)
        assertEquals(202_507, fields.osPatchLevel)
        assertEquals(202_502, fields.vendorPatchLevel)
        assertNull(fields.bootPatchLevel)
        assertArrayEquals("abc".toByteArray(), fields.challenge)
        assertArrayEquals(byteArrayOf(0xaa.toByte(), 0xbb.toByte()), fields.verifiedBootKey)
        assertNull(fields.verifiedBootHash)
    }

    @Test
    fun `refuses anything else`() {
        assertNull(AttestationFields.decode(ByteArray(0)))
        assertNull(AttestationFields.decode(record.copyOf(record.size - 1)))
        assertNull(AttestationFields.decode(record + 0))
        assertNull(AttestationFields.decode(record.copyOf().also { it[0] = 2 }))
        // A length beyond the record, a negative one other than -1, and a challenge that is absent.
        assertNull(AttestationFields.decode(record.copyOf().also { it[65 + 3] = 0x7f }))
        assertNull(AttestationFields.decode(record.copyOf().also { it[65] = 0xfe.toByte() }))
        val noChallenge = record.copyOf(65) + byteArrayOf(-1, -1, -1, -1) + record.copyOfRange(72, record.size)
        assertNull(AttestationFields.decode(noChallenge))
        // A value too large for an Int, and values outside their ranges.
        assertNull(AttestationFields.decode(record.copyOf().also { it[33] = 1 }))
        assertNull(AttestationFields.decode(record.copyOf().also { it[16] = 3 }))
        assertNull(AttestationFields.decode(record.copyOf().also { it[24] = 2 }))
        assertNull(AttestationFields.decode(record.copyOf().also { it[32] = 4 }))
    }
}
