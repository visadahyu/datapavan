package org.visadahyu.datapavan.audit

import java.nio.BufferUnderflowException
import java.nio.ByteBuffer

/**
 * The fields of a key attestation's KeyDescription, as the Rust engine decodes them in the parsers' isolated
 * process (`core/jni`, `encode`). Absent values are null. With a [securityLevel] of 1 or 2, the values from
 * [deviceLocked] on come from the list the secure hardware enforces itself, never from the one the system
 * writes; with 0, everything is the system's word.
 */
class AttestationFields(
    val attestationVersion: Long,
    /** 0 software, 1 trusted execution environment, 2 secure chip: the weaker of the attestation's and the key's. */
    val securityLevel: Int,
    val deviceLocked: Boolean?,
    /** 0 verified, 1 self-signed, 2 unverified, 3 failed. */
    val verifiedBoot: Int?,
    /** Android's version as `MMmmpp`. */
    val osVersion: Int?,
    /** Patch levels as `YYYYMM`. */
    val osPatchLevel: Int?,
    val vendorPatchLevel: Int?,
    val bootPatchLevel: Int?,
    /** The challenge the key was generated with, which the app compares with its own. */
    val challenge: ByteArray,
    /** A digest of the key that verified the system. */
    val verifiedBootKey: ByteArray?,
    /** A digest of the verified boot images. */
    val verifiedBootHash: ByteArray?,
) {
    companion object {
        /** Format of the record, which `core/jni` writes. */
        private const val FORMAT: Byte = 1

        /**
         * Reads the record that NativeCore.parseAttestation returns, or null when it is not one: it comes from
         * the isolated process, so it is checked like any input.
         */
        fun decode(record: ByteArray): AttestationFields? = try {
            val buffer = ByteBuffer.wrap(record)
            if (buffer.get() != FORMAT) {
                null
            } else {
                val numbers = LongArray(8) { buffer.getLong() }
                val bytes = List(3) { bytes(buffer) }
                val challenge = bytes[0]
                val valid = numbers[0] in 0..UInt.MAX_VALUE.toLong() && numbers[1] in 0..2 && numbers[2] in -1..1 &&
                    numbers[3] in -1..3 && numbers.drop(4).all { it in -1..Int.MAX_VALUE.toLong() }
                if (buffer.hasRemaining() || challenge == null || !valid) {
                    null
                } else {
                    fun int(index: Int) = numbers[index].takeIf { it >= 0 }?.toInt()
                    AttestationFields(
                        attestationVersion = numbers[0],
                        securityLevel = numbers[1].toInt(),
                        deviceLocked = int(2)?.let { it == 1 },
                        verifiedBoot = int(3),
                        osVersion = int(4),
                        osPatchLevel = int(5),
                        vendorPatchLevel = int(6),
                        bootPatchLevel = int(7),
                        challenge = challenge,
                        verifiedBootKey = bytes[1],
                        verifiedBootHash = bytes[2],
                    )
                }
            }
        } catch (_: BufferUnderflowException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }

        private fun bytes(buffer: ByteBuffer): ByteArray? {
            val length = buffer.getInt()
            if (length == -1) return null
            require(length >= 0 && length <= buffer.remaining())
            return ByteArray(length).also { buffer.get(it) }
        }
    }
}
