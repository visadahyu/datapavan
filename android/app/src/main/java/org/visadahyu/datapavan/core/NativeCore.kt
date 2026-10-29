package org.visadahyu.datapavan.core

/**
 * Entry point to the Rust engine (`libdatapavan.so`).
 *
 * The JNI surface is kept deliberately small: every function here is a boundary where
 * untrusted data may cross, so each one must be reviewed like a public API.
 */
internal object NativeCore {
    init {
        System.loadLibrary("datapavan")
    }

    /** Version of the Rust engine, e.g. `0.1.0`. */
    @JvmStatic
    external fun version(): String

    /**
     * Decodes the `KeyDescription` extension of a key-attestation certificate (untrusted input,
     * parsed in Rust). Returns `[attestationVersion, securityLevel, deviceLocked, verifiedBoot,
     * osPatchLevel]` with -1 for an absent value, and throws a `RuntimeException` on malformed input.
     */
    @JvmStatic
    external fun parseAttestation(extension: ByteArray): LongArray

    /**
     * Reads the tracker signatures (`data/exodus/trackers.tsv`) into the engine for [scanDex],
     * replacing any loaded before, and returns the number of trackers. Throws a `RuntimeException`
     * on malformed data.
     */
    @JvmStatic
    external fun loadTrackers(tsv: String): Int

    /**
     * Finds the loaded trackers in one DEX file of another app (untrusted input, parsed in Rust).
     * Returns `[n, e1..en, r1..rm]`: n embedded εxodus ids, then the referenced ids, which include
     * the embedded ones. Throws a `RuntimeException` on a malformed file.
     */
    @JvmStatic
    external fun scanDex(dex: ByteArray): IntArray
}
