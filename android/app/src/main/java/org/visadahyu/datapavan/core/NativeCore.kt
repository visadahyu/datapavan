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
}
