package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class OwnCopyTest {
    @Test
    fun aFingerprintReadsAsAppVerifierShowsItInFourLines() {
        // The certificate digest of a throwaway debug key made for the emulator captures (core/engine/testdata/emulator),
        // not any developer's own key.
        val sha256 = "dc0043e7b001dc980941a76509765bea2d945010b9adeab0d6dcae9c95827e9a"
        assertEquals(
            "DC:00:43:E7:B0:01:DC:98:\n09:41:A7:65:09:76:5B:EA:\n2D:94:50:10:B9:AD:EA:B0:\nD6:DC:AE:9C:95:82:7E:9A",
            fingerprint(sha256),
        )
    }
}
