package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class OwnCopyTest {
    @Test
    fun aFingerprintReadsAsAppVerifierShowsItInFourLines() {
        val sha256 = "277e0184458e1eedd38399bf64192883a60f718fb800ba090cf41b7879cc054d"
        assertEquals(
            "27:7E:01:84:45:8E:1E:ED:\nD3:83:99:BF:64:19:28:83:\nA6:0F:71:8F:B8:00:BA:09:\n0C:F4:1B:78:79:CC:05:4D",
            fingerprint(sha256),
        )
    }
}
