package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.BuildConfig

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

    /**
     * Each edition's genuine copy is judged genuine by what it asks for, and a copy that asks for what its
     * edition never does is not: the internet in Basic; the camera, microphone, location, contacts,
     * messages or call log in Advanced, which has the internet (review b2 of W5's second part, fresh, M0:
     * Advanced's genuine copy was told to uninstall itself). The permissions are the build's allowlists.
     */
    @Test
    fun eachEditionsGenuineCopyIsJudgedGenuine() {
        val basic = listOf(
            "android.permission.QUERY_ALL_PACKAGES", "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.ACCESS_NETWORK_STATE", "android.permission.HIDE_OVERLAY_WINDOWS",
        )
        val advanced = basic + listOf(
            "android.permission.INTERNET", "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.POST_NOTIFICATIONS", "android.permission.ACCESS_LOCAL_NETWORK",
        )
        val neverInBasic = listOf("android.permission.INTERNET")
        val neverInAdvanced = listOf(
            "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS", "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS",
            "RECEIVE_WAP_PUSH", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
        ).map { "android.permission.$it" }
        assertFalse(asksForWhatItNever(basic, neverInBasic))
        assertFalse("Advanced's own internet", asksForWhatItNever(advanced, neverInAdvanced))
        assertTrue(asksForWhatItNever(basic + "android.permission.INTERNET", neverInBasic))
        assertTrue(asksForWhatItNever(advanced + "android.permission.READ_SMS", neverInAdvanced))
        // This build's own list is its edition's.
        assertEquals(if (BuildConfig.ADVANCED) neverInAdvanced else neverInBasic, neverRequested())
    }
}
