package org.visadahyu.datapavan.network

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.visadahyu.datapavan.network.tunnel.Import

/**
 * The network screen keeps the import's confirmation across its recreation, and zeroes the configuration's bytes when
 * the screen finishes (W7, part 2, fix round, screens review M1): the model outlives a rotation, a dark-mode switch or
 * a font change, which keep its store, and is cleared when the screen is gone for good, which clears it.
 */
class TunnelModelTest {
    private val described = Import.read(
        "ok\nendpoint 192.0.2.1 51820\naddress 10.0.0.2/32\ndns 10.0.0.1\nallowed 0.0.0.0/0\neverything 1\npreshared 0\nmtu 1420",
    ) as Import.Described

    @Test
    fun the_confirmation_outlives_a_recreation_and_is_zeroed_when_the_screen_finishes() {
        val store = ViewModelStore()
        val first = ViewModelProvider.create(store)[TunnelModel::class]
        val text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n".toByteArray()
        first.held.hold(Import.Pending(text, described, "one"))
        // The screen made anew finds the same model in the same store.
        val again = ViewModelProvider.create(store)[TunnelModel::class]
        assertSame(first, again)
        assertSame(text, again.held.now?.text)
        store.clear()
        assertNull(again.held.now)
        assertTrue("zeroed", text.all { it == 0.toByte() })
    }
}
