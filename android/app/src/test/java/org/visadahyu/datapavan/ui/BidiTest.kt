package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BidiTest {
    @Test
    fun wrapsTokenInLeftToRightIsolate() {
        assertEquals("⁦example.com⁩", isolateLtr("example.com"))
    }

    @Test
    fun keepsTokenContentUnchanged() {
        val token = "192.168.1.26"
        val wrapped = isolateLtr(token)
        assertEquals(token, wrapped.substring(1, wrapped.length - 1))
        assertTrue(wrapped.first() == '⁦' && wrapped.last() == '⁩')
    }
}
