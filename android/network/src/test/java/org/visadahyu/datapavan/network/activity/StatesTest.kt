package org.visadahyu.datapavan.network.activity

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test

class StatesTest {
    private val t = 1_794_953_400_000L

    /** Readings of each kind, as the tracker hands them to the engine. */
    private fun messages(): List<ByteArray> = listOf(
        States.encode(
            UsageStates.Reading(
                t, t + 60_000,
                listOf(
                    UsageStates.Interval(10_123, t, t + 30_000, States.IN_USE),
                    UsageStates.Interval(10_124, t + 2_000, t + 60_000, States.NOTIFICATION),
                ),
                UsageStates.Screen(true, t - 5_000, t - 65_000),
            ),
        ),
        States.encode(t + 60_000, t + 120_000, States.NO_ACCESS, UsageStates.Screen(false, t - 5_000, t + 61_000), emptyList()),
        States.encode(t + 120_000, t + 180_000, States.LOCKED, UsageStates.Screen(null, null, t + 121_000), emptyList()),
    )

    /**
     * The messages the engine reads are what this side writes, byte for byte (`states.hex`, read by the
     * engine's test `the_kotlin_sides_states_are_read_as_written`): a change of the format fails here until
     * the fixture is written anew, with DATAPAVAN_WRITE_FIXTURE=1, and then fails the engine's test until it
     * reads them.
     */
    @Test
    fun theEngineReadsWhatThisSideWrites() {
        val text = buildString {
            append("# Readings of the apps' states as Watch's Kotlin side writes them (States.kt; core/net/src/states.rs,\n")
            append("# version 2), one a line, in hex. Written by StatesTest, which fails when this side writes otherwise;\n")
            append("# run it with DATAPAVAN_WRITE_FIXTURE=1 to write it anew. Read by the engine's test\n")
            append("# the_kotlin_sides_states_are_read_as_written. Not edited by hand.\n")
            for (message in messages()) append(message.joinToString("") { "%02x".format(it) }).append('\n')
        }
        val file = File("src/test/resources/org/visadahyu/datapavan/network/activity/states.hex")
        if (System.getenv("DATAPAVAN_WRITE_FIXTURE") != null) file.writeText(text)
        assertEquals("states.hex is not what this side writes: run StatesTest with DATAPAVAN_WRITE_FIXTURE=1", text, file.readText())
    }

    /** The layout, field by field, as the engine's test `a_message_is_laid_out_field_by_field` has it. */
    @Test
    fun aReadingIsLaidOutFieldByField() {
        val message = messages()[0]
        assertEquals(39 + 2 * 21, message.size)
        assertEquals(listOf<Byte>(2), message.take(1))
        assertEquals(0.toByte() to 1.toByte(), message[17] to message[18])
        assertEquals(t - 65_000, java.nio.ByteBuffer.wrap(message, 27, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).long)
        assertEquals(2, message[35].toInt())
        assertEquals(1.toByte() to 2.toByte(), message[39 + 20] to message[39 + 21 + 20])
        val nothing = messages()[1]
        assertEquals(listOf(1, 0), listOf(nothing[17].toInt(), nothing[18].toInt()))
        // The screen is off: when it came on is not told, when it went off is.
        assertEquals(List(8) { 0.toByte() }, nothing.slice(19 until 27))
        assertEquals(t + 61_000, java.nio.ByteBuffer.wrap(nothing, 27, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).long)
        // A screen not known tells no time it went off, which the engine would refuse.
        assertEquals(List(8) { 0.toByte() }, messages()[2].slice(27 until 35))
    }

    /** When the screen went off is told only where the engine takes it (review of W5's third part's rule). */
    @Test
    fun theScreenOffTimeIsToldOnlyWhereTheEngineTakesIt() {
        assertEquals(10L, States.offSince(UsageStates.Screen(false, null, 10)))
        assertEquals(10L, States.offSince(UsageStates.Screen(true, 10, 10)))
        assertEquals(null, States.offSince(UsageStates.Screen(true, null, 10)))
        assertEquals(null, States.offSince(UsageStates.Screen(true, 9, 10)))
        assertEquals(null, States.offSince(UsageStates.Screen(null, null, 10)))
        assertEquals(null, States.offSince(UsageStates.Screen(false, null, null)))
    }
}
