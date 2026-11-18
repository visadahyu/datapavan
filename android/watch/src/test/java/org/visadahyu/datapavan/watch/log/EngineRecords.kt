package org.visadahyu.datapavan.watch.log

/**
 * The batch of records the engine itself wrote for these tests (`engine-records.hex`, beside this class
 * among the test resources): its Rust test `the_kotlin_sides_fixture_is_what_the_engine_writes` fails
 * when the engine writes otherwise, so the reader here and the writer there cannot drift apart unseen.
 */
object EngineRecords {
    /** The batch, as the engine hands it to the log. */
    val batch: ByteArray by lazy {
        val text = checkNotNull(EngineRecords::class.java.getResource("engine-records.hex")) { "engine-records.hex is missing" }
            .readText()
        val hex = text.lineSequence().filterNot { it.startsWith("#") }.joinToString("") { it.trim() }
        ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    }

    /** Its records, read, each with its bytes. */
    val records: List<Pair<LogRecord, ByteArray>> by lazy { LogRecord.batch(batch) }
}
