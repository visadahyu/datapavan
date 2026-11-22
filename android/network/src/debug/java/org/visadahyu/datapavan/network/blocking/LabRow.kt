package org.visadahyu.datapavan.network.blocking

/**
 * Debug builds only (W8, part 3a; the brief's point 9): one row of the graded table for the lab's own names, appended
 * to `blocking/hosts.tsv` before the table is handed to the engine and read here, so that part 3a's emulator check
 * blocks the project's own fixture by the same path as a tracker, with no real tracker's host. Release builds carry
 * none: their LabRow, in src/release, is empty.
 */
object LabRow {
    /** The row, nine tab-separated columns, with its line's end. */
    const val ROW = "tracker.blocklab.home.arpa\torg.visadahyu.datapavan:blockfixture\torg.visadahyu.datapavan.blockfixture.\t" +
        "block\t-\tThe lab's stand-in tracker (debug builds only)\tcode\thttps://github.com/mehdashti/datapavan\t2026-11-21\n"
}
