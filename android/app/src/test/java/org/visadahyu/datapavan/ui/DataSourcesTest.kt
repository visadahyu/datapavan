package org.visadahyu.datapavan.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import org.visadahyu.datapavan.R
import org.visadahyu.datapavan.datapack.PackRefusal

/** What the data sources screen says of each refused pack. */
class DataSourcesTest {
    @Test
    fun `each refusal says why`() {
        val expected = mapOf(
            PackRefusal.TOO_LARGE to R.string.data_refused_too_large,
            PackRefusal.NOT_SIGNED to R.string.data_refused_not_signed,
            PackRefusal.UNKNOWN_KEY to R.string.data_refused_unknown_key,
            PackRefusal.BAD_SIGNATURE to R.string.data_refused_bad_signature,
            PackRefusal.NOT_PACK to R.string.data_refused_invalid,
            PackRefusal.UNSUPPORTED_VERSION to R.string.data_refused_unsupported,
            PackRefusal.INVALID_HEADER to R.string.data_refused_invalid,
            PackRefusal.INVALID_KEY to R.string.data_refused_invalid,
            PackRefusal.NOT_NEWER to R.string.data_refused_not_newer,
            PackRefusal.NO_TRUSTED_KEYS to R.string.data_import_unavailable,
            PackRefusal.UNREADABLE to R.string.data_refused_unreadable,
            // Signed and whole, so not "damaged": it says the list's date is missing.
            PackRefusal.UNDATED_DATASET to R.string.data_refused_undated,
        )
        assertEquals(PackRefusal.entries.toSet(), expected.keys)
        assertEquals(expected, PackRefusal.entries.associateWith(::refusalText))
    }
}
