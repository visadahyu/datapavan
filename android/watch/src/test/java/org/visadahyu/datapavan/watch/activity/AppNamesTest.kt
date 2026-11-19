package org.visadahyu.datapavan.watch.activity

import org.junit.Assert.assertEquals
import org.junit.Test

class AppNamesTest {
    /** A UID's apps: the label first in the alphabet names it, every package is listed, the first install counts. */
    @Test
    fun aUidIsNamedByItsPackages() {
        var asked = 0
        val names = AppNames(
            packagesFor = { uid ->
                asked++
                when (uid) {
                    1_000 -> listOf("com.android.settings", "android")
                    10_123 -> listOf("org.example.mail")
                    else -> emptyList()
                }
            },
            labelOf = { mapOf("android" to "Android System", "com.android.settings" to "Settings", "org.example.mail" to "mail").get(it) },
            installedAt = { mapOf("android" to 50L, "com.android.settings" to 10L, "org.example.mail" to 99L).get(it) },
        )
        assertEquals(AppNames.Named(1_000, "Android System", listOf("android", "com.android.settings"), 10L), names.of(1_000))
        assertEquals(AppNames.Named(10_123, "mail", listOf("org.example.mail"), 99L), names.of(10_123))
        // No package holds it: an app since removed, with no label; no UID: what Android named no app for.
        assertEquals(AppNames.Named(10_999, null, emptyList(), null), names.of(10_999))
        assertEquals(AppNames.Named(null, null, emptyList(), null), names.of(null))
        // Read once per UID while the view is open.
        names.of(1_000)
        assertEquals(3, asked)
    }

    /** A package with no label is listed by its name. */
    @Test
    fun aPackageWithNoLabelIsNamedByItsName() {
        val names = AppNames({ listOf("org.example.quiet") }, { null }, { null })
        assertEquals("org.example.quiet", names.of(5).label)
    }
}
