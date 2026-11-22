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

    /**
     * The label first in the alphabet without regard to case names a shared UID (review c1 of W5's third part,
     * screens, m5); a UID no package holds is Android's own below the first of apps', else an app since
     * removed; flows with no UID are no app Android named (nit 7).
     */
    @Test
    fun aUidIsNamedByItsKind() {
        val names = AppNames(
            packagesFor = { if (it == 10_200) listOf("a.b", "c.d") else emptyList() },
            labelOf = { mapOf("a.b" to "Zeta", "c.d" to "alpha")[it] },
            installedAt = { null },
        )
        assertEquals("alpha", names.of(10_200).label)
        assertEquals(AppNames.Kind.NAMED, names.of(10_200).kind)
        assertEquals(AppNames.Kind.SYSTEM, names.of(0).kind)
        assertEquals(AppNames.Kind.SYSTEM, names.of(9_999).kind)
        assertEquals(AppNames.Kind.REMOVED, names.of(10_000).kind)
        assertEquals(AppNames.Kind.UNNAMED, names.of(null).kind)
    }

    /** A package with no label is listed by its name. */
    @Test
    fun aPackageWithNoLabelIsNamedByItsName() {
        val names = AppNames({ listOf("org.example.quiet") }, { null }, { null })
        assertEquals("org.example.quiet", names.of(5).label)
    }
}
