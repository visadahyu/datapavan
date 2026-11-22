package org.visadahyu.datapavan.network.activity

import android.content.pm.PackageManager

/**
 * The apps behind a UID, as "Now" and the history name them (ADR 0046, decision 2 (d)): the label of the
 * packages that hold it, all of them where several share one UID, which count together (decision 5); none
 * for a UID no package holds now (an app since removed) or for flows Android named no app for. Read once
 * per UID while the view is open, since a package installed again gets a new UID.
 */
internal class AppNames(
    private val packagesFor: (Int) -> List<String>,
    private val labelOf: (String) -> String?,
    private val installedAt: (String) -> Long?,
) {
    /** A UID's apps: the label to show, the packages by name, and when the first of them was installed. */
    data class Named(val uid: Int?, val label: String?, val packages: List<String>, val installedAt: Long?) {
        /** What the row is called by when no package names it. */
        val kind: Kind
            get() = when {
                uid == null -> Kind.UNNAMED
                packages.isNotEmpty() -> Kind.NAMED
                // A UID below the first of apps' is Android's own, root and the system's services among them,
                // not an app since removed (review c1 of W5's third part, screens, nit 7).
                uid < FIRST_APPLICATION_UID -> Kind.SYSTEM
                else -> Kind.REMOVED
            }
    }

    /** By what a UID is named: its packages, Android's own, an app since removed, or no app Android named. */
    enum class Kind { NAMED, SYSTEM, REMOVED, UNNAMED }

    private val known = HashMap<Int?, Named>()

    fun of(uid: Int?): Named = known.getOrPut(uid) { read(uid) }

    private fun read(uid: Int?): Named {
        if (uid == null) return Named(null, null, emptyList(), null)
        val packages = packagesFor(uid).sorted()
        val labels = packages.map { labelOf(it) ?: it }
        // The label first in the alphabet names the row; every package is listed under it.
        val label = labels.minByOrNull { it.lowercase() }
        val installed = packages.mapNotNull(installedAt).minOrNull()
        return Named(uid, label, packages, installed)
    }

    companion object {
        /** `android.os.Process.FIRST_APPLICATION_UID`: UIDs below it are Android's own. */
        const val FIRST_APPLICATION_UID = 10_000

        /** Names read from Android's package manager. */
        fun of(packageManager: PackageManager): AppNames = AppNames(
            packagesFor = { uid -> packageManager.getPackagesForUid(uid)?.toList().orEmpty() },
            labelOf = { name ->
                try {
                    packageManager.getApplicationLabel(packageManager.getApplicationInfo(name, 0)).toString()
                } catch (e: PackageManager.NameNotFoundException) {
                    null
                }
            },
            installedAt = { name ->
                try {
                    packageManager.getPackageInfo(name, 0).firstInstallTime
                } catch (e: PackageManager.NameNotFoundException) {
                    null
                }
            },
        )
    }
}
