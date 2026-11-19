package org.visadahyu.datapavan.watch.activity

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
    data class Named(val uid: Int?, val label: String?, val packages: List<String>, val installedAt: Long?)

    private val known = HashMap<Int?, Named>()

    fun of(uid: Int?): Named = known.getOrPut(uid) { read(uid) }

    /** The UID of [packageName] among those named so far, or null. */
    fun uidOf(packageName: String): Int? = known.values.firstOrNull { packageName in it.packages }?.uid

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
