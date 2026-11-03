package org.visadahyu.datapavan.audit

import java.util.Locale

/** The app list's filters (ADR 0027, point 1), in the order of the chips: the default, then all apps, then the narrower ones. */
enum class AppFilter { WITH_FINDINGS, ALL, TRACKERS, CONTROL, NOT_OPENED, PREINSTALLED, VPN_PROXY }

/** The app list's orders. */
enum class AppSort { URGENCY, NAME, DATA_USE, INSTALLED }

/** One app as the list sees it. */
data class ListedApp(
    val app: AppFacts,
    val findings: List<FindingKind>,
    /** The tracker scan of the app, or null while it runs. */
    val trackers: AppTrackers? = null,
    /** On the list of VPN, proxy and circumvention apps (ADR 0018). */
    val carriesOthers: Boolean = false,
)

/** The app list's search, filters and orders: pure, so that they can be unit-tested. */
object AppQuery {
    private val CONTROL = setOf(SpecialAccess.ACCESSIBILITY, SpecialAccess.NOTIFICATION_LISTENER, SpecialAccess.DEVICE_ADMIN)

    /** [usage] is null without usage access; then no app counts as not opened. */
    fun matches(filter: AppFilter, item: ListedApp, usage: UsageFacts?): Boolean {
        val app = item.app
        return when (filter) {
            AppFilter.WITH_FINDINGS -> item.findings.any { it.severity != Severity.INFO }
            AppFilter.TRACKERS -> item.trackers?.embedded?.isNotEmpty() == true
            AppFilter.CONTROL -> app.special.any { it in CONTROL } && !app.isSystem
            AppFilter.NOT_OPENED -> usage != null && Dormancy.notOpened(app, usage).days >= Dormancy.DAYS && (!app.isSystem || app.launcherIcon)
            AppFilter.PREINSTALLED -> app.isSystem
            AppFilter.VPN_PROXY -> app.isVpnApp || item.carriesOthers
            AppFilter.ALL -> true
        }
    }

    /** Whether the label or the package contains [query], ignoring case; an empty query matches all. */
    fun search(query: String, app: AppFacts): Boolean {
        val q = query.trim().lowercase(Locale.ROOT)
        if (q.isEmpty()) return true
        return app.packageName.lowercase(Locale.ROOT).contains(q) || app.label?.lowercase(Locale.ROOT)?.contains(q) == true
    }

    /** The apps that pass [filter] and [query], in [sort]'s order. */
    fun list(items: List<ListedApp>, filter: AppFilter, query: String, sort: AppSort, usage: UsageFacts?): List<ListedApp> =
        items.filter { matches(filter, it, usage) && search(query, it.app) }.sortedWith(order(sort, usage))

    /** How many apps each filter holds, for its chip. */
    fun counts(items: List<ListedApp>, usage: UsageFacts?): Map<AppFilter, Int> =
        AppFilter.entries.associateWith { filter -> items.count { matches(filter, it, usage) } }

    private fun name(item: ListedApp) = (item.app.label ?: item.app.packageName).lowercase(Locale.ROOT)

    private fun order(sort: AppSort, usage: UsageFacts?): Comparator<ListedApp> = when (sort) {
        AppSort.URGENCY -> compareBy<ListedApp> { it.findings.firstOrNull()?.severity?.ordinal ?: Int.MAX_VALUE }
            .thenByDescending { it.findings.size }
            .thenBy(::name)
        AppSort.NAME -> compareBy(::name)
        // The 30 days' total; without usage access, by name.
        AppSort.DATA_USE -> compareByDescending<ListedApp> { usage?.network(UsageFacts.PERIODS.first(), it.app.uid)?.total ?: 0L }.thenBy(::name)
        AppSort.INSTALLED -> compareByDescending<ListedApp> { it.app.firstInstall }.thenBy(::name)
    }
}
