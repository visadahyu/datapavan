package org.visadahyu.datapavan.audit

import java.util.Locale

/** What an action removes (ADR 0026, point 3); the queue shows the classes in this order. */
enum class PlanClass { A, B, C }

/** Why an item is in the remediation plan (ADR 0026, point 2), with the class of what its action removes. */
enum class PlanReason(val planClass: PlanClass) {
    WIRELESS_DEBUGGING(PlanClass.A),
    CERTIFICATE_AUTHORITY(PlanClass.A),

    /** Accessibility, a notification listener or device admin, held by a VPN app or an app the user installed. */
    CONTROL_ACCESS(PlanClass.A),

    /** Modified against the official list, or carrying an untrusted system key. */
    DOUBTFUL_COPY(PlanClass.A),

    /** Not opened for 90 days, and holds a sensor permission, special access or VPN permission. */
    NOT_OPENED_SENSITIVE(PlanClass.B),
    INSTALLS_APPS(PlanClass.B),
    TRAFFIC_SHARING(PlanClass.B),
    USB_DEBUGGING(PlanClass.B),

    /** Not opened for 90 days, and holds another sensitive permission or used data in the background. */
    NOT_OPENED_OTHER(PlanClass.C),

    /** A preinstalled app not opened for 90 days, or a preinstalled data collector: the strict level only. */
    PREINSTALLED(PlanClass.C),
}

/** How much the plan includes (ADR 0026, point 4). */
enum class PlanLevel {
    LIGHT,
    MEDIUM,
    STRICT,
    ;

    fun includes(reason: PlanReason): Boolean = when (this) {
        LIGHT -> reason.planClass == PlanClass.A || reason == PlanReason.NOT_OPENED_SENSITIVE
        MEDIUM -> reason != PlanReason.PREINSTALLED
        STRICT -> true
    }
}

/** A system screen that an item hands off to (ADR 0026, point 1). */
enum class Screen {
    APP_INFO,
    UNUSED_APP_SETTING,
    ACCESSIBILITY,
    NOTIFICATION_LISTENER,
    DEVICE_ADMINS,
    INSTALL_UNKNOWN_APPS,
    OVERLAY,
    USAGE_ACCESS,
    ALL_FILES,
    BATTERY,
    VPN,
    DEVELOPER_OPTIONS,
    SECURITY,
}

/** The one extra tap some items need before their screen opens (ADR 0026, points 4 and 6). */
enum class Care {
    /** Changing control access can alert someone who installed the app to watch the user. */
    CONTROL,

    /** A preinstalled app that Datapavan has not tested on this phone. */
    UNTESTED,
}

data class PlanItem(
    val reason: PlanReason,
    /** Null for the phone's own items. */
    val app: AppFacts?,
    /** The screens that can remove it, the most useful first. */
    val screens: List<Screen>,
    /** The app contains advertising, analytics or profiling trackers. */
    val trackerPurpose: Boolean = false,
    /** For apps not opened for 90 days: how many days. */
    val notOpenedDays: Long? = null,
    /** Other reasons for which the same app is in the plan, shown on its card. */
    val also: List<PlanReason> = emptyList(),
) {
    /** Identifies the item across sessions, for the journal. */
    val key: String get() = key(reason, app?.packageName)

    val care: Care?
        get() = when {
            reason == PlanReason.CONTROL_ACCESS || PlanReason.CONTROL_ACCESS in also -> Care.CONTROL
            reason == PlanReason.PREINSTALLED || PlanReason.PREINSTALLED in also -> Care.UNTESTED
            else -> null
        }

    companion object {
        fun key(reason: PlanReason, packageName: String?) = "${reason.name}:${packageName.orEmpty()}"
    }
}

/** Why the safety floor leaves an app alone (ADR 0026, point 5). */
enum class FloorReason {
    // Computed on the phone.
    HOME,
    PHONE,
    SMS,
    BROWSER,
    KEYBOARD,
    SCREEN_READER,
    DEVICE_OWNER,
    PREINSTALLED_ADMIN,
    INSTALLER,
    PERMISSION_CONTROLLER,
    DATAPAVAN,

    // The functions of the deny-list in data/remediation/floor.tsv.
    CORE,
    TELEPHONY,
    EMERGENCY,
    UPDATES,
    SETUP,
    TIME_ZONE,
    CONNECTIVITY,
    DEVICE_LOCK,
}

/**
 * The deny-list of the safety floor, by function (`data/remediation/floor.tsv`, ADR 0026). A pattern is a
 * package name, or a prefix followed by `*`; the vendor is `*` or a phone maker as Android names it.
 */
class SafetyFloor(private val rows: List<Row>) {
    data class Row(val pattern: String, val vendor: String, val function: FloorReason)

    fun reason(packageName: String, manufacturer: String): FloorReason? {
        val maker = manufacturer.lowercase(Locale.ROOT)
        return rows.firstOrNull { row ->
            (row.vendor == "*" || row.vendor == maker) &&
                if (row.pattern.endsWith('*')) packageName.startsWith(row.pattern.dropLast(1)) else packageName == row.pattern
        }?.function
    }

    companion object {
        const val PATH = "remediation/floor.tsv"

        /** Columns: pattern, vendor, function, source, checked; comments start with `#`; unknown functions are skipped. */
        fun parse(tsv: String): SafetyFloor = SafetyFloor(
            tsv.lineSequence()
                .filter { it.isNotBlank() && !it.startsWith("#") }
                .mapNotNull { line ->
                    val columns = line.split('\t')
                    if (columns.size != 5 || columns[0].isEmpty()) return@mapNotNull null
                    val function = FloorReason.entries.firstOrNull { it.name == columns[2].uppercase(Locale.ROOT).replace('-', '_') }
                        ?: return@mapNotNull null
                    Row(columns[0], columns[1].lowercase(Locale.ROOT), function)
                }
                .toList(),
        )
    }
}

/** Everything the plan is made from: the audit's findings and, with usage access, when apps were last opened. */
data class PlanInput(
    val device: List<FindingKind>,
    val apps: List<Pair<AppFacts, List<FindingKind>>>,
    /** Null without usage access; then no item about apps not opened. */
    val usage: UsageFacts?,
    /** The tracker scan, or null while it runs. */
    val trackers: Map<String, AppTrackers>?,
    val trackerInfo: Map<Int, TrackerInfo>,
    /** The safety floor's reason for each protected app. */
    val floor: Map<String, FloorReason>,
    val ownPackage: String,
)

/** The plan's items in order, and the apps the floor left alone that would otherwise have been items. */
data class PlanResult(val items: List<PlanItem>, val leftAlone: List<Pair<AppFacts, FloorReason>>)

/** The remediation plan's rules (ADR 0026): pure functions, so that they can be unit-tested. */
object Plan {
    /** Cards in one session; the rest wait for the next (ADR 0026, point 7). */
    const val SESSION_CARDS = 5

    private val TRACKER_PURPOSES = setOf("Advertisement", "Analytics", "Profiling")

    private val CONTROL = listOf(
        SpecialAccess.ACCESSIBILITY to Screen.ACCESSIBILITY,
        SpecialAccess.NOTIFICATION_LISTENER to Screen.NOTIFICATION_LISTENER,
        SpecialAccess.DEVICE_ADMIN to Screen.DEVICE_ADMINS,
    )

    private val SPECIAL_SCREENS = CONTROL.toMap() + mapOf(
        SpecialAccess.OVERLAY to Screen.OVERLAY,
        SpecialAccess.USAGE_ACCESS to Screen.USAGE_ACCESS,
        SpecialAccess.INSTALL_UNKNOWN_APPS to Screen.INSTALL_UNKNOWN_APPS,
        SpecialAccess.ALL_FILES to Screen.ALL_FILES,
        SpecialAccess.BATTERY_EXEMPT to Screen.BATTERY,
    )

    /** The items at [level], one per app, in the queue's order. */
    fun items(input: PlanInput, level: PlanLevel): PlanResult {
        val candidates = (deviceItems(input.device) + appItems(input)).filter { level.includes(it.reason) }
        val (protected, open) = candidates.partition { item -> item.app != null && item.app.packageName in input.floor }
        val leftAlone = protected.mapNotNull { it.app }.distinctBy { it.packageName }.map { it to input.floor.getValue(it.packageName) }
        val merged = open.groupBy { it.app?.packageName ?: it.key }.values.map(::merge)
        return PlanResult(merged.sortedWith(order), leftAlone)
    }

    /** The items of one session: those the user has not kept as they are, while their state is still the one kept. */
    fun session(items: List<PlanItem>, kept: Map<String, ItemState>, state: (PlanItem) -> ItemState): List<PlanItem> =
        items.filter { kept[it.key] != state(it) }.take(SESSION_CARDS)

    /** Class, then apps with advertising, analytics or profiling trackers, then the longest time not opened, then the name. */
    val order: Comparator<PlanItem> = compareBy<PlanItem> { it.reason.planClass }
        .thenBy { !it.trackerPurpose }
        .thenByDescending { it.notOpenedDays ?: -1L }
        .thenBy { it.reason }
        .thenBy { it.app?.let { app -> (app.label ?: app.packageName).lowercase(Locale.ROOT) }.orEmpty() }

    private fun deviceItems(findings: List<FindingKind>): List<PlanItem> = findings.mapNotNull { kind ->
        when (kind) {
            FindingKind.WIRELESS_DEBUGGING -> PlanItem(PlanReason.WIRELESS_DEBUGGING, null, listOf(Screen.DEVELOPER_OPTIONS))
            FindingKind.USER_CERTIFICATE_AUTHORITY -> PlanItem(PlanReason.CERTIFICATE_AUTHORITY, null, listOf(Screen.SECURITY))
            FindingKind.USB_DEBUGGING -> PlanItem(PlanReason.USB_DEBUGGING, null, listOf(Screen.DEVELOPER_OPTIONS))
            else -> null
        }
    }

    private fun appItems(input: PlanInput): List<PlanItem> {
        val dormant = input.usage?.let { usage -> Dormancy.dormant(input.apps.map { it.first }, usage, input.ownPackage) }.orEmpty()
            .associateBy { it.app.packageName }
        return input.apps.filter { (app, _) -> app.packageName != input.ownPackage }.flatMap { (app, findings) ->
            val purpose = input.trackers?.get(app.packageName)?.embedded.orEmpty()
                .any { id -> input.trackerInfo[id]?.categories.orEmpty().any { it in TRACKER_PURPOSES } }
            // Days not opened, from 90 on.
            val unopened = input.usage?.let { Dormancy.notOpened(app, it).days }?.takeIf { it >= Dormancy.DAYS }
            buildList {
                if (FindingKind.VPN_WITH_REMOTE_CONTROL in findings || FindingKind.REMOTE_CONTROL in findings) {
                    add(PlanReason.CONTROL_ACCESS to CONTROL.filter { (access, _) -> access in app.special }.map { it.second })
                }
                if (FindingKind.MODIFIED_APP in findings || FindingKind.UNTRUSTED_SYSTEM_KEY in findings) {
                    add(PlanReason.DOUBTFUL_COPY to listOf(Screen.APP_INFO))
                }
                if (FindingKind.INSTALLS_APPS in findings) add(PlanReason.INSTALLS_APPS to listOf(Screen.INSTALL_UNKNOWN_APPS))
                if (FindingKind.TRAFFIC_SHARING in findings) add(PlanReason.TRAFFIC_SHARING to listOf(Screen.APP_INFO))
                dormant[app.packageName]?.let { addAll(notOpened(it)) }
                if (app.isSystem && app.enabled && (FindingKind.PREINSTALLED_COLLECTOR in findings || app.launcherIcon && unopened != null)) {
                    add(PlanReason.PREINSTALLED to listOf(Screen.APP_INFO))
                }
            }.map { (reason, screens) -> PlanItem(reason, app, screens, purpose, unopened?.takeIf { reason.notOpened() }) }
        }
    }

    private fun PlanReason.notOpened() = this == PlanReason.NOT_OPENED_SENSITIVE || this == PlanReason.NOT_OPENED_OTHER || this == PlanReason.PREINSTALLED

    /** An app not opened for 90 days: sensors, special access and VPN permission in one item, the rest in another. */
    private fun notOpened(dormant: Dormant): List<Pair<PlanReason, List<Screen>>> {
        val app = dormant.app
        val permissions = buildList {
            add(Screen.APP_INFO)
            if (!app.isSystem) add(Screen.UNUSED_APP_SETTING)
        }
        val sensitive = buildList {
            if (app.sensors.isNotEmpty()) addAll(permissions)
            if (StillHolds.SPECIAL_ACCESS in dormant.holds) app.special.sortedBy { it.ordinal }.mapNotNullTo(this) { SPECIAL_SCREENS[it] }
            if (StillHolds.VPN_PERMISSION in dormant.holds) add(Screen.VPN)
        }
        val other = StillHolds.BACKGROUND_DATA in dormant.holds ||
            StillHolds.SENSITIVE_PERMISSION in dormant.holds && app.sensors.isEmpty()
        return buildList {
            if (sensitive.isNotEmpty()) add(PlanReason.NOT_OPENED_SENSITIVE to sensitive)
            if (other && sensitive.isEmpty()) add(PlanReason.NOT_OPENED_OTHER to permissions)
        }
    }

    /** One card per app: its most urgent reason, with the others' screens after its own. */
    private fun merge(items: List<PlanItem>): PlanItem {
        val sorted = items.sortedWith(compareBy<PlanItem> { it.reason.planClass }.thenBy { it.reason })
        val first = sorted.first()
        return first.copy(
            screens = sorted.flatMap { it.screens }.distinct(),
            notOpenedDays = sorted.firstNotNullOfOrNull { it.notOpenedDays },
            also = sorted.drop(1).map { it.reason },
        )
    }
}
