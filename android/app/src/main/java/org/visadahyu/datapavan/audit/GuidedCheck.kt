package org.visadahyu.datapavan.audit

/**
 * One reading for the guided check (ADR 0025): an app's use in the check's period, the sum over all
 * UIDs, and Android's live totals read just before the queries. Kept in memory only.
 */
data class CheckReading(
    /** Wall-clock time of the reading. */
    val at: Long,
    val app: NetworkUse,
    /** Received plus sent over all UIDs, mobile and Wi-Fi. */
    val all: Long,
    /** `TrafficStats`' total received plus sent, or null where the phone does not offer them. */
    val live: Long?,
)

/** What the user says they will do; the first ones only receive. */
enum class CheckActivity(val receiveOnly: Boolean) {
    WATCH(true),
    LISTEN(true),
    SCROLL(true),
    MAP(true),
    DOWNLOAD(true),
    SEND(false),
    CALL(false),
    TYPE(false),
    OPEN(false),
    OTHER(false),
}

/** Whether Android's count was up to date at both readings, as far as Datapavan can tell. */
enum class Freshness {
    UP_TO_DATE,

    /** The second reading fell short of the live totals: traffic may be missing. */
    BEHIND,

    /** The first reading fell short: the result may include traffic from before the check. */
    FIRST_BEHIND,

    /** A VPN counts traffic twice in the live totals, and the comparison was not tested with one. */
    NOT_CHECKED_VPN,

    /** The phone offers no live totals. */
    NOT_CHECKED,
}

/** Why sent bytes are not shown as a share of received ones. */
enum class NotCompared { PROXY_OR_VPN, SHARED_UID, SYSTEM_COMPONENT, LITTLE_RECEIVED, OLD_KERNEL }

data class CheckResult(
    val activity: CheckActivity,
    val millis: Long,
    val use: NetworkUse,
    val freshness: Freshness,
    /** Null when the share is shown, or when the activity does not only receive. */
    val notCompared: NotCompared?,
) {
    /** Sent bytes as a share of received ones, for activities that only receive and can be compared. */
    val sentShare: Double?
        get() = if (activity.receiveOnly && notCompared == null && use.received > 0) use.sent.toDouble() / use.received else null
}

/** The guided check's rules (ADR 0025, docs/spikes/2026-11-guided-check.md): pure, so that they can be unit-tested. */
object GuidedCheck {
    /** Android brings its counts up to date on a query only if no app other than the system queried in this time. */
    const val GAP_MS = 15_000L

    /** Android keeps per-UID counts in buckets of two hours since the Unix epoch. */
    const val BUCKET_MS = 2 * 60 * 60 * 1000L

    /** How often the second reading is taken again while the count is behind. */
    const val READS = 3

    const val SLACK_SHARE = 0.05
    const val SLACK_BYTES = 64 * 1024L

    /** Below this, a share of sent bytes says little. */
    const val MIN_RECEIVED = 1_000_000L

    /**
     * The period both readings ask for: from the two-hour boundary at least a day before the first
     * reading, because Android spreads a late count over earlier buckets, to two days after it, so
     * that the end is in the future at every reading. A period ending now loses part of the current
     * bucket, and one starting inside a bucket gets a share of it.
     */
    fun period(firstAt: Long): Pair<Long, Long> =
        Math.floorDiv(firstAt - UsageFacts.DAY, BUCKET_MS) * BUCKET_MS to firstAt + 2 * UsageFacts.DAY

    /** Milliseconds to wait before a fresh reading, [now] and [lastQuery] in `elapsedRealtime`. */
    fun wait(now: Long, lastQuery: Long?): Long = if (lastQuery == null) 0 else (lastQuery + GAP_MS - now).coerceAtLeast(0)

    /**
     * Compares the change summed over all UIDs with the change of the live totals. A gap of more than
     * 5 % and more than 64 KB means that one of the readings was not up to date.
     */
    fun freshness(first: CheckReading, second: CheckReading, vpnActive: Boolean): Freshness {
        if (vpnActive) return Freshness.NOT_CHECKED_VPN
        val live = (second.live ?: return Freshness.NOT_CHECKED) - (first.live ?: return Freshness.NOT_CHECKED)
        val counted = second.all - first.all
        val slack = maxOf(SLACK_BYTES, (live * SLACK_SHARE).toLong())
        return when {
            live - counted > slack -> Freshness.BEHIND
            counted - live > slack -> Freshness.FIRST_BEHIND
            else -> Freshness.UP_TO_DATE
        }
    }

    /**
     * Why the share of sent bytes is not shown for [app], if it is not: an app that carries others'
     * traffic ([carriesOthers]: a VPN, proxy or circumvention app), a UID shared with other apps
     * ([sharedUid]), a part of the system without an icon, too little received, or a kernel older than
     * 4.9 ([osVersion]), which counts with `xt_qtaguid` and counted sent bytes 10 to 29 % high on the A40.
     */
    fun notCompared(app: AppFacts, carriesOthers: Boolean, sharedUid: Boolean, received: Long, osVersion: String?): NotCompared? = when {
        carriesOthers || app.isVpnApp -> NotCompared.PROXY_OR_VPN
        sharedUid -> NotCompared.SHARED_UID
        app.isSystem && !app.launcherIcon -> NotCompared.SYSTEM_COMPONENT
        received < MIN_RECEIVED -> NotCompared.LITTLE_RECEIVED
        osVersion != null && olderThan49(osVersion) -> NotCompared.OLD_KERNEL
        else -> null
    }

    fun result(activity: CheckActivity, first: CheckReading, second: CheckReading, vpnActive: Boolean, notCompared: (Long) -> NotCompared?): CheckResult {
        val use = second.app - first.app
        return CheckResult(activity, second.at - first.at, use, freshness(first, second, vpnActive), notCompared(use.received))
    }

    /** Whether a kernel version such as "4.4.177-25902526" is older than 4.9; unknown versions are not. */
    fun olderThan49(osVersion: String): Boolean {
        val (major, minor) = Regex("""^(\d+)\.(\d+)""").find(osVersion)?.destructured ?: return false
        return major.toInt() < 4 || major.toInt() == 4 && minor.toInt() < 9
    }
}

/** An app installed by the user and never opened since, that used the network (ADR 0025). */
data class NeverOpenedUse(val installed: Long, val use: NetworkUse)

/** The facts of ADR 0025 that need no comparison, from the data of ADR 0022. */
object TrafficFacts {
    /** Days of the period both facts cover. */
    const val DAYS = 30

    /** A display threshold for background sending by a quiet role, not a judgement. */
    const val QUIET_ROLE_SENT = 1_000_000L

    /**
     * For an app the user installed, that shares no UID ([sharedUid]) and is not one that works
     * without being opened, installed after Android's oldest usage record and with no recorded use
     * since: its use in the last [DAYS] days, if any.
     */
    fun neverOpened(app: AppFacts, usage: UsageFacts, sharedUid: Boolean): NeverOpenedUse? {
        if (app.isSystem || app.worksUnopened || sharedUid || app.firstInstall < usage.recordsSince) return null
        if ((usage.lastUsed[app.packageName] ?: 0) >= app.firstInstall) return null
        val use = usage.network(DAYS, app.uid)?.takeIf { it.total > 0 } ?: return null
        return NeverOpenedUse(app.firstInstall, use)
    }

    /** Bytes that a keyboard, live wallpaper or home screen sent in the background in the last [DAYS] days, from 1 MB. */
    fun quietRoleSent(app: AppFacts, usage: UsageFacts): Long? {
        if (app.quietRole == null) return null
        val use = usage.network(DAYS, app.uid) ?: return null
        return (use.mobile.backgroundSent + use.wifi.backgroundSent).takeIf { it >= QUIET_ROLE_SENT }
    }
}
