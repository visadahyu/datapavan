package org.visadahyu.datapavan.audit

import android.Manifest
import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import android.os.RemoteException

/** Bytes received and sent on one kind of network, and how much of each Android counted as background. */
data class Traffic(
    val received: Long = 0,
    val sent: Long = 0,
    val backgroundReceived: Long = 0,
    val backgroundSent: Long = 0,
) {
    val total: Long get() = received + sent
    val background: Long get() = backgroundReceived + backgroundSent

    operator fun plus(other: Traffic) = Traffic(
        received + other.received, sent + other.sent, backgroundReceived + other.backgroundReceived, backgroundSent + other.backgroundSent,
    )
}

/** One UID's use of mobile networks (all SIMs together) and of Wi-Fi in a period. */
data class NetworkUse(val mobile: Traffic = Traffic(), val wifi: Traffic = Traffic()) {
    val total: Long get() = mobile.total + wifi.total
    val background: Long get() = mobile.background + wifi.background
}

/**
 * What usage access showed at [readAt] (ADR 0022): network use by UID for each period in
 * [UsageFacts.PERIODS], and when each package was last used. Only totals; kept in memory, never stored.
 */
data class UsageFacts(
    val readAt: Long,
    /** Days of the period to network use by UID, including Android's own UIDs in [UsageFacts.OTHER_UIDS]. */
    val network: Map<Int, Map<Int, NetworkUse>>,
    /** The last time each package was visible, in use or running a foreground service; absent without a record. */
    val lastUsed: Map<String, Long>,
    /** The start of the oldest usage record Android still keeps. */
    val recordsSince: Long,
) {
    fun network(days: Int, uid: Int): NetworkUse? = network[days]?.get(uid)

    companion object {
        val PERIODS = listOf(30, 7)
        const val DAY = 24 * 60 * 60 * 1000L

        /** Removed apps, tethering and the system: counted by Android, but under no installed app. */
        val OTHER_UIDS = listOf(NetworkStats.Bucket.UID_REMOVED, NetworkStats.Bucket.UID_TETHERING, Process.SYSTEM_UID)
    }
}

/** How long an app has not been opened, and since when. */
data class NotOpened(
    val days: Long,
    /** The last recorded use, or null when Android's records hold none since the app was installed. */
    val lastUsed: Long?,
    /** When the period without use starts: the last use, or the later of the install and the oldest record. */
    val since: Long,
)

/** What an app not opened for [Dormancy.DAYS] days still holds, for the remediation plan (ADR 0022). */
enum class StillHolds { SENSITIVE_PERMISSION, SPECIAL_ACCESS, VPN_PERMISSION, BACKGROUND_DATA }

data class Dormant(val app: AppFacts, val notOpened: NotOpened, val holds: Set<StillHolds>)

/** Rules over [UsageFacts]: pure functions, so that they can be unit-tested. */
object Dormancy {
    const val DAYS = 90

    /** Background data counts if it happened within this many days. */
    const val BACKGROUND_DAYS = 30

    fun notOpened(app: AppFacts, usage: UsageFacts): NotOpened {
        val last = usage.lastUsed[app.packageName]?.takeIf { it > 0 }
        val since = last ?: maxOf(app.firstInstall, usage.recordsSince)
        return NotOpened(((usage.readAt - since) / UsageFacts.DAY).coerceAtLeast(0), last, since)
    }

    /**
     * Apps not opened for [DAYS] days or more that still hold something. Preinstalled system apps count
     * when they have an icon in the app drawer; the others are parts of the system. Background data of a
     * shared UID counts only when no app of that UID was used in the period, because Android cannot
     * tell which of them used it. Datapavan itself ([ownPackage]) is left out.
     */
    fun dormant(apps: List<AppFacts>, usage: UsageFacts, ownPackage: String): List<Dormant> {
        val byUid = apps.groupBy { it.uid }
        val recent = usage.readAt - BACKGROUND_DAYS * UsageFacts.DAY
        return apps.asSequence()
            .filter { it.packageName != ownPackage && it.enabled && (!it.isSystem || it.launcherIcon) }
            .mapNotNull { app ->
                val notOpened = notOpened(app, usage)
                if (notOpened.days < DAYS) return@mapNotNull null
                val sharedInUse = byUid[app.uid].orEmpty().any { (usage.lastUsed[it.packageName] ?: 0) >= recent }
                val holds = buildSet {
                    if (app.grantedDangerous.isNotEmpty()) add(StillHolds.SENSITIVE_PERMISSION)
                    if (app.special.isNotEmpty()) add(StillHolds.SPECIAL_ACCESS)
                    if (app.vpnAuthorised) add(StillHolds.VPN_PERMISSION)
                    if (!sharedInUse && (usage.network(BACKGROUND_DAYS, app.uid)?.background ?: 0) > 0) add(StillHolds.BACKGROUND_DATA)
                }
                holds.takeIf { it.isNotEmpty() }?.let { Dormant(app, notOpened, it) }
            }
            .sortedByDescending { it.notOpened.days }
            .toList()
    }
}

/**
 * Reads Android's own records with usage access (ADR 0022): network summaries and the aggregated use
 * of apps. Never the event stream of which app was opened when.
 */
class UsageReader(private val context: Context) {

    /** The rule system Settings uses: an explicit allow, or the default mode with the permission granted. */
    fun hasAccess(): Boolean {
        val mode = context.getSystemService(AppOpsManager::class.java)
            .unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
        return mode == AppOpsManager.MODE_ALLOWED ||
            mode == AppOpsManager.MODE_DEFAULT && context.checkSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) == PackageManager.PERMISSION_GRANTED
    }

    /**
     * Null without usage access. [periods] are lengths in days, ending at [now]; they must include
     * [Dormancy.BACKGROUND_DAYS]. The queries can take seconds: call it off the main thread.
     */
    fun read(now: Long = System.currentTimeMillis(), periods: List<Int> = UsageFacts.PERIODS): UsageFacts? {
        if (!hasAccess()) return null
        val stats = context.getSystemService(NetworkStatsManager::class.java)
        val network = periods.associateWith { days -> network(stats, now - days * UsageFacts.DAY, now) }
        // Android keeps yearly records for three years; a longer span reads all of them.
        val used = context.getSystemService(UsageStatsManager::class.java).queryAndAggregateUsageStats(now - RECORD_SPAN, now).orEmpty()
        val lastUsed = used.mapValues { (_, it) -> maxOf(it.lastTimeVisible, it.lastTimeUsed, it.lastTimeForegroundServiceUsed) }
            .filterValues { it > 0 }
        val since = used.values.minOfOrNull { it.firstTimeStamp } ?: now
        return UsageFacts(now, network, lastUsed, since)
    }

    private fun network(stats: NetworkStatsManager, start: Long, end: Long): Map<Int, NetworkUse> {
        val mobile = summary(stats, ConnectivityManager.TYPE_MOBILE, start, end)
        val wifi = summary(stats, ConnectivityManager.TYPE_WIFI, start, end)
        return (mobile.keys + wifi.keys).associateWith { NetworkUse(mobile[it] ?: Traffic(), wifi[it] ?: Traffic()) }
    }

    /** Per-UID totals of one network type. A null subscriber ID reads all SIMs together. */
    private fun summary(stats: NetworkStatsManager, type: Int, start: Long, end: Long): Map<Int, Traffic> {
        @Suppress("DEPRECATION") // The network types are the documented arguments of querySummary.
        val buckets = try {
            stats.querySummary(type, null, start, end)
        } catch (_: SecurityException) {
            null
        } catch (_: RemoteException) {
            null
        } ?: return emptyMap()
        val totals = mutableMapOf<Int, Traffic>()
        buckets.use {
            val bucket = NetworkStats.Bucket()
            while (it.getNextBucket(bucket)) {
                val background = bucket.state != NetworkStats.Bucket.STATE_FOREGROUND
                val traffic = Traffic(
                    bucket.rxBytes, bucket.txBytes,
                    if (background) bucket.rxBytes else 0, if (background) bucket.txBytes else 0,
                )
                totals.merge(bucket.uid, traffic, Traffic::plus)
            }
        }
        return totals
    }

    private companion object {
        const val RECORD_SPAN = 4 * 366 * UsageFacts.DAY
    }
}
