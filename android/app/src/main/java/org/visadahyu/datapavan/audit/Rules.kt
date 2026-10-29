package org.visadahyu.datapavan.audit

/** How urgently a finding needs the user's attention, most urgent first. */
enum class Severity { HIGH, MEDIUM, LOW, INFO }

/** Everything the audit can report. Wording lives in string resources, keyed by these names. */
enum class FindingKind(val severity: Severity) {
    // Apps
    VPN_WITH_REMOTE_CONTROL(Severity.HIGH),
    REMOTE_CONTROL(Severity.MEDIUM),
    PREINSTALLED_COLLECTOR(Severity.MEDIUM),
    INSTALLS_APPS(Severity.MEDIUM),
    SENSORS(Severity.LOW),
    TRACKERS(Severity.LOW),
    UNKNOWN_SOURCE(Severity.INFO),

    // Device
    USER_CERTIFICATE_AUTHORITY(Severity.HIGH),
    WIRELESS_DEBUGGING(Severity.HIGH),
    BOOTLOADER_UNLOCKED(Severity.HIGH),
    BOOT_NOT_VERIFIED(Severity.HIGH),
    ATTESTATION_REVOKED(Severity.HIGH),
    ATTESTATION_UNCONFIRMED(Severity.MEDIUM),
    USB_DEBUGGING(Severity.MEDIUM),
    OLD_SECURITY_PATCH(Severity.MEDIUM),
    INTEGRITY_SOFTWARE_ONLY(Severity.LOW),
    VPN_ACTIVE(Severity.INFO),
}

/**
 * Companies whose business is collecting data, recognised by package name. Device makers ship some
 * of their apps as system apps (for example Meta's app manager and services on Samsung phones).
 * Bundled for now; from M3 the list arrives as a signed data file.
 */
object KnownCollectors {
    private val prefixes = listOf(
        "com.facebook." to "Meta",
        "com.instagram." to "Meta",
        "com.whatsapp" to "Meta",
    )

    fun companyOf(packageName: String): String? = prefixes.firstOrNull { (prefix, _) -> packageName.startsWith(prefix) }?.second
}

/** App stores whose installs are not reported as an unknown source. */
private val KNOWN_STORES = setOf(
    "com.android.vending", // Google Play
    "com.sec.android.app.samsungapps", // Galaxy Store
    "org.fdroid.fdroid",
    "org.fdroid.basic",
    "com.aurora.store",
    "com.huawei.appmarket",
    "com.xiaomi.market",
)

/**
 * Access that lets an app read the screen or notifications, or control the device. Drawing over
 * other apps is not on the list: browsers with a built-in VPN use it for picture-in-picture, and
 * flagging them as able to control the phone was a false alarm on the A40.
 */
private val REMOTE_CONTROL = setOf(
    SpecialAccess.ACCESSIBILITY,
    SpecialAccess.NOTIFICATION_LISTENER,
    SpecialAccess.DEVICE_ADMIN,
)

/** Where an app stands in the strict sensor review. */
enum class ReviewStatus { NOT_REVIEWED, REVIEWED, CHANGED }

/** Voice assistants that can listen for a wake word, with the settings screen that turns it off. */
object WakeWordAssistants {
    /** Package name to an intent action that opens its wake-word setting, or null for the app's own page. */
    val known = mapOf(
        "com.google.android.googlequicksearchbox" to "com.google.android.googlequicksearchbox.action.HOTWORD_DETECTION_SETTINGS",
        "com.samsung.android.bixby.agent" to null,
    )
}

/** The audit's rules: pure functions from facts to findings, ordered by severity. */
object Rules {
    /**
     * An app the user has reviewed counts as reviewed while its sensor access stays within what it
     * had at the review. Gaining access again, or new access, puts it back on the list.
     */
    fun reviewStatus(current: Set<Sensor>, reviewed: Set<Sensor>?): ReviewStatus = when {
        reviewed == null -> ReviewStatus.NOT_REVIEWED
        reviewed.containsAll(current) -> ReviewStatus.REVIEWED
        else -> ReviewStatus.CHANGED
    }

    /** [trackers] is the tracker scan of the app, or null while it is still running. */
    fun forApp(app: AppFacts, trackers: AppTrackers? = null): List<FindingKind> = buildList {
        val control = app.special intersect REMOTE_CONTROL
        if (app.isVpnApp && control.isNotEmpty()) add(FindingKind.VPN_WITH_REMOTE_CONTROL)
        if (!app.isVpnApp && !app.isSystem && control.isNotEmpty()) add(FindingKind.REMOTE_CONTROL)
        if (app.isSystem && app.enabled && KnownCollectors.companyOf(app.packageName) != null) add(FindingKind.PREINSTALLED_COLLECTOR)
        if (!app.isSystem && SpecialAccess.INSTALL_UNKNOWN_APPS in app.special) add(FindingKind.INSTALLS_APPS)
        if (!app.isSystem && app.sensors.isNotEmpty()) add(FindingKind.SENSORS)
        if (trackers != null && trackers.embedded.isNotEmpty()) add(FindingKind.TRACKERS)
        if (!app.isSystem && app.installer !in KNOWN_STORES) add(FindingKind.UNKNOWN_SOURCE)
    }.sortedBy { it.severity }

    /** [nowYearMonth] is the current month as `YYYYMM`; a patch more than 12 months older is flagged. */
    fun forDevice(device: DeviceFacts, nowYearMonth: Int): List<FindingKind> = buildList {
        if (device.userCertificateAuthorities.isNotEmpty()) add(FindingKind.USER_CERTIFICATE_AUTHORITY)
        if (device.wirelessDebugging) add(FindingKind.WIRELESS_DEBUGGING)
        if (device.usbDebugging) add(FindingKind.USB_DEBUGGING)
        device.integrity?.let { integrity ->
            // A software-only attestation says nothing reliable about the bootloader.
            if (integrity.securityLevel == 0) {
                add(FindingKind.INTEGRITY_SOFTWARE_ONLY)
            } else {
                when (integrity.trust) {
                    AttestationTrust.GOOGLE_ROOT -> Unit
                    AttestationTrust.REVOKED -> add(FindingKind.ATTESTATION_REVOKED)
                    AttestationTrust.OTHER_ROOT, AttestationTrust.BROKEN_CHAIN -> add(FindingKind.ATTESTATION_UNCONFIRMED)
                }
                if (integrity.deviceLocked == false) add(FindingKind.BOOTLOADER_UNLOCKED)
                if (integrity.deviceLocked == true && integrity.verifiedBoot in setOf(2, 3)) add(FindingKind.BOOT_NOT_VERIFIED)
            }
            val patch = integrity.osPatchLevel
            if (patch != null && months(nowYearMonth) - months(patch) > 12) add(FindingKind.OLD_SECURITY_PATCH)
        }
        if (device.vpnActive) add(FindingKind.VPN_ACTIVE)
    }.sortedBy { it.severity }

    /** The most severe finding first; apps without findings last, then by label. */
    val byUrgency: Comparator<Pair<AppFacts, List<FindingKind>>> =
        compareBy<Pair<AppFacts, List<FindingKind>>> { (_, f) -> f.firstOrNull()?.severity?.ordinal ?: Int.MAX_VALUE }
            .thenByDescending { (_, f) -> f.size }
            .thenBy { (app, _) -> (app.label ?: app.packageName).lowercase() }

    private fun months(yearMonth: Int) = yearMonth / 100 * 12 + yearMonth % 100
}
