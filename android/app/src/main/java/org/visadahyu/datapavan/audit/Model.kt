package org.visadahyu.datapavan.audit

/** Special access that the user grants in system Settings, outside the normal permission dialog. */
enum class SpecialAccess {
    ACCESSIBILITY,
    NOTIFICATION_LISTENER,
    DEVICE_ADMIN,
    OVERLAY,
    USAGE_ACCESS,
    INSTALL_UNKNOWN_APPS,
    ALL_FILES,
    BATTERY_EXEMPT,
}

/** Sensors behind a granted runtime permission. */
enum class Sensor { MICROPHONE, CAMERA, LOCATION }

/** What the audit learned about one installed app. Plain data, so the rules can be unit-tested. */
data class AppFacts(
    val packageName: String,
    val label: String,
    val isSystem: Boolean,
    val enabled: Boolean,
    /** Package that installed the app, or null when Android does not know (preinstalled, adb). */
    val installer: String?,
    val firstInstall: Long,
    val lastUpdate: Long,
    /** Granted permissions with the *dangerous* protection level. */
    val grantedDangerous: List<String>,
    val sensors: Set<Sensor>,
    val special: Set<SpecialAccess>,
    /** Declares a service bound with `BIND_VPN_SERVICE`. */
    val isVpnApp: Boolean,
    /** The user has accepted this app's VPN dialog. */
    val vpnAuthorised: Boolean,
)

/** Hardware key attestation, decoded by the Rust engine. Null fields were absent. */
data class Integrity(
    /** 0 software, 1 trusted execution environment, 2 secure chip. */
    val securityLevel: Int,
    val deviceLocked: Boolean?,
    /** 0 verified, 1 self-signed, 2 unverified, 3 failed. */
    val verifiedBoot: Int?,
    /** Security patch level as `YYYYMM`. */
    val osPatchLevel: Int?,
)

/** Device-wide facts. */
data class DeviceFacts(
    val usbDebugging: Boolean,
    val wirelessDebugging: Boolean,
    /** Subjects of certificate authorities that the user, or an app through the user, installed. */
    val userCertificateAuthorities: List<String>,
    val vpnActive: Boolean,
    /** Null when attestation is unavailable or failed. */
    val integrity: Integrity?,
)
