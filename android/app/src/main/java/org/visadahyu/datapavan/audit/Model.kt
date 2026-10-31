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
    /** User-visible name; null until loaded, because loading every label is the slowest step. */
    val label: String?,
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
    /** The app's signing certificates; null when Android does not report them. */
    val signing: AppSigning? = null,
    /** The Linux user ID under which Android counts the app's network use; several apps can share one. */
    val uid: Int = -1,
    /** Has an icon in the app drawer. */
    val launcherIcon: Boolean = false,
    /**
     * Can do its work without being opened: a keyboard, the home screen, the default SMS or phone app,
     * a live wallpaper, a widget, a VPN, or one bound through special access (ADR 0022).
     */
    val worksUnopened: Boolean = false,
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
    /** Whether the attestation's certificate chain leads to Google's attestation root. */
    val trust: AttestationTrust,
)

/** Result of checking an attestation certificate chain; see [AttestationChain]. */
enum class AttestationTrust {
    /** Signed up to one of Google's attestation root keys, and nothing in the chain is revoked. */
    GOOGLE_ROOT,

    /** A valid chain to a root key that Google does not vouch for, such as the emulator's software key. */
    OTHER_ROOT,

    /** A certificate is not signed by the next one, so the chain proves nothing. */
    BROKEN_CHAIN,

    /** A certificate in the chain is on Google's revocation list, for example because its key leaked. */
    REVOKED,
}

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
