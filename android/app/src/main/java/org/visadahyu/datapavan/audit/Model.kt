package org.visadahyu.datapavan.audit

import java.time.LocalDate

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

/** A role, declared in the app's manifest, whose work needs no network (ADR 0025). */
enum class QuietRole { KEYBOARD, LIVE_WALLPAPER, HOME }

/** What the audit learned about one installed app. Plain data, so the rules can be unit-tested. */
data class AppFacts(
    val packageName: String,
    /** User-visible name; null until loaded, because loading every label is the slowest step. */
    val label: String?,
    val isSystem: Boolean,
    val enabled: Boolean,
    /** A system app that has been updated since the phone was made. */
    val updatedSystemApp: Boolean = false,
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
    /** Declares a keyboard, a live wallpaper or a home screen, whether or not it is in use. */
    val quietRole: QuietRole? = null,
)

/**
 * Hardware key attestation, decoded by the Rust engine. Null fields were absent. With a [securityLevel] of 1 or 2,
 * [deviceLocked], [verifiedBoot], [osPatchLevel], [verifiedBootKey] and [vendorPatchLevel] come from the list the
 * secure hardware enforces itself, never from the one the system writes; with 0, everything is the system's word.
 * They are the hardware's word only when [trust] is [AttestationTrust.GOOGLE_ROOT] as well.
 */
data class Integrity(
    /** 0 software, 1 trusted execution environment, 2 secure chip: the weaker of the attestation's and the key's. */
    val securityLevel: Int,
    val deviceLocked: Boolean?,
    /** 0 verified, 1 self-signed, 2 unverified, 3 failed. */
    val verifiedBoot: Int?,
    /** Security patch level as `YYYYMM`. */
    val osPatchLevel: Int?,
    /** Whether the attestation's certificate chain leads to Google's attestation root. */
    val trust: AttestationTrust,
    /** The digest of the key that verified the system, in lowercase hex. */
    val verifiedBootKey: String? = null,
    /** The vendor image's security patch level as `YYYYMM`. */
    val vendorPatchLevel: Int? = null,
    /** The day the revocation list that the chain was checked against was fetched. */
    val revocationListDate: LocalDate? = null,
) {
    companion object {
        /** An attestation that is not the hardware's answer to this app's request: nothing it says is used. */
        fun forged() = Integrity(securityLevel = 0, deviceLocked = null, verifiedBoot = null, osPatchLevel = null, trust = AttestationTrust.FORGED)
    }
}

/** Result of checking an attestation certificate chain; see [AttestationChain]. */
enum class AttestationTrust {
    /** Signed up to one of Google's attestation root keys, and nothing in the chain is revoked. */
    GOOGLE_ROOT,

    /**
     * A valid chain to a root key that Google does not vouch for: a maker's or a system's own root, as on phones
     * outside Google's programme, or a root that whoever hooks the keystore made. (The emulator's software
     * keystore signs under AOSP's published root, [SOFTWARE_ROOT].)
     */
    OTHER_ROOT,

    /** A certificate is not signed by the next one, so the chain proves nothing. */
    BROKEN_CHAIN,

    /** A certificate in the chain is on Google's revocation list, for example because its key leaked. */
    REVOKED,

    /**
     * The attestation is not the secure hardware's answer to this app's request: a certificate below the
     * attested key carries an attestation of its own, or the attested key or the challenge is not the one
     * the app generated. Only something that tampers with the keystore produces this.
     */
    FORGED,

    /** A certificate between the leaf and the root is not valid at the phone's date (AttestationChain). */
    OUT_OF_DATE,

    /**
     * A valid chain to AOSP's software attestation root, whose private key is published: what a software keystore
     * gives, and what anyone can make.
     */
    SOFTWARE_ROOT,

    /**
     * A valid chain to the root of the certificates that Google's key provisioning service gives to devices their
     * maker did not register ("Droid Unregistered Device CA", Google Test LLC): Android's emulator from Android 12
     * on, and test devices on debug builds. Anyone who runs the emulator holds keys under it, in software, so it
     * vouches for nothing about a phone.
     */
    TEST_ROOT,
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
    /** Why [integrity] is null: the hardware check failed, or its answer could not be read (see HardwareCheck). */
    val integrityFailure: IntegrityFailure? = null,
    /**
     * Whether the phone declares secure hardware for its keys, which Android says through its package manager,
     * apart from the keystore (DeviceCollector).
     */
    val hardwareKeystore: Boolean = false,
    /** Whether the system reports this device as an emulator (DeviceCollector). */
    val emulator: Boolean = false,
    /**
     * The Android version the system runs (`Build.VERSION.SDK_INT`); 0 where unknown. Every phone that meets
     * Android's requirements and runs Android 12 (API 31) or later has secure hardware for its keys, so on those
     * versions the version is a second declaration of that hardware (Rules).
     */
    val sdk: Int = 0,
)

/** Why the hardware check gave no result. */
enum class IntegrityFailure {
    /** The keystore refused the check, the data pack lacked its data, or the answer could not be read. */
    FAILED,

    /**
     * The phone's secure hardware has no attestation key until the phone reaches Google's provisioning server
     * (Remote Key Provisioning), as the keystore says (Android 13 and later).
     */
    KEYS_UNAVAILABLE,

    /**
     * Google's provisioning server gives the phone keys only after a system update: the keystore says to try
     * again after the next reboot, once an update is installed (Android 14 and later).
     */
    UPDATE_REQUIRED,

    /**
     * Google's provisioning server refused the phone keys for good, as for a phone its maker did not register
     * or that Google no longer trusts: the keystore says the keys are unavailable and never to try again.
     */
    KEYS_REFUSED,
}

/** What the hardware check found: the attestation's decoded state, or why there is none. */
data class IntegrityResult(val integrity: Integrity? = null, val failure: IntegrityFailure? = null)
