package org.visadahyu.datapavan.audit

/** How urgently a finding needs the user's attention, most urgent first. */
enum class Severity { HIGH, MEDIUM, LOW, INFO }

/** Everything the audit can report. Wording lives in string resources, keyed by these names. */
enum class FindingKind(val severity: Severity) {
    // Apps
    UNTRUSTED_SYSTEM_KEY(Severity.HIGH),
    MODIFIED_APP(Severity.HIGH),
    VPN_WITH_REMOTE_CONTROL(Severity.HIGH),
    REMOTE_CONTROL(Severity.MEDIUM),
    PREINSTALLED_COLLECTOR(Severity.MEDIUM),
    INSTALLS_APPS(Severity.MEDIUM),
    SENSORS(Severity.LOW),
    TRACKERS(Severity.LOW),
    TRAFFIC_SHARING(Severity.MEDIUM),
    REMOTE_SUPPORT(Severity.LOW),
    SCREEN_RECORDING(Severity.LOW),
    UNKNOWN_SOURCE(Severity.INFO),
    SIGNER_UNKNOWN(Severity.INFO),
    LEAKED_KEY_FROM_STORE(Severity.INFO),

    // Device
    SYSTEM_KEY_PUBLIC(Severity.HIGH),
    USER_CERTIFICATE_AUTHORITY(Severity.HIGH),
    WIRELESS_DEBUGGING(Severity.HIGH),
    BOOTLOADER_UNLOCKED(Severity.HIGH),
    BOOT_NOT_VERIFIED(Severity.HIGH),
    ATTESTATION_REVOKED(Severity.HIGH),
    ATTESTATION_FORGED(Severity.HIGH),
    ATTESTATION_SOFTWARE_ANSWER(Severity.HIGH),
    ATTESTATION_PUBLIC_ROOT(Severity.HIGH),
    ATTESTATION_UNCONFIRMED(Severity.MEDIUM),
    ATTESTATION_INCOMPLETE(Severity.MEDIUM),
    ATTESTATION_OUT_OF_DATE(Severity.MEDIUM),
    ATTESTATION_BROKEN(Severity.MEDIUM),
    ATTESTATION_KEYS_UNAVAILABLE(Severity.MEDIUM),
    ATTESTATION_UPDATE_REQUIRED(Severity.MEDIUM),
    ATTESTATION_KEYS_REFUSED(Severity.MEDIUM),
    SYSTEM_KEY_LEAKED(Severity.MEDIUM),
    USB_DEBUGGING(Severity.MEDIUM),
    OLD_SECURITY_PATCH(Severity.MEDIUM),
    ATTESTATION_FAILED(Severity.MEDIUM),
    SYSTEM_OWN_KEY(Severity.MEDIUM),
    INTEGRITY_SOFTWARE_ONLY(Severity.LOW),
    INTEGRITY_EMULATOR(Severity.LOW),
    VPN_ACTIVE(Severity.INFO),
    SYSTEM_KEY_DEVELOPMENT(Severity.INFO),
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

/** App stores whose installs are not reported as an unknown source (Stores.kt). */
private val KNOWN_STORES = Stores.names.keys

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

    /**
     * [trackers] is the tracker scan of the app, or null while it is still running. [signature] is
     * the app's signature judged against the list of official certificates (ADR 0018). [sdks] are
     * the categories of the SDKs from `data/sdks` whose code the app contains (ADR 0019). [keys] is
     * what the phone's system key says about the app (ADR 0023).
     */
    fun forApp(
        app: AppFacts,
        trackers: AppTrackers? = null,
        signature: SignatureVerdict? = null,
        sdks: Set<SdkCategory> = emptySet(),
        keys: KeyFacts? = null,
    ): List<FindingKind> = buildList {
        keys?.untrusted?.let { kind ->
            // Code from the system image is what the phone shipped with; anything installed later, or an
            // update, could be malware posing as a system app, unless the maker's store, Play or the
            // phone's own setup put it there.
            val later = keys.origin != Origin.SYSTEM_IMAGE
            when {
                later && !keys.fromTrustedStore && !keys.fromSetup -> add(FindingKind.UNTRUSTED_SYSTEM_KEY)
                later && kind == KeyKind.LEAKED -> add(FindingKind.LEAKED_KEY_FROM_STORE)
                else -> Unit
            }
        }
        if (SdkCategory.TRAFFIC_SHARING in sdks) add(FindingKind.TRAFFIC_SHARING)
        if (SdkCategory.REMOTE_SUPPORT in sdks) add(FindingKind.REMOTE_SUPPORT)
        if (SdkCategory.SCREEN_RECORDING in sdks) add(FindingKind.SCREEN_RECORDING)
        if (signature is SignatureVerdict.Modified) add(FindingKind.MODIFIED_APP)
        if (signature is SignatureVerdict.UnknownKey) add(FindingKind.SIGNER_UNKNOWN)
        val control = app.special intersect REMOTE_CONTROL
        if (app.isVpnApp && control.isNotEmpty()) add(FindingKind.VPN_WITH_REMOTE_CONTROL)
        if (!app.isVpnApp && !app.isSystem && control.isNotEmpty()) add(FindingKind.REMOTE_CONTROL)
        if (app.isSystem && app.enabled && KnownCollectors.companyOf(app.packageName) != null) add(FindingKind.PREINSTALLED_COLLECTOR)
        if (!app.isSystem && SpecialAccess.INSTALL_UNKNOWN_APPS in app.special) add(FindingKind.INSTALLS_APPS)
        if (!app.isSystem && app.sensors.isNotEmpty()) add(FindingKind.SENSORS)
        if (trackers != null && trackers.embedded.isNotEmpty()) add(FindingKind.TRACKERS)
        if (!app.isSystem && app.installer !in KNOWN_STORES) add(FindingKind.UNKNOWN_SOURCE)
    }.sortedBy { it.severity }

    /**
     * [nowYearMonth] is the current month as `YYYYMM`; a patch more than 12 months older is flagged.
     * [systemKey] says why the key that signs the package `android` cannot be trusted, or is null.
     */
    fun forDevice(device: DeviceFacts, nowYearMonth: Int, systemKey: KeyKind? = null): List<FindingKind> = buildList {
        when (systemKey) {
            KeyKind.AOSP_TEST -> add(FindingKind.SYSTEM_KEY_PUBLIC)
            KeyKind.LEAKED -> add(FindingKind.SYSTEM_KEY_LEAKED)
            KeyKind.GOOGLE_DEV -> add(FindingKind.SYSTEM_KEY_DEVELOPMENT)
            null -> Unit
        }
        if (device.userCertificateAuthorities.isNotEmpty()) add(FindingKind.USER_CERTIFICATE_AUTHORITY)
        if (device.wirelessDebugging) add(FindingKind.WIRELESS_DEBUGGING)
        if (device.usbDebugging) add(FindingKind.USB_DEBUGGING)
        // A check that should work and did not is reported, so that a system cannot hide the bootloader's
        // state by breaking the check, and a fault on a sound phone comes to light. What the keystore says of
        // the cause (waiting for Google, a system update needed, keys refused) is told apart, so that the owner
        // knows what to do, at the same severity, since a hook could claim each of them too. A device that
        // calls itself an emulator changes none of this.
        if (device.integrity == null) {
            when (device.integrityFailure) {
                IntegrityFailure.FAILED -> add(FindingKind.ATTESTATION_FAILED)
                IntegrityFailure.KEYS_UNAVAILABLE -> add(FindingKind.ATTESTATION_KEYS_UNAVAILABLE)
                IntegrityFailure.UPDATE_REQUIRED -> add(FindingKind.ATTESTATION_UPDATE_REQUIRED)
                IntegrityFailure.KEYS_REFUSED -> add(FindingKind.ATTESTATION_KEYS_REFUSED)
                null -> Unit
            }
        }
        device.integrity?.let { integrity ->
            val trust = integrity.trust
            // Nothing a forged attestation says is used, not its bootloader state, not its patch level: it may be
            // another phone's answer, or whatever its forger chose.
            if (trust == AttestationTrust.FORGED) {
                add(FindingKind.ATTESTATION_FORGED)
                return@let
            }
            if (integrity.securityLevel == 0) {
                // A software answer says nothing reliable about the bootloader. On a phone that declares secure
                // hardware for its keys, it is not the answer a sound phone gives: a hook that answers in software
                // must not look quieter than the unlocked bootloader it could hide. Android's emulator declares the
                // same feature with a KeyMint in software; it says so in words, which a phone made to claim it would
                // show its owner as plainly false.
                add(
                    when {
                        device.emulator -> FindingKind.INTEGRITY_EMULATOR
                        device.hardwareKeystore -> FindingKind.ATTESTATION_SOFTWARE_ANSWER
                        trust == AttestationTrust.BROKEN_CHAIN -> FindingKind.ATTESTATION_BROKEN
                        trust == AttestationTrust.OTHER_ROOT -> FindingKind.ATTESTATION_UNCONFIRMED
                        trust == AttestationTrust.REVOKED -> FindingKind.ATTESTATION_REVOKED
                        else -> FindingKind.INTEGRITY_SOFTWARE_ONLY
                    },
                )
            } else {
                // A claim of secure hardware signed under a key that AOSP publishes: anyone could have made it, and
                // no sound phone does. Like a forged one, it is reported alone; what it says is its maker's choice.
                if (trust == AttestationTrust.SOFTWARE_ROOT) {
                    add(FindingKind.ATTESTATION_PUBLIC_ROOT)
                    return@let
                }
                when (trust) {
                    AttestationTrust.GOOGLE_ROOT, AttestationTrust.FORGED, AttestationTrust.SOFTWARE_ROOT -> Unit
                    AttestationTrust.REVOKED -> add(FindingKind.ATTESTATION_REVOKED)
                    AttestationTrust.OTHER_ROOT -> add(FindingKind.ATTESTATION_UNCONFIRMED)
                    AttestationTrust.BROKEN_CHAIN -> add(FindingKind.ATTESTATION_BROKEN)
                    AttestationTrust.OUT_OF_DATE -> add(FindingKind.ATTESTATION_OUT_OF_DATE)
                }
                // A sound trusted environment or secure chip always states the bootloader and boot state
                // in the list it enforces itself, and the engine never takes them from the list the
                // system writes (ADR 0040, decision 5), so their absence is reported, not passed over.
                if (integrity.deviceLocked == null || integrity.verifiedBoot == null) add(FindingKind.ATTESTATION_INCOMPLETE)
                // The warnings of an attestation a sound phone could have made are reported, confirmed or not: a
                // forger gains nothing by them. (The two that no sound phone makes returned above.)
                if (integrity.deviceLocked == false) add(FindingKind.BOOTLOADER_UNLOCKED)
                // Locked with a key that is not the maker's (ADR 0040, decision 7): until a dataset of the keys
                // that systems such as GrapheneOS publish exists, no such key can be named, so each is a medium fact.
                if (integrity.deviceLocked == true && integrity.verifiedBoot == 1) add(FindingKind.SYSTEM_OWN_KEY)
                if (integrity.deviceLocked == true && integrity.verifiedBoot in setOf(2, 3)) add(FindingKind.BOOT_NOT_VERIFIED)
            }
            // An old patch level is believed from any attestation a sound phone could have made, in hardware or in
            // software, confirmed or not: no system makes itself look older than it is. The vendor's level is
            // shown, not judged: a phone may patch its vendor image and leave the level behind.
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
