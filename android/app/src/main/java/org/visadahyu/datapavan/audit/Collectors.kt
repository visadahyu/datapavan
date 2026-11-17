package org.visadahyu.datapavan.audit

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.WallpaperManager
import android.app.admin.DevicePolicyManager
import android.appwidget.AppWidgetManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.content.pm.ResolveInfo
import android.net.ConnectivityManager
import android.net.Uri
import android.net.NetworkCapabilities
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.provider.Telephony
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telecom.TelecomManager
import android.view.accessibility.AccessibilityManager
import android.service.wallpaper.WallpaperService
import android.view.inputmethod.InputMethod
import android.view.inputmethod.InputMethodManager
import androidx.core.net.toUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import org.visadahyu.datapavan.datapack.DataPackStore
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/** The sensor that a runtime permission gives access to, if any. */
fun sensorOf(permission: String): Sensor? = SENSOR_PERMISSIONS[permission]

private val SENSOR_PERMISSIONS = mapOf(
    Manifest.permission.RECORD_AUDIO to Sensor.MICROPHONE,
    Manifest.permission.CAMERA to Sensor.CAMERA,
    Manifest.permission.ACCESS_FINE_LOCATION to Sensor.LOCATION,
    Manifest.permission.ACCESS_COARSE_LOCATION to Sensor.LOCATION,
)

/**
 * Reads what an unprivileged app can learn about the installed apps. Every API used here was
 * checked in the M2 spike (docs/spikes/2026-10-m2-access.md). Components are found by their
 * binding permission, because intent queries miss services that are not exported.
 */
class AppCollector(private val context: Context) {
    private val pm = context.packageManager
    private val appOps = context.getSystemService(AppOpsManager::class.java)
    private val power = context.getSystemService(PowerManager::class.java)
    private val dangerous = ConcurrentHashMap<String, Boolean>()

    /**
     * Collects all apps in parallel, without labels. Nearly all the time goes into blocking calls to
     * system services, so the work is split into one chunk per core on the IO dispatcher. Labels are
     * the slowest part (5.7 of 8.4 seconds on the A40, sequentially), so [withLabels] loads them
     * separately: first for the apps on screen, then for the rest.
     */
    suspend fun collect(): List<AppFacts> = coroutineScope {
        val accessibility = enabledAccessibilityPackages()
        val listeners = enabledNotificationListenerPackages()
        val admins = context.getSystemService(DevicePolicyManager::class.java)
            .activeAdmins.orEmpty().map { it.packageName }.toSet()
        val launchable = launchablePackages()
        val roles = roleHolders()
        val quiet = quietRoles()
        val packages = installedPackages()
        packages.inParallel { info ->
            facts(info, accessibility, listeners, admins)?.let { app ->
                app.copy(
                    launcherIcon = app.packageName in launchable,
                    worksUnopened = app.packageName in roles || app.isVpnApp || app.special.any { it in BOUND_ACCESS },
                    quietRole = quiet[app.packageName],
                )
            }
        }
    }

    /** Fills in the labels of [apps], in parallel. */
    suspend fun withLabels(apps: List<AppFacts>): List<AppFacts> = apps.inParallel { app ->
        val label = try {
            pm.getApplicationInfo(app.packageName, 0).loadLabel(pm).toString()
        } catch (_: PackageManager.NameNotFoundException) {
            null // Uninstalled since the audit ran.
        }
        app.copy(label = label)
    }

    /**
     * What one app holds now, read again when the user comes back from a system screen of the
     * remediation plan (ADR 0026); [ItemState.UNINSTALLED] once it is gone.
     */
    fun state(packageName: String): ItemState {
        val info = try {
            packageInfo(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            return ItemState.UNINSTALLED
        }
        val admins = context.getSystemService(DevicePolicyManager::class.java).activeAdmins.orEmpty().map { it.packageName }.toSet()
        val app = facts(info, enabledAccessibilityPackages(), enabledNotificationListenerPackages(), admins) ?: return ItemState.UNINSTALLED
        return ItemState.of(app)
    }

    /**
     * The apps that the safety floor protects on this phone (ADR 0026, point 5), apart from its
     * deny-list: the default home, phone, SMS and browser apps, every enabled keyboard, the screen
     * readers in use, the device or profile owner and preinstalled device admins, the package installer
     * and permission controller, and Datapavan. [apps] tells preinstalled admins apart.
     */
    fun protectedApps(apps: List<AppFacts>): Map<String, FloorReason> = buildMap {
        fun protect(packageName: String?, reason: FloorReason) {
            // "android" resolves an intent that has no default, with its chooser.
            if (packageName != null && packageName != PLATFORM && packageName !in this) put(packageName, reason)
        }
        protect(context.packageName, FloorReason.DATAPAVAN)
        protect(defaultActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME))?.activityInfo?.packageName, FloorReason.HOME)
        protect(context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage, FloorReason.PHONE)
        protect(Telephony.Sms.getDefaultSmsPackage(context), FloorReason.SMS)
        val web = Intent(Intent.ACTION_VIEW, "https://example.org/".toUri()).addCategory(Intent.CATEGORY_BROWSABLE)
        protect(defaultActivity(web)?.activityInfo?.packageName, FloorReason.BROWSER)
        context.getSystemService(InputMethodManager::class.java).enabledInputMethodList.forEach { protect(it.packageName, FloorReason.KEYBOARD) }
        val accessibility = context.getSystemService(AccessibilityManager::class.java)
        // Only while a screen reader is on, so that an app cannot hide from the plan by declaring speech.
        if (accessibility.isTouchExplorationEnabled) {
            accessibility.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_SPOKEN or AccessibilityServiceInfo.FEEDBACK_BRAILLE)
                .forEach { protect(it.resolveInfo.serviceInfo.packageName, FloorReason.SCREEN_READER) }
        }
        val policy = context.getSystemService(DevicePolicyManager::class.java)
        val system = apps.filter { it.isSystem }.map { it.packageName }.toSet()
        for (admin in policy.activeAdmins.orEmpty().map { it.packageName }.distinct()) {
            when {
                policy.isDeviceOwnerApp(admin) || policy.isProfileOwnerApp(admin) -> protect(admin, FloorReason.DEVICE_OWNER)
                admin in system -> protect(admin, FloorReason.PREINSTALLED_ADMIN)
            }
        }
        val apk = Intent(Intent.ACTION_VIEW).setDataAndType("content://org.visadahyu.datapavan/app.apk".toUri(), APK_TYPE)
        protect(defaultActivity(apk)?.activityInfo?.packageName, FloorReason.INSTALLER)
        protect(defaultActivity(Intent(Intent.ACTION_DELETE, Uri.fromParts("package", context.packageName, null)))?.activityInfo?.packageName, FloorReason.INSTALLER)
        val permissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Intent(Intent.ACTION_AUTO_REVOKE_PERMISSIONS, Uri.fromParts("package", context.packageName, null))
        } else {
            Intent(ACTION_MANAGE_PERMISSIONS)
        }
        protect(defaultActivity(permissions)?.activityInfo?.packageName, FloorReason.PERMISSION_CONTROLLER)
    }

    private fun packageInfo(packageName: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PACKAGE_FLAGS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, PACKAGE_FLAGS)
        }

    private suspend fun <T, R : Any> List<T>.inParallel(transform: (T) -> R?): List<R> = coroutineScope {
        val chunk = size / Runtime.getRuntime().availableProcessors() + 1
        chunked(chunk).map { part -> async(Dispatchers.IO) { part.mapNotNull(transform) } }.awaitAll().flatten()
    }

    private fun facts(info: PackageInfo, accessibility: Set<String>, listeners: Set<String>, admins: Set<String>): AppFacts? {
        val app = info.applicationInfo ?: return null
        val granted = grantedDangerous(info)
        val special = buildSet {
            if (info.packageName in accessibility) add(SpecialAccess.ACCESSIBILITY)
            if (info.packageName in listeners) add(SpecialAccess.NOTIFICATION_LISTENER)
            if (info.packageName in admins) add(SpecialAccess.DEVICE_ADMIN)
            for ((permission, op, access) in APP_OP_ACCESS) {
                if (info.requestedPermissions?.contains(permission) == true && opAllowed(op, permission, app.uid, info.packageName)) add(access)
            }
            if (power.isIgnoringBatteryOptimizations(info.packageName)) add(SpecialAccess.BATTERY_EXEMPT)
        }
        return AppFacts(
            packageName = info.packageName,
            label = null,
            isSystem = app.flags and ApplicationInfo.FLAG_SYSTEM != 0,
            enabled = app.enabled,
            updatedSystemApp = app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0,
            installer = installer(info.packageName),
            firstInstall = info.firstInstallTime,
            lastUpdate = info.lastUpdateTime,
            grantedDangerous = granted,
            sensors = SENSOR_PERMISSIONS.filterKeys { it in granted }.values.toSet(),
            special = special,
            isVpnApp = info.services.orEmpty().any { it.permission == Manifest.permission.BIND_VPN_SERVICE },
            vpnAuthorised = opMode(OP_ACTIVATE_VPN, app.uid, info.packageName) == AppOpsManager.MODE_ALLOWED,
            signing = appSigning(info),
            uid = app.uid,
        )
    }

    private fun launchablePackages(): Set<String> =
        activities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)).map { it.activityInfo.packageName }.toSet()

    private fun activities(intent: Intent): List<ResolveInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(intent, 0)
        }

    /** The activity that [intent] opens by default, or null when the user has not chosen one. */
    private fun defaultActivity(intent: Intent): ResolveInfo? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)
        }

    /**
     * Apps that work without being opened because of a role the user gave them: the enabled keyboards,
     * the home screen, the default SMS and phone apps, the live wallpaper, and every app that offers a
     * widget (whether one is placed cannot be read).
     */
    private fun roleHolders(): Set<String> = buildSet {
        context.getSystemService(InputMethodManager::class.java).enabledInputMethodList.mapTo(this) { it.packageName }
        defaultActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME))?.activityInfo?.packageName?.let(::add)
        Telephony.Sms.getDefaultSmsPackage(context)?.let(::add)
        context.getSystemService(TelecomManager::class.java)?.defaultDialerPackage?.let(::add)
        try {
            WallpaperManager.getInstance(context).wallpaperInfo?.packageName?.let(::add)
        } catch (_: SecurityException) {
            // Some versions guard the wallpaper; a live wallpaper is then not known.
        }
        AppWidgetManager.getInstance(context)?.installedProviders.orEmpty().mapTo(this) { it.provider.packageName }
    }

    /**
     * Apps whose manifests declare a keyboard, a live wallpaper or a home screen, in use or not: roles
     * that need no network (ADR 0025). An app with several gets the first in that order.
     */
    private fun quietRoles(): Map<String, QuietRole> = buildMap {
        for (home in activities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME))) put(home.activityInfo.packageName, QuietRole.HOME)
        for (wallpaper in services(Intent(WallpaperService.SERVICE_INTERFACE))) put(wallpaper.serviceInfo.packageName, QuietRole.LIVE_WALLPAPER)
        for (keyboard in services(Intent(InputMethod.SERVICE_INTERFACE))) put(keyboard.serviceInfo.packageName, QuietRole.KEYBOARD)
    }

    private fun services(intent: Intent): List<ResolveInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentServices(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.queryIntentServices(intent, 0)
        }

    /** System label of a permission in the user's language, e.g. "Microphone" for `RECORD_AUDIO`. */
    fun permissionLabel(permission: String): String = try {
        pm.getPermissionInfo(permission, 0).loadLabel(pm).toString()
    } catch (_: PackageManager.NameNotFoundException) {
        permission.substringAfterLast('.')
    }

    private fun installedPackages(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PACKAGE_FLAGS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PACKAGE_FLAGS)
        }

    private fun grantedDangerous(info: PackageInfo): List<String> {
        val requested = info.requestedPermissions ?: return emptyList()
        val flags = info.requestedPermissionsFlags ?: return emptyList()
        return requested.filterIndexed { i, permission ->
            flags.getOrNull(i)?.let { it and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 } == true && isDangerous(permission)
        }
    }

    private fun isDangerous(permission: String): Boolean = dangerous.getOrPut(permission) {
        try {
            pm.getPermissionInfo(permission, 0).protection == PermissionInfo.PROTECTION_DANGEROUS
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun installer(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun opMode(op: String, uid: Int, packageName: String): Int = try {
        appOps.unsafeCheckOpNoThrow(op, uid, packageName)
    } catch (_: SecurityException) {
        AppOpsManager.MODE_ERRORED
    } catch (_: IllegalArgumentException) {
        AppOpsManager.MODE_ERRORED
    }

    /** The rule system Settings uses: an explicit allow, or the default mode with the permission granted. */
    private fun opAllowed(op: String, permission: String, uid: Int, packageName: String): Boolean = when (opMode(op, uid, packageName)) {
        AppOpsManager.MODE_ALLOWED -> true
        AppOpsManager.MODE_DEFAULT -> pm.checkPermission(permission, packageName) == PackageManager.PERMISSION_GRANTED
        else -> false
    }

    /**
     * Services the system has bound, plus the user's setting. The setting matters because Android
     * hides bound services from other apps while a UI automation session runs (as in our own
     * end-to-end checks), and it is what the user actually switched on.
     */
    private fun enabledAccessibilityPackages(): Set<String> =
        context.getSystemService(AccessibilityManager::class.java)
            .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .map { it.resolveInfo.serviceInfo.packageName }
            .toSet() + componentPackages(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)

    private fun enabledNotificationListenerPackages(): Set<String> = componentPackages(SETTING_NOTIFICATION_LISTENERS)

    /** Packages in a secure setting that lists components as `package/class:package/class`. */
    private fun componentPackages(key: String): Set<String> {
        val setting = try {
            Settings.Secure.getString(context.contentResolver, key)
        } catch (_: SecurityException) {
            null
        }
        return setting.orEmpty().split(':').mapNotNull { it.substringBefore('/').takeIf(String::isNotBlank) }.toSet()
    }

    private companion object {
        const val SETTING_NOTIFICATION_LISTENERS = "enabled_notification_listeners"
        const val OP_ACTIVATE_VPN = "android:activate_vpn"
        const val PLATFORM = "android"
        const val PACKAGE_FLAGS = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_SIGNING_CERTIFICATES
        const val APK_TYPE = "application/vnd.android.package-archive"

        /** The permission controller's own action on Android 10, which has no public one. */
        const val ACTION_MANAGE_PERMISSIONS = "android.intent.action.MANAGE_PERMISSIONS"

        /** Special access through which the system keeps an app running without it being opened. */
        val BOUND_ACCESS = setOf(SpecialAccess.ACCESSIBILITY, SpecialAccess.NOTIFICATION_LISTENER, SpecialAccess.DEVICE_ADMIN)

        val APP_OP_ACCESS = listOf(
            Triple(Manifest.permission.SYSTEM_ALERT_WINDOW, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, SpecialAccess.OVERLAY),
            Triple(Manifest.permission.PACKAGE_USAGE_STATS, AppOpsManager.OPSTR_GET_USAGE_STATS, SpecialAccess.USAGE_ACCESS),
            Triple(Manifest.permission.REQUEST_INSTALL_PACKAGES, "android:request_install_packages", SpecialAccess.INSTALL_UNKNOWN_APPS),
            Triple("android.permission.MANAGE_EXTERNAL_STORAGE", "android:manage_external_storage", SpecialAccess.ALL_FILES),
        )

    }
}

/** Reads device-wide settings, user certificate authorities and hardware key attestation. */
class DeviceCollector(private val context: Context) {

    fun collect(): DeviceFacts {
        val check = integrity()
        return DeviceFacts(
            usbDebugging = global(Settings.Global.ADB_ENABLED) == "1",
            wirelessDebugging = global(SETTING_ADB_WIFI) == "1",
            userCertificateAuthorities = userCertificateAuthorities(),
            vpnActive = vpnActive(),
            integrity = check.integrity,
            integrityFailure = check.failure,
            hardwareKeystore = hardwareKeystore(),
            emulator = Build.HARDWARE in EMULATOR_HARDWARE,
        )
    }

    /**
     * Whether the phone declares secure hardware for its keys ([HardwareCheck.declaresHardware]). The package
     * manager answers this from the system server, apart from the keystore, so a hook in the keystore does not
     * change it. It is a declaration, not proof: Android's emulator declares a keystore in a trusted environment
     * for its KeyMint, which runs in software, and so it is weighed with [EMULATOR_HARDWARE]; a system modified
     * with root can also hide the declaration (the feature's file in the vendor partition). A phone upgraded to
     * Android 12 or later whose vendor partition stayed as it shipped may not declare it, and on Android 10 and 11
     * without a secure chip no public API says: there, the check cannot tell a software answer from a phone
     * without such hardware.
     */
    private fun hardwareKeystore(): Boolean = HardwareCheck.declaresHardware(context.packageManager::hasSystemFeature)

    /** Debugging and user certificate authorities only, read again after a system screen of the plan (ADR 0026). */
    fun planState(): ItemState = ItemState(
        usbDebugging = global(Settings.Global.ADB_ENABLED) == "1",
        wirelessDebugging = global(SETTING_ADB_WIFI) == "1",
        authorities = userCertificateAuthorities().size,
    )

    private fun global(key: String): String? = try {
        Settings.Global.getString(context.contentResolver, key)
    } catch (_: SecurityException) {
        null
    }

    private fun userCertificateAuthorities(): List<String> = try {
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        store.aliases().toList().filter { it.startsWith("user:") }.mapNotNull {
            (store.getCertificate(it) as? X509Certificate)?.subjectX500Principal?.name
        }
    } catch (_: java.security.GeneralSecurityException) {
        emptyList()
    } catch (_: IOException) {
        emptyList()
    }

    private fun vpnActive(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = cm.activeNetwork ?: return false
        return cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    /**
     * The hardware check (HardwareCheck), with AndroidKeyStore, the parsers' isolated process and the phone's
     * clock.
     *
     * Every phone this app runs on can attest: Android requires it of phones that launched with Android 8 or
     * later, and the keystore of the few that launched earlier and run Android 10 attests in software, as the
     * Pixel XL's chain in Google's test data shows. No public API says which version a phone launched with, so a
     * failure counts everywhere.
     *
     * What a system that hooks the keystore can still do, so that the result is reported as what the keystore
     * states, never as proof: sign a whole chain with an attestation key that leaked and is not yet revoked; or
     * pass the challenge to another phone that it controls, locked and sound, and show that phone's answer as
     * this one's. A hook inside this app's own process can do more: make the challenge one it knows, so that a
     * captured genuine chain from any phone answers it, or hand back certificates whose signature check lies.
     * Only a check from outside the phone (ADR 0040, decision 6) closes all three.
     *
     * On a phone that declares secure hardware for its keys ([hardwareKeystore]), a hook cannot make the answer
     * quiet, but it can still make it medium where an unlocked bootloader is high: a chain at a hardware level
     * under a root of its own (unconfirmed), a broken chain, a failed check, or the error that says the keys are
     * unavailable (waiting for Google). With root, a modified system can also hide the declaration, the feature's
     * file in the vendor partition, and a software answer then reads as on a phone without such hardware (low).
     * Remembering an earlier sound check on the phone would not close these (ADR 0040: unlocking wipes the
     * memory, and root can erase it); decision 6's check from a second phone, which pins what it saw, does.
     */
    private fun integrity(): IntegrityResult {
        val keystore = try {
            AndroidAttestationKeystore()
        } catch (_: java.security.GeneralSecurityException) {
            return IntegrityResult(failure = IntegrityFailure.FAILED)
        } catch (_: IOException) {
            return IntegrityResult(failure = IntegrityFailure.FAILED)
        }
        val random = SecureRandom()
        return HardwareCheck(
            keystore = keystore,
            chains = ::attestationChain,
            // Parsed in the parsers' isolated process (ParserService), like every untrusted input.
            parse = { extension -> Parsers(context).use { it.parseAttestation(extension) } },
            random = random::nextBytes,
            now = ::Date,
            failure = ::failureOf,
        ).run()
    }

    /** What a failed check means ([HardwareCheck.failureOf]), from the keystore's errors among its causes. */
    private fun failureOf(error: Exception): IntegrityFailure {
        val errors = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            generateSequence<Throwable>(error) { it.cause }.take(MAX_CAUSES)
                .filterIsInstance<android.security.KeyStoreException>()
                .map { KeystoreError(it.numericErrorCode, it.retryPolicy) }
        } else {
            emptySequence()
        }
        return HardwareCheck.failureOf(errors)
    }

    private fun attestationChain(): AttestationChain {
        val data = DataPackStore.get(context)
        return AttestationChain.load(data.active, data.bundled)
    }

    private companion object {
        const val SETTING_ADB_WIFI = "adb_wifi_enabled"

        /** How far down an exception's causes to look; the keystore's errors are one or two deep. */
        const val MAX_CAUSES = 8

        /**
         * `Build.HARDWARE` (ro.hardware) of Android's emulator: "ranchu" since 2015, "goldfish" before. The system
         * sets it, so a modified one can claim it; a phone that does so is then told, in words, that it calls itself
         * an emulator, which its owner can see is false.
         */
        val EMULATOR_HARDWARE = setOf("ranchu", "goldfish")
    }
}

/** AndroidKeyStore, for the hardware check: P-256 signing keys, each with an attestation of its own. */
private class AndroidAttestationKeystore : AttestationKeystore {
    private val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    override fun generate(alias: String, challenge: ByteArray): PublicKey {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        generator.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build(),
        )
        return generator.generateKeyPair().public
    }

    override fun chain(alias: String): List<X509Certificate> =
        store.getCertificateChain(alias)?.filterIsInstance<X509Certificate>().orEmpty()

    override fun aliases(): List<String> = store.aliases().toList()

    override fun delete(alias: String) = store.deleteEntry(alias)

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
    }
}
