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
import android.net.NetworkCapabilities
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.provider.Telephony
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telecom.TelecomManager
import android.view.accessibility.AccessibilityManager
import android.view.inputmethod.InputMethodManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import org.visadahyu.datapavan.core.NativeCore
import org.visadahyu.datapavan.datapack.DataPackStore
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

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
        val packages = installedPackages()
        packages.inParallel { info ->
            facts(info, accessibility, listeners, admins)?.let { app ->
                app.copy(
                    launcherIcon = app.packageName in launchable,
                    worksUnopened = app.packageName in roles || app.isVpnApp || app.special.any { it in BOUND_ACCESS },
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
            signing = signing(info),
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

    /** SHA-256 of each signing certificate, as apksigner prints it, for matching against ADR 0018's list. */
    private fun signing(info: PackageInfo): AppSigning? {
        val signing = info.signingInfo ?: return null
        val current = signing.apkContentsSigners.orEmpty().toList()
        val history = if (signing.hasMultipleSigners()) current else signing.signingCertificateHistory.orEmpty().toList()
        val debug = current.any { signature ->
            try {
                // A factory per call: facts() runs on several threads at once.
                val certificate = CertificateFactory.getInstance("X.509")
                    .generateCertificate(signature.toByteArray().inputStream()) as X509Certificate
                certificate.subjectX500Principal.name.contains("CN=Android Debug")
            } catch (_: CertificateException) {
                false
            }
        }
        return AppSigning(current.map { sha256(it.toByteArray()) }, history.map { sha256(it.toByteArray()) }, debug)
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(Locale.ROOT, it) }

    /** System label of a permission in the user's language, e.g. "Microphone" for `RECORD_AUDIO`. */
    fun permissionLabel(permission: String): String = try {
        pm.getPermissionInfo(permission, 0).loadLabel(pm).toString()
    } catch (_: PackageManager.NameNotFoundException) {
        permission.substringAfterLast('.')
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES or PackageManager.GET_SIGNING_CERTIFICATES
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(flags)
        }
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

        /** Special access through which the system keeps an app running without it being opened. */
        val BOUND_ACCESS = setOf(SpecialAccess.ACCESSIBILITY, SpecialAccess.NOTIFICATION_LISTENER, SpecialAccess.DEVICE_ADMIN)

        val APP_OP_ACCESS = listOf(
            Triple(Manifest.permission.SYSTEM_ALERT_WINDOW, AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW, SpecialAccess.OVERLAY),
            Triple(Manifest.permission.PACKAGE_USAGE_STATS, AppOpsManager.OPSTR_GET_USAGE_STATS, SpecialAccess.USAGE_ACCESS),
            Triple(Manifest.permission.REQUEST_INSTALL_PACKAGES, "android:request_install_packages", SpecialAccess.INSTALL_UNKNOWN_APPS),
            Triple("android.permission.MANAGE_EXTERNAL_STORAGE", "android:manage_external_storage", SpecialAccess.ALL_FILES),
        )

        val SENSOR_PERMISSIONS = mapOf(
            Manifest.permission.RECORD_AUDIO to Sensor.MICROPHONE,
            Manifest.permission.CAMERA to Sensor.CAMERA,
            Manifest.permission.ACCESS_FINE_LOCATION to Sensor.LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION to Sensor.LOCATION,
        )
    }
}

/** Reads device-wide settings, user certificate authorities and hardware key attestation. */
class DeviceCollector(private val context: Context) {

    fun collect(): DeviceFacts = DeviceFacts(
        usbDebugging = global(Settings.Global.ADB_ENABLED) == "1",
        wirelessDebugging = global(SETTING_ADB_WIFI) == "1",
        userCertificateAuthorities = userCertificateAuthorities(),
        vpnActive = vpnActive(),
        integrity = integrity(),
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
     * Creates a throwaway key with an attestation challenge, reads the `KeyDescription` extension of
     * its certificate, checks the certificate chain against Google's attestation roots and revocation
     * list, and deletes the key again. A compromised system can still tamper with this check on itself
     * (with a leaked key that is not yet revoked), so the result is reported as what the keystore
     * states, never as proof.
     */
    private fun integrity(): Integrity? {
        val store = try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }
        } catch (_: java.security.GeneralSecurityException) {
            return null
        }
        return try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(ATTESTATION_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(ByteArray(CHALLENGE_BYTES).also { SecureRandom().nextBytes(it) })
                    .build(),
            )
            generator.generateKeyPair()
            val chain = store.getCertificateChain(ATTESTATION_ALIAS)?.filterIsInstance<X509Certificate>().orEmpty()
            val extension = chain.firstOrNull()?.getExtensionValue(KEY_DESCRIPTION_OID) ?: return null
            val fields = NativeCore.parseAttestation(extension)
            Integrity(
                securityLevel = fields[1].toInt(),
                deviceLocked = fields[2].takeIf { it >= 0 }?.let { it == 1L },
                verifiedBoot = fields[3].takeIf { it >= 0 }?.toInt(),
                osPatchLevel = fields[4].takeIf { it >= 0 }?.toInt(),
                trust = attestationChain().trust(chain),
            )
        } catch (_: java.security.GeneralSecurityException) {
            null
        } catch (_: IOException) {
            // The data pack lacks the roots or the revocation list; the smoke test catches this.
            null
        } catch (_: RuntimeException) {
            // Malformed extension (thrown by the Rust parser) or a keystore without attestation.
            null
        } finally {
            try {
                store.deleteEntry(ATTESTATION_ALIAS)
            } catch (_: java.security.KeyStoreException) {
                // Nothing to clean up.
            }
        }
    }

    private fun attestationChain(): AttestationChain {
        val data = DataPackStore.get(context)
        val roots = data.file(AttestationChain.ROOTS_PATH) ?: throw IOException(AttestationChain.ROOTS_PATH)
        val revoked = data.file(AttestationChain.REVOKED_PATH) ?: throw IOException(AttestationChain.REVOKED_PATH)
        return AttestationChain.load(roots.inputStream(), revoked.inputStream())
    }

    private companion object {
        const val SETTING_ADB_WIFI = "adb_wifi_enabled"
        const val KEYSTORE = "AndroidKeyStore"
        const val ATTESTATION_ALIAS = "datapavan-integrity-check"
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
        const val CHALLENGE_BYTES = 16
    }
}
