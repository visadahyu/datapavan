package org.visadahyu.datapavan.probe

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.view.accessibility.AccessibilityManager
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * M2 feasibility spike: logs, under the tag DPPROBE, what a normal app can read about other apps
 * and the device without privileges. Start with
 * `adb shell am start -n org.visadahyu.datapavan/.probe.ProbeActivity [--es targets a,b]`.
 */
class ProbeActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent.hasExtra("cleanup")) {
            // Only the admin app itself can drop a non-test device admin.
            getSystemService(DevicePolicyManager::class.java)
                .removeActiveAdmin(android.content.ComponentName(this, ProbeAdminReceiver::class.java))
            out("cleanup", "device admin removed")
            finish()
            return
        }
        val targets = intent.getStringExtra("targets")?.split(',')?.filter { it.isNotBlank() }.orEmpty()
        Thread {
            out("begin", "sdk=${Build.VERSION.SDK_INT} release=${Build.VERSION.RELEASE} device=${Build.MANUFACTURER} ${Build.MODEL}")
            check("packages") { packages() }
            for (t in targets) check("target $t") { target(t) }
            check("appops-sweep") { appOpsSweep() }
            check("battery-exempt") { batteryExempt() }
            check("accessibility") { accessibility() }
            check("notification-listeners") { notificationListeners() }
            check("device-admins") { deviceAdmins() }
            check("vpn") { vpn() }
            check("user-ca") { userCas() }
            check("debugging") { debugging() }
            check("attestation") { attestation() }
            for (t in targets) check("apk-read $t") { apkRead(t) }
            check("netstats") { netStats() }
            out("end", "done")
            runOnUiThread { finish() }
        }.start()
    }

    private fun out(check: String, result: String) = Log.i(TAG, "$check | $result")

    private fun check(name: String, block: () -> String) {
        val result = try {
            block()
        } catch (e: Throwable) {
            "ERROR ${e.javaClass.simpleName}: ${e.message}"
        }
        out(name, result)
    }

    @Suppress("DEPRECATION")
    private fun installed(flags: Int = 0): List<PackageInfo> = packageManager.getInstalledPackages(flags)

    private fun packages(): String {
        val all = installed()
        val system = all.count { (it.applicationInfo?.flags ?: 0) and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0 }
        return "visible=${all.size} system=$system user=${all.size - system}"
    }

    @Suppress("DEPRECATION")
    private fun target(pkg: String): String {
        val pm = packageManager
        val info = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
        val installer = if (Build.VERSION.SDK_INT >= 30) {
            val s = pm.getInstallSourceInfo(pkg)
            "installing=${s.installingPackageName} initiating=${s.initiatingPackageName} originating=${s.originatingPackageName}"
        } else {
            "installer=${pm.getInstallerPackageName(pkg)}"
        }
        val granted = mutableListOf<String>()
        val denied = mutableListOf<String>()
        info.requestedPermissions?.forEachIndexed { i, perm ->
            val dangerous = try {
                pm.getPermissionInfo(perm, 0).protection == PermissionInfo.PROTECTION_DANGEROUS
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
            if (dangerous) {
                val flags = info.requestedPermissionsFlags?.getOrNull(i) ?: 0
                if (flags and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) granted += perm.substringAfterLast('.') else denied += perm.substringAfterLast('.')
            }
        }
        val uid = info.applicationInfo?.uid ?: -1
        val ops = OPS.joinToString(" ") { op -> "${op.substringAfter(':')}=${opMode(op, uid, pkg)}" }
        return "$installer first=${info.firstInstallTime} updated=${info.lastUpdateTime} " +
            "dangerousGranted=$granted dangerousDenied=$denied ops[$ops] batteryExempt=${power().isIgnoringBatteryOptimizations(pkg)}"
    }

    private fun opMode(op: String, uid: Int, pkg: String): String {
        val aom = getSystemService(AppOpsManager::class.java)
        return try {
            when (aom.unsafeCheckOpNoThrow(op, uid, pkg)) {
                AppOpsManager.MODE_ALLOWED -> "allowed"
                AppOpsManager.MODE_IGNORED -> "ignored"
                AppOpsManager.MODE_ERRORED -> "errored"
                AppOpsManager.MODE_DEFAULT -> "default"
                AppOpsManager.MODE_FOREGROUND -> "foreground"
                else -> "other"
            }
        } catch (e: SecurityException) {
            "SecurityException"
        } catch (e: IllegalArgumentException) {
            "unknown-op"
        }
    }

    /** For every package that requests a special-access permission, read its app-op mode. */
    private fun appOpsSweep(): String {
        val pkgs = installed(PackageManager.GET_PERMISSIONS)
        return SPECIAL.entries.joinToString("; ") { (perm, op) ->
            val requesting = pkgs.filter { it.requestedPermissions?.contains(perm) == true }
            val modes = requesting.groupingBy { opMode(op, it.applicationInfo?.uid ?: -1, it.packageName) }.eachCount()
            // MODE_DEFAULT defers to the permission grant itself.
            val effective = requesting.filter {
                val mode = opMode(op, it.applicationInfo?.uid ?: -1, it.packageName)
                mode == "allowed" || (mode == "default" && packageManager.checkPermission(perm, it.packageName) == PackageManager.PERMISSION_GRANTED)
            }.map { it.packageName }
            "${perm.substringAfterLast('.')}: requesting=${requesting.size} modes=$modes effectiveAllowed=$effective requesters=${requesting.map { it.packageName }.take(15)}"
        }
    }

    private fun power() = getSystemService(PowerManager::class.java)

    private fun batteryExempt(): String {
        val exempt = installed().map { it.packageName }.filter { power().isIgnoringBatteryOptimizations(it) }
        return "count=${exempt.size} ${exempt.take(40)}"
    }

    private fun accessibility(): String {
        val am = getSystemService(AccessibilityManager::class.java)
        val enabled = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).map { it.id }
        val installedCount = am.installedAccessibilityServiceList.size
        val setting = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
        return "enabledApi=$enabled installed=$installedCount secureSetting=$setting"
    }

    private fun notificationListeners(): String {
        val setting = try {
            Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        } catch (e: SecurityException) {
            "SecurityException"
        }
        val declared = packageManager.queryIntentServices(Intent("android.service.notification.NotificationListenerService"), 0)
            .map { it.serviceInfo.packageName }
        return "secureSetting=$setting declaredBy=${declared.size}"
    }

    private fun deviceAdmins(): String {
        val dpm = getSystemService(DevicePolicyManager::class.java)
        return "active=${dpm.activeAdmins?.map { it.flattenToShortString() }}"
    }

    private fun vpn(): String {
        val declared = packageManager.queryIntentServices(Intent("android.net.VpnService"), 0).map { it.serviceInfo.packageName }
        val cm = getSystemService(ConnectivityManager::class.java)
        @Suppress("DEPRECATION")
        val vpnNets = cm.allNetworks.mapNotNull { cm.getNetworkCapabilities(it) }.filter { it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }
        val owners = vpnNets.map { if (Build.VERSION.SDK_INT >= 31) it.ownerUid else -2 }
        val alwaysOn = secure("always_on_vpn_app")
        val lockdown = secure("always_on_vpn_lockdown")
        return "declaredBy=$declared activeVpnNetworks=${vpnNets.size} ownerUids=$owners alwaysOnApp=$alwaysOn lockdown=$lockdown"
    }

    private fun secure(key: String): String = try {
        Settings.Secure.getString(contentResolver, key) ?: "null"
    } catch (e: SecurityException) {
        "SecurityException"
    }

    private fun global(key: String): String = try {
        Settings.Global.getString(contentResolver, key) ?: "null"
    } catch (e: SecurityException) {
        "SecurityException"
    }

    private fun userCas(): String {
        val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val aliases = ks.aliases().toList()
        val user = aliases.filter { it.startsWith("user:") }
        val subjects = user.map { (ks.getCertificate(it) as X509Certificate).subjectX500Principal.name }
        return "system=${aliases.count { it.startsWith("system:") }} user=${user.size} $subjects"
    }

    private fun debugging(): String =
        "adb=${global(Settings.Global.ADB_ENABLED)} adbWifi=${global("adb_wifi_enabled")} devOptions=${global(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)}"

    private fun attestation(): String {
        val alias = "dp-probe-attestation"
        val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        gen.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build(),
        )
        gen.generateKeyPair()
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val chain = ks.getCertificateChain(alias).map { it as X509Certificate }
            val ext = chain.first().getExtensionValue(KEY_DESCRIPTION_OID)
                ?: return "chain=${chain.size} noKeyDescription"
            val desc = Der.parse(Der.parse(ext, 0).content(ext)) // OCTET STRING wrapping the SEQUENCE
            return "chain=${chain.size} root=${chain.last().issuerX500Principal.name.take(60)} ${KeyDescription.describe(desc)}"
        } finally {
            ks.deleteEntry(alias)
        }
    }

    /** M3 feasibility: can a normal app read another app's APK files (for the DEX scan)? */
    private fun apkRead(pkg: String): String {
        val ai = packageManager.getApplicationInfo(pkg, 0)
        val files = listOfNotNull(ai.sourceDir) + ai.splitSourceDirs.orEmpty()
        return files.joinToString(" ") { path ->
            val f = java.io.File(path)
            val magic = try {
                f.inputStream().use { s -> ByteArray(2).also { s.read(it) }.toString(Charsets.ISO_8859_1) }
            } catch (e: Exception) {
                e.javaClass.simpleName
            }
            "${f.name}:${f.length()}:$magic"
        }
    }

    /** M4 feasibility: per-app byte counts from NetworkStatsManager (needs usage access). */
    @Suppress("DEPRECATION")
    private fun netStats(): String {
        val nsm = getSystemService(android.app.usage.NetworkStatsManager::class.java)
        val end = System.currentTimeMillis()
        val start = end - 30L * 24 * 3600 * 1000
        val perUid = mutableMapOf<Int, Long>()
        for (type in listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            val stats = nsm.querySummary(type, null, start, end)
            val b = android.app.usage.NetworkStats.Bucket()
            while (stats.hasNextBucket()) {
                stats.getNextBucket(b)
                perUid.merge(b.uid, b.rxBytes + b.txBytes, Long::plus)
            }
            stats.close()
        }
        val top = perUid.entries.sortedByDescending { it.value }.take(5).map { (uid, bytes) ->
            "${packageManager.getNameForUid(uid) ?: uid}=${bytes / 1024}KiB"
        }
        return "uids=${perUid.size} top=$top"
    }

    private companion object {
        const val TAG = "DPPROBE"
        const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
        val OPS = listOf(
            AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
            AppOpsManager.OPSTR_GET_USAGE_STATS,
            "android:request_install_packages",
            "android:activate_vpn",
            "android:manage_external_storage",
        )
        val SPECIAL = mapOf(
            "android.permission.SYSTEM_ALERT_WINDOW" to AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
            "android.permission.PACKAGE_USAGE_STATS" to AppOpsManager.OPSTR_GET_USAGE_STATS,
            "android.permission.REQUEST_INSTALL_PACKAGES" to "android:request_install_packages",
            "android.permission.MANAGE_EXTERNAL_STORAGE" to "android:manage_external_storage",
        )
    }
}

/** Minimal DER reader, enough to walk an attestation KeyDescription. Spike only. */
private class Der(val tagClass: Int, val constructed: Boolean, val tag: Int, val start: Int, val end: Int, val bytes: ByteArray) {
    fun content(src: ByteArray = bytes): ByteArray = src.copyOfRange(start, end)

    fun children(): List<Der> {
        val out = mutableListOf<Der>()
        var pos = start
        while (pos < end) {
            val d = read(bytes, pos)
            out += d
            pos = d.end
        }
        return out
    }

    fun int(): Long = content().fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }

    companion object {
        fun parse(bytes: ByteArray, offset: Int = 0): Der = read(bytes, offset)

        fun read(b: ByteArray, at: Int): Der {
            var p = at
            val first = b[p++].toInt() and 0xff
            val cls = first shr 6
            val cons = first and 0x20 != 0
            var tag = first and 0x1f
            if (tag == 0x1f) {
                tag = 0
                do {
                    val x = b[p++].toInt() and 0xff
                    tag = (tag shl 7) or (x and 0x7f)
                } while (x and 0x80 != 0)
            }
            var len = b[p++].toInt() and 0xff
            if (len and 0x80 != 0) {
                val n = len and 0x7f
                len = 0
                repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xff) }
            }
            return Der(cls, cons, tag, p, p + len, b)
        }
    }
}

private object KeyDescription {
    private val LEVELS = listOf("Software", "TEE", "StrongBox")
    private val BOOT = listOf("Verified", "SelfSigned", "Unverified", "Failed")

    fun describe(desc: Der): String {
        val f = desc.children()
        val attVersion = f[0].int()
        val attLevel = LEVELS.getOrElse(f[1].int().toInt()) { "?" }
        val root = (rootOfTrust(f[7]) ?: rootOfTrust(f[6]))
        val osPatch = (find(f[7], 706) ?: find(f[6], 706))?.children()?.firstOrNull()?.int()
        return "attVersion=$attVersion attLevel=$attLevel osPatch=$osPatch rootOfTrust=$root"
    }

    private fun find(list: Der, tag: Int): Der? = list.children().firstOrNull { it.tagClass == 2 && it.tag == tag }

    private fun rootOfTrust(list: Der): String? {
        val explicit = find(list, 704) ?: return null
        val seq = explicit.children().first().children()
        val locked = seq[1].content().firstOrNull()?.toInt() != 0
        val state = BOOT.getOrElse(seq[2].int().toInt()) { "?" }
        return "deviceLocked=$locked verifiedBoot=$state"
    }
}
