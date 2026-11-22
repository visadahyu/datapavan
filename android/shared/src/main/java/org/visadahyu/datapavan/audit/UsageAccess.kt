package org.visadahyu.datapavan.audit

import android.Manifest
import android.app.AppOpsManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Process
import android.provider.Settings

/**
 * Whether this app holds usage access (`PACKAGE_USAGE_STATS`, ADR 0022), by the rule system Settings uses:
 * an explicit allow, or the default mode with the permission granted. One rule for the audit's reader and the
 * network part's tracker of the apps' states (ADR 0046), in two processes of one package (android/shared).
 */
fun hasUsageAccess(context: Context): Boolean {
    val mode = context.getSystemService(AppOpsManager::class.java)
        .unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
    return mode == AppOpsManager.MODE_ALLOWED ||
        mode == AppOpsManager.MODE_DEFAULT && context.checkSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) == PackageManager.PERMISSION_GRANTED
}

/**
 * Opens Android's usage access settings: the page for Datapavan itself where the system offers one, otherwise
 * the list of all apps. The audit's route, which the network part's view "Now" takes too (W5's third part).
 */
fun openUsageAccess(context: Context) {
    val own = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.fromParts("package", context.packageName, null))
    try {
        context.startActivity(own)
    } catch (_: ActivityNotFoundException) {
        context.startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
    }
}
