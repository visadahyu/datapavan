package org.visadahyu.datapavan.audit

import android.Manifest
import android.app.AppOpsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Process

/**
 * Whether this app holds usage access (`PACKAGE_USAGE_STATS`, ADR 0022), by the rule system Settings uses:
 * an explicit allow, or the default mode with the permission granted. One rule for the audit's reader and
 * Watch's tracker of the apps' states (ADR 0046), which run in two processes of one package (android/shared).
 */
fun hasUsageAccess(context: Context): Boolean {
    val mode = context.getSystemService(AppOpsManager::class.java)
        .unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
    return mode == AppOpsManager.MODE_ALLOWED ||
        mode == AppOpsManager.MODE_DEFAULT && context.checkSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) == PackageManager.PERMISSION_GRANTED
}
