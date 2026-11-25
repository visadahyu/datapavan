package org.visadahyu.datapavan.network.proxy

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process

/**
 * Android's PAC proxy (the proxy record's unit B, B5; measurements 7.2): `com.android.proxyhandler`, which evaluates a
 * PAC file and connects for other apps, the apps left out included, under its own UID inside the tunnel. Most apps do
 * not use it: they connect to the PAC file's proxies themselves. Its UID counts only for Android's own app with a UID
 * of its own (audit-B 17): a system app, of an application UID, with no shared user ID. An app installed later under
 * that name is no system app; and an OEM build that ran the handler under a shared system UID would put the fact on
 * every row of that UID, `system_server`'s own fetches of the PAC file included.
 */
object PacHandler {
    /** The handler's package, in AOSP and on the measured emulators (Android 15 and 17). */
    const val PACKAGE = "com.android.proxyhandler"

    /** Whether a package of that name, with its [flags], [uid] and [sharedUserId], is Android's own handler. */
    fun owns(flags: Int, uid: Int, sharedUserId: String?): Boolean =
        flags and ApplicationInfo.FLAG_SYSTEM != 0 && uid >= Process.FIRST_APPLICATION_UID && sharedUserId == null

    /** The handler's UID on this phone, or null where there is none that [owns] allows. One lookup: any thread. */
    @Suppress("DEPRECATION") // getPackageInfo(String, Int) and sharedUserId: the network part's minimum SDK takes both.
    fun uid(packages: PackageManager): Int? = try {
        val info = packages.getPackageInfo(PACKAGE, 0)
        info.applicationInfo?.takeIf { owns(it.flags, it.uid, info.sharedUserId) }?.uid
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }
}
