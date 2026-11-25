package org.visadahyu.datapavan.network.proxy

/**
 * The rule of the user's choice for one app, "Log where APP connects through a proxy" (the proxy record's unit C, R3),
 * as the network part's screens read it to offer the choice, a pure function the JVM tests hold to the engine's own
 * vectors (core/net/testdata/logged-apps.tsv, which the engine's `LoggedApps::covers` and `app_of` read too). The engine
 * alone decides what is logged: were the two ever to differ, the worst a screen does is offer a link that changes
 * nothing, or miss one.
 */
object ProxyChoice {
    /** Android numbers users by the hundred thousand UIDs (`UserHandle.PER_USER_RANGE`). */
    const val PER_USER_RANGE = 100_000

    /**
     * Whether [uid] is an application's, in any user's range (AOSP's `FIRST_APPLICATION_UID` to `LAST_APPLICATION_UID`):
     * Android's own UIDs, below, are shared by many of its parts and never chosen.
     */
    fun application(uid: Int): Boolean = uid >= 0 && uid % PER_USER_RANGE in 10_000 until 20_000

    /**
     * The app whose code [uid] runs: an SDK Runtime sandbox's (AOSP's `FIRST_SDK_SANDBOX_UID`, 20,000 to 29,999 in each
     * user's range, ten thousand above its app's), else the UID itself. Android assigns both; no app can run in another
     * app's sandbox.
     */
    fun appOf(uid: Int): Int = if (uid >= 0 && uid % PER_USER_RANGE in 20_000 until 30_000) uid - 10_000 else uid

    /**
     * Whether the choice covers a flow of [uid] through a proxy that is Android's setting ([setting]) or on the user's
     * own network ([local]), the apps chosen being [logged], with the circumvention tools [tools] and Android's PAC
     * handler [pacHandler], neither of which is ever chosen: the engine's `LoggedApps::of` and `covers`.
     */
    fun covers(uid: Int?, logged: Collection<Int>, tools: Collection<Int>, pacHandler: Int?, setting: Boolean, local: Boolean): Boolean {
        if (uid == null || setting || local) return false
        val app = appOf(uid)
        return app in logged && application(app) && app !in tools && app != pacHandler
    }

    /**
     * Whether a screen offers the choice on a row of [uid]: choosing its app would cover it ([covers]), and the row is of
     * this user's range ([user], `Process.myUid() / PER_USER_RANGE`), since a vendor's dual app or Android's clone
     * profile runs a copy under another user, and a choice made there would name the package in this one (audit-C 22).
     * A record that never said whether its proxy was local (before log version 7) is not local for the link.
     */
    fun offered(uid: Int?, tools: Collection<Int>, pacHandler: Int?, setting: Boolean, local: Boolean?, user: Int): Boolean =
        uid != null && uid / PER_USER_RANGE == user &&
            covers(uid, listOf(appOf(uid)), tools, pacHandler, setting, local == true)
}
