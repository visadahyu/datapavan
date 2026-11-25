package org.visadahyu.datapavan.network.chain

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import android.util.Log
import java.net.InetSocketAddress
import org.visadahyu.datapavan.audit.SignatureVerdict
import org.visadahyu.datapavan.network.guides.Guides

/** Finding the user's tool from any part of the network part (W6). Blocking: call it off the main thread. */
object Tools {
    /** Android numbers users by the hundred thousand UIDs (`UserHandle.PER_USER_RANGE`). */
    private const val PER_USER_RANGE = 100_000

    /**
     * The table of tools, as the build put it in the assets, and in debug builds also W6's test tool
     * (src/debug/assets/tools-test.tsv), which release builds do not carry; with the ports the guides have the user
     * set where the tool's profile sets its listener (W8, part 3b: Guides.withNamedPorts).
     */
    fun table(context: Context): List<KnownTool> {
        val table = context.assets.open(ToolTable.ASSET).bufferedReader().use { ToolTable.parse(it.readText()) }
        val test = try {
            context.assets.open(TEST_ASSET).bufferedReader().use { ToolTable.parse(it.readText()) }
        } catch (e: java.io.FileNotFoundException) {
            emptyList()
        }
        return Guides.withNamedPorts(table + test, Guides.book(context))
    }

    private const val TEST_ASSET = "tools-test.tsv"

    /**
     * Searches for the user's tool once. [from] names the part of the network part that asks (the screen, the
     * service), for the debug log: only a debuggable build writes the search's steps to Android's log,
     * under the tag [TAG]. A release build writes nothing there, since the lines name the user's tool.
     */
    fun search(context: Context, from: String): ToolSearch {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        return ToolFinder(
            uidOf = { uidOf(context.packageManager, it) },
            table = table(context),
            ownerOf = { local, remote -> ownerOf(connectivity, local, remote) },
            userId = Process.myUid() / PER_USER_RANGE,
            note = if (debuggable) { line -> Log.i(TAG, "$from: $line") } else { _ -> },
            retryRefused = setOfNotNull(ChainSettings.of(context).lastTool?.packageName),
        ).search()
    }

    /** The tag of the search's lines in a debug build's log. */
    const val TAG = "NetworkChain"

    /**
     * The table's rows of mode `none` that count as circumvention tools all the same: Tor Browser, its alpha, and Briar,
     * which the maintainer named so on 2026-11-24 (the proxy record's PLAN.md; audit-B 7). Telegram, Signal and Datapavan
     * Basic stay out.
     */
    val NAMED_TOOLS = setOf("org.torproject.torbrowser", "org.torproject.torbrowser_alpha", "org.briarproject.briar.android")

    /**
     * The circumvention tools installed, by UID, each with the table's name for it (the proxy record's unit B, B6;
     * audit-B 7 and 18), as a pure function the JVM tests hold. A tool is a row of [table] of mode `vpn` or `proxy` (a
     * mode with `?` counting, as the table's best guess) or one of [NAMED_TOOLS], installed ([uidOf]), whose copy
     * [verdict] judges [SignatureVerdict.Genuine]: by its signing key, never by its package name, so a package of a
     * tool's name signed with another key (`UnknownKey`, `Modified`, `Disguised`, or none recorded) is an ordinary app.
     * A real copy from a store whose key is not recorded yet is one too, until its key is: the honest direction. The
     * tool the user chose for the chain ([chosen]) counts as well, by the user's own choice, whatever its key.
     */
    fun uids(
        table: List<KnownTool>,
        chosen: String?,
        verdict: (String) -> SignatureVerdict?,
        uidOf: (String) -> Int?,
    ): Map<Int, String> {
        val tools = mutableMapOf<Int, String>()
        for (tool in table) {
            if (!tool.vpnMode && !tool.proxyMode && tool.packageName !in NAMED_TOOLS) continue
            val uid = uidOf(tool.packageName) ?: continue
            if (verdict(tool.packageName) is SignatureVerdict.Genuine) tools[uid] = tool.name
        }
        if (chosen != null) {
            uidOf(chosen)?.let { uid -> tools[uid] = table.firstOrNull { it.packageName == chosen }?.name ?: chosen }
        }
        return tools
    }

    /**
     * [uids] on this phone: the table as the build put it in the assets, the keys parsed once for every package
     * ([ToolKeys.judge]), and the chain's tool while the chain is on. Blocking: call it off the main thread, at the
     * tunnel's start and at each change of the apps. With the table or the keys unreadable, only the chain's tool counts.
     */
    fun uids(context: Context): Map<Int, String> {
        val table = try {
            table(context)
        } catch (e: java.io.IOException) {
            emptyList()
        }
        val judge: (String) -> SignatureVerdict? = ToolKeys.judge(context) ?: { null }
        val chain = ChainSettings.of(context)
        val chosen = chain.lastTool?.packageName?.takeIf { chain.on }
        return uids(table, chosen, judge) { uidOf(context.packageManager, it) }
    }

    @Suppress("DEPRECATION")
    private fun uidOf(packages: PackageManager, packageName: String): Int? = try {
        packages.getApplicationInfo(packageName, 0).uid
    } catch (e: PackageManager.NameNotFoundException) {
        null
    }

    /**
     * Android's owner of the TCP connection from [local] to [remote]. Only the active VPN may ask;
     * otherwise, and when Android does not know, null.
     */
    private fun ownerOf(connectivity: ConnectivityManager, local: InetSocketAddress, remote: InetSocketAddress): Int? = try {
        connectivity.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, local, remote).takeIf { it >= 0 }
    } catch (e: SecurityException) {
        null
    } catch (e: IllegalArgumentException) {
        null
    }
}
