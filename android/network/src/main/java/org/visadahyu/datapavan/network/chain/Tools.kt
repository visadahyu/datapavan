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
        return Guides.withNamedPorts(table + testRows(context), Guides.book(context))
    }

    private const val TEST_ASSET = "tools-test.tsv"

    /** The rows of W6's test tool, which only debug builds carry (src/debug/assets/tools-test.tsv); none in a release. */
    private fun testRows(context: Context): List<KnownTool> = try {
        context.assets.open(TEST_ASSET).bufferedReader().use { ToolTable.parse(it.readText()) }
    } catch (e: java.io.FileNotFoundException) {
        emptyList()
    }

    /** The prefix of this project's own packages, such as W6's test tool's. */
    const val PROJECT_PREFIX = "org.visadahyu.datapavan."

    /**
     * The packages of W6's test tool that count as circumvention tools whatever their key, as a pure function the JVM
     * tests hold (the proxy record's unit D, D8): in a [debuggable] build only, and only a row of [rows] under this
     * project's own prefix ([PROJECT_PREFIX]), so that scripts/verify-chain.sh can check a tool that is not chained. A
     * release build carries no such rows; a row under another prefix is never one, whoever put it there.
     */
    fun testTools(rows: List<KnownTool>, debuggable: Boolean): Set<String> =
        if (debuggable) rows.map { it.packageName }.filter { it.startsWith(PROJECT_PREFIX) }.toSet() else emptySet()

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
     * tool the user chose for the chain ([chosen]) counts as well, by the user's own choice, whatever its key; and in a
     * debug build W6's test tool ([test], [testTools]). This is the set whose proxy rows say they are a tool's own
     * connection (B6); the record's rule for a tool's own connections takes the narrower [carriers].
     */
    fun uids(
        table: List<KnownTool>,
        chosen: String?,
        verdict: (String) -> SignatureVerdict?,
        test: Set<String>,
        uidOf: (String) -> Int?,
    ): Map<Int, String> = found(table, chosen, verdict, uidOf, test) { it.vpnMode || it.proxyMode || it.packageName in NAMED_TOOLS }

    /** [uids] with no test tool, as a release build counts them. */
    fun uids(table: List<KnownTool>, chosen: String?, verdict: (String) -> SignatureVerdict?, uidOf: (String) -> Int?): Map<Int, String> =
        uids(table, chosen, verdict, emptySet(), uidOf)

    /**
     * The circumvention tools whose own connections follow R10 (the proxy record's unit D; audit-D M3, as the maintainer
     * decided on 2026-11-25), by UID, as a pure function the JVM tests hold: those of [uids] that can carry traffic inside
     * Datapavan's VPN. That is a row of mode `proxy` (a `proxy?` mode counting, as B6 does), one of [NAMED_TOOLS], which
     * carry Tor inside, and the chain's tool ([chosen]), whatever its key. A row of mode `vpn` alone, such as Psiphon's,
     * Lantern's or Windscribe's, cannot run its tunnel while Datapavan is the VPN, so its connections inside it are its
     * own API, ads and analytics: it stays an ordinary app, here and for the choice of one app's proxy (unit C). It is
     * the set the engine is handed as the tools, and every line of R10 on the screens reads it.
     */
    fun carriers(
        table: List<KnownTool>,
        chosen: String?,
        verdict: (String) -> SignatureVerdict?,
        test: Set<String>,
        uidOf: (String) -> Int?,
    ): Map<Int, String> = found(table, chosen, verdict, uidOf, test) { it.proxyMode || it.packageName in NAMED_TOOLS }

    /** [carriers] with no test tool, as a release build counts them. */
    fun carriers(table: List<KnownTool>, chosen: String?, verdict: (String) -> SignatureVerdict?, uidOf: (String) -> Int?): Map<Int, String> =
        carriers(table, chosen, verdict, emptySet(), uidOf)

    /** The rows of [table] that [counts] takes, installed and genuine or a test tool's, and the chain's tool. */
    private fun found(
        table: List<KnownTool>,
        chosen: String?,
        verdict: (String) -> SignatureVerdict?,
        uidOf: (String) -> Int?,
        test: Set<String>,
        counts: (KnownTool) -> Boolean,
    ): Map<Int, String> {
        val tools = mutableMapOf<Int, String>()
        for (tool in table) {
            if (!counts(tool) && tool.packageName !in test) continue
            val uid = uidOf(tool.packageName) ?: continue
            if (tool.packageName in test || verdict(tool.packageName) is SignatureVerdict.Genuine) tools[uid] = tool.name
        }
        if (chosen != null) {
            uidOf(chosen)?.let { uid -> tools[uid] = table.firstOrNull { it.packageName == chosen }?.name ?: chosen }
        }
        return tools
    }

    /** Both sets of tools on this phone, read once: [tools] ([uids], B6's) and [carriers] (R10's, which it holds). */
    data class Found(val tools: Map<Int, String>, val carriers: Map<Int, String>)

    /**
     * [uids] and [carriers] on this phone: the table as the build put it in the assets, the keys parsed once for every
     * package ([ToolKeys.judge]) and each package judged once for both, the chain's tool while the chain is on, and in a
     * debug build W6's test tool ([testTools]). Blocking: call it off the main thread, at the tunnel's start and at each
     * change of the apps. With the table or the keys unreadable, only the chain's tool counts.
     */
    fun read(context: Context): Found {
        val table = try {
            table(context)
        } catch (e: java.io.IOException) {
            emptyList()
        }
        val judge: (String) -> SignatureVerdict? = ToolKeys.judge(context) ?: { null }
        val judged = HashMap<String, SignatureVerdict?>()
        // A null verdict is kept too: getOrPut would judge such a package again.
        val verdict = { name: String -> if (name in judged) judged[name] else judge(name).also { judged[name] = it } }
        val chain = ChainSettings.of(context)
        val chosen = chain.lastTool?.packageName?.takeIf { chain.on }
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val test = testTools(testRows(context), debuggable)
        val uidOf = { name: String -> uidOf(context.packageManager, name) }
        return Found(uids(table, chosen, verdict, test, uidOf), carriers(table, chosen, verdict, test, uidOf))
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
