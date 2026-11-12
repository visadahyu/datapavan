package org.visadahyu.datapavan.watch.chain

import android.content.Context
import android.content.pm.ApplicationInfo
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import android.util.Log
import java.net.InetSocketAddress

/** Finding the user's tool from any part of Watch (W6). Blocking: call it off the main thread. */
object Tools {
    /** Android numbers users by the hundred thousand UIDs (`UserHandle.PER_USER_RANGE`). */
    private const val PER_USER_RANGE = 100_000

    /**
     * The table of tools, as the build put it in the assets, and in debug builds also W6's test tool
     * (src/debug/assets/tools-test.tsv), which release builds do not carry.
     */
    fun table(context: Context): List<KnownTool> {
        val table = context.assets.open(ToolTable.ASSET).bufferedReader().use { ToolTable.parse(it.readText()) }
        val test = try {
            context.assets.open(TEST_ASSET).bufferedReader().use { ToolTable.parse(it.readText()) }
        } catch (e: java.io.FileNotFoundException) {
            emptyList()
        }
        return table + test
    }

    private const val TEST_ASSET = "tools-test.tsv"

    /**
     * Searches for the user's tool once. [from] names the part of Watch that asks (the screen, the
     * service), for the debug log: only a debuggable build writes the search's steps to Android's log,
     * under the tag [TAG]. A release build writes nothing there, since the lines name the user's tool.
     */
    fun search(context: Context, from: String): ToolSearch {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        return ToolFinder(
            packages = context.packageManager,
            table = table(context),
            ownerOf = { local, remote -> ownerOf(connectivity, local, remote) },
            userId = Process.myUid() / PER_USER_RANGE,
            note = if (debuggable) { line -> Log.i(TAG, "$from: $line") } else { _ -> },
        ).search()
    }

    /** The tag of the search's lines in a debug build's log. */
    const val TAG = "WatchChain"

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
