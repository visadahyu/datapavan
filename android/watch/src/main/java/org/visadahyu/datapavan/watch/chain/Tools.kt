package org.visadahyu.datapavan.watch.chain

import android.content.Context
import android.net.ConnectivityManager
import android.os.Process
import android.system.OsConstants
import java.net.InetSocketAddress

/** Finding the user's tool from any part of Watch (W6). Blocking: call it off the main thread. */
object Tools {
    /** Android numbers users by the hundred thousand UIDs (`UserHandle.PER_USER_RANGE`). */
    private const val PER_USER_RANGE = 100_000

    /** The table of tools, as the build put it in the assets. */
    fun table(context: Context): List<KnownTool> =
        context.assets.open(ToolTable.ASSET).bufferedReader().use { ToolTable.parse(it.readText()) }

    /** Searches for the user's tool once. */
    fun search(context: Context): ToolSearch {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        return ToolFinder(
            packages = context.packageManager,
            table = table(context),
            ownerOf = { local, remote -> ownerOf(connectivity, local, remote) },
            userId = Process.myUid() / PER_USER_RANGE,
        ).search()
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
