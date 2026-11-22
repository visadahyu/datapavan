package org.visadahyu.datapavan.network

import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.visadahyu.datapavan.network.tunnel.Import
import org.visadahyu.datapavan.network.ui.TunnelsView

/**
 * What the network screen holds of the WireGuard configurations across its recreation (W7, part 2, fix round, screens
 * review M1): a rotation, a dark-mode switch or a font change makes the screen anew, and the confirmation the user
 * had open, with its name and ticks, comes back with it, as does an answer the store's worker gives meanwhile. The
 * configuration on its way is held here, in the network process alone, never in a saved state, which Android copies out
 * of the process; its bytes are zeroed when it is saved or cancelled, and when the screen finishes ([onCleared]).
 */
internal class TunnelModel : ViewModel() {
    /** The WireGuard part of the screen, the confirmation among it. */
    val tunnels = mutableStateOf(TunnelsView())

    /** The configuration on its way to the store. Main thread only. */
    val held = Import.Held()

    /** The slot the import under way replaces, or null for a new configuration. */
    var replacing: Int? = null

    public override fun onCleared() {
        held.drop()
    }

    companion object {
        /**
         * Where the store is changed and read, the Keystore with it: one task at a time, for every screen of the
         * process, so that two changes never cross; its thread ends when idle. Documents and pictures are read on
         * threads of their own, never here (fix round, security review M2).
         */
        val worker = ThreadPoolExecutor(0, 1, 30, TimeUnit.SECONDS, LinkedBlockingQueue()) { task ->
            Thread(task, "network-tunnels").apply { isDaemon = true }
        }
    }
}
