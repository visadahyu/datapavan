package org.visadahyu.datapavan.watch

/**
 * The packet engine in Rust (`core/net`, ADR 0012), through its JNI bridge (`core/watch-jni`). One
 * engine runs at a time; it owns the tunnel's descriptor from [nativeStart] until [nativeStop].
 */
internal object Engine {
    init {
        System.loadLibrary("datapavan_watch")
    }

    /**
     * Starts the engine on the tunnel descriptor [fd], which it takes over (from
     * `ParcelFileDescriptor.detachFd()`). It calls back into [service] for `ownerUid` and
     * `protectSocket`. [keepFlows] is how many of the latest flows it keeps for debug builds; 0 in
     * release builds, where the connection log (W4) decides what is recorded.
     */
    external fun nativeStart(service: WatchVpnService, fd: Int, mtu: Int, keepFlows: Int): Boolean

    /** Stops the engine and closes the tunnel's descriptor. */
    external fun nativeStop()

    /** The network beneath the tunnel changed; [dns] is its DNS server's address, or "" for none. */
    external fun nativeNetworkChanged(dns: String)

    /**
     * The counters: TCP flows, UDP flows, bytes up, bytes down, flows without an owner, refused,
     * unreachable, failed, packets skipped, packets in, packets out. Empty when no engine runs.
     */
    external fun nativeCounters(): LongArray

    /** The flows kept, one per line as `protocol app destination uid outcome`; debug builds only. */
    external fun nativeFlows(): String
}
