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
     * release builds, where the connection log (W4) decides what is recorded. [tableFd], if not -1, is
     * a descriptor of the IP-to-organisation table (ADR 0036), [tableLength] bytes from [tableStart],
     * which the engine takes over as well.
     */
    external fun nativeStart(
        service: WatchVpnService,
        fd: Int,
        mtu: Int,
        keepFlows: Int,
        tableFd: Int,
        tableStart: Long,
        tableLength: Long,
        /** The tunnel's spare addresses, for a network that uses the common ones itself (ADR 0041). */
        spareAddresses: Boolean,
    ): Boolean

    /** Stops the engine and closes the tunnel's descriptor. */
    external fun nativeStop()

    /** The release month of the organisation table the engine reads, such as "2026-11", or "" for none. */
    external fun nativeOrganisations(): String

    /**
     * The network beneath the tunnel or its DNS server changed; [dns] is its DNS server's address, or
     * "" for none, and [moved] says whether the network itself is another one, which closes UDP flows.
     */
    external fun nativeNetworkChanged(dns: String, moved: Boolean)

    /**
     * The counters: TCP flows, UDP flows, bytes up, bytes down, flows without an owner, refused,
     * unreachable, failed, packets skipped, packets in, packets out, server names read from TLS and
     * from QUIC, QUIC flows whose name could not be read, hellos that offered ECH, hellos whose name
     * was an ECH public name, and flows of an app's own plain and encrypted DNS. None names a
     * destination. Empty when no engine runs.
     */
    external fun nativeCounters(): LongArray

    /** Hands the connection log every waiting record now, with each open flow's segment so far; debug builds' test only. */
    external fun nativeFlushLog()

    /**
     * Turns chaining on (W6, ADR 0038): [proxy] and [port] are the address of the tool's SOCKS5 proxy,
     * [user] and [password] its credentials or null, [toolUid] the tool's UID, [apps] the UIDs of the
     * chained apps or null for every app but the tool, [udp] whether the tool carries UDP, and
     * [logDestinations] whether chained flows' destinations go to the log. An empty [proxy] turns
     * chaining off. Returns whether a chain is on; false when no engine runs.
     */
    external fun nativeChain(
        proxy: String,
        port: Int,
        user: ByteArray?,
        password: ByteArray?,
        toolUid: Int,
        apps: IntArray?,
        udp: Boolean,
        logDestinations: Boolean,
    ): Boolean

    /**
     * Whether the answers of the tunnel's DNS address reach the apps with a time to live of 0, so that
     * Android's resolver, which keeps one cache for all apps of a network, keeps none of them; debug
     * builds' DNS spike only, for now (W6).
     */
    external fun nativeUncacheAnswers(on: Boolean)

    /** The flows kept, one per line as `protocol app destination uid outcome named-by ech dns network name`; debug builds only. */
    external fun nativeFlows(): String
}
