package org.visadahyu.datapavan.watch

/**
 * The packet engine in Rust (`core/net`, ADR 0012), through its JNI bridge (`core/watch-jni`). One
 * engine runs at a time; it owns the tunnel's descriptor from [nativeStart] or [nativeSwapTunnel] until
 * [nativeStop].
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

    /**
     * Hands the running engine the tunnel set up again with the same addresses on the same VPN network
     * ([TunnelSetup]), the descriptor [fd], which it takes over as [nativeStart] does (from
     * `ParcelFileDescriptor.detachFd()`): the engine goes
     * on with it in place of the old tunnel, keeping its connections, mappings, ping sockets, chain,
     * names, stand-ins and counters, and closes the old one once it has handled what was still queued
     * on it (ADR 0044, unit 12b). Returns whether it took it; false, with [fd] closed, when no engine
     * runs or it could not take it.
     */
    external fun nativeSwapTunnel(fd: Int): Boolean

    /** Stops the engine and closes the tunnel's descriptor. */
    external fun nativeStop()

    /**
     * The MTU the kernel keeps for the route of the connected socket [fd] (`IP_MTU`), or -1 when it says
     * nothing: how [TunnelMtu]'s probe reads the first hop's, since `android.system.Os` offers apps no
     * `getsockoptInt`. The caller keeps [fd] open for the call; no engine needs to run.
     */
    external fun nativeRouteMtu(fd: Int): Int

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
     * was an ECH public name, and flows of an app's own plain and encrypted DNS; then those that
     * `Counters::snapshot` in core/net lists after them: among them the refusals and evictions of the
     * budget for the engine and for each app, the echo requests carried, their replies, and those
     * refused, unsupported or dropped (ADR 0044, decisions 3 and 5), and last the datagrams put together
     * from the apps' fragments, those the engine's kernel refused to send as too long, dropped, and the
     * routers' "fragmentation needed" and "packet too big" passed on to the apps (decision 5 as amended;
     * the 20th counts the fragments dropped); and last the seconds, and segments with no count, placed in no
     * state because their app's state was told too late (W5, ADR 0046). New ones are only appended. None
     * names a destination.
     * Empty when no engine runs.
     */
    external fun nativeCounters(): LongArray

    /** Hands the connection log every waiting record now, with each open flow's segment so far; debug builds' test only. */
    external fun nativeFlushLog()

    /**
     * Turns chaining on (W6, ADR 0038): [proxy] and [port] are the address of the tool's SOCKS5 proxy,
     * [user] and [password] its credentials or null, [toolUid] the tool's UID, [apps] the UIDs of the
     * chained apps or null for every app but the tool, [udp] whether the tool carries UDP, and
     * [logDestinations] whether chained flows' destinations go to the log. An empty [proxy] turns
     * chaining off. Returns whether a chain is on; false when no engine runs, as at a start, where
     * Watch sets the chain before the engine (unit 12b), or for a moment while the tunnel is set up
     * again with other addresses: the chain is kept all the same, and the next engine starts with it
     * (ADR 0044, unit 12). Stopping the tunnel forgets it.
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

    /**
     * Hands the running engine a reading of the apps' states ([org.visadahyu.datapavan.watch.activity.States],
     * ADR 0046, decision 1): it places every second the reading covers and cuts the log's segments where an
     * app's state changed. Whether an engine took it; false when none runs or the message is not one of its
     * version.
     */
    external fun nativeStates(message: ByteArray): Boolean

    /**
     * What the live view "Now" draws ([org.visadahyu.datapavan.watch.activity.Snapshot]): each app's bytes by
     * state in the last 10 minutes, the last hour and since the screen came on, and its destinations, from
     * the engine's memory. Empty when no engine runs. Cheap: read every second while the view is open.
     */
    external fun nativeActivity(): ByteArray

    /**
     * Forgets everything the live view holds: every app's bytes in every window, its destinations, the window
     * while the screen was off and the organisations looked up; seconds before now stay out of the view when
     * they are placed later. ADR 0047's profile will call it at each screen-off (W9); for now only debug
     * builds' dump reaches it (`activity-clear`). It cannot clear the flows still open, nor what waits for the
     * log. Nothing when no engine runs.
     */
    external fun nativeClearActivity()

    /**
     * The flows kept, one per line as `protocol app destination uid outcome named-by ech dns network dns-name name`,
     * `dns-name` being the DNS answer's name where it differs from the connection's own; debug builds only.
     */
    external fun nativeFlows(): String
}
