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
     * Sets the WireGuard configuration [text], in wg-quick's form, as the tunnel [id] (not 0), in place of the
     * one of that number if any (W7, ADR 0035), with "Local network directly" as [localNetwork] says. The text
     * is handed over unwrapped; the caller zeroes its array after. Returns "" when it is set, else why it is
     * refused: a code, a line and a key, never a value (core/net/src/wireguard/config.rs, `Refusal`), or
     * `too-many` for a new one past the engine's bound of eight (`MAX_TUNNELS`, W7, part 2). Kept for the
     * engines to come while none runs, as the chain is; stopping the tunnel forgets it.
     */
    external fun nativeTunnelSet(id: Int, text: ByteArray, localNetwork: Boolean): String

    /**
     * Removes the configuration of the tunnel [id] (W7). The routes to it stay: its apps wait, their flows
     * refused and never sent directly, until [nativeTunnelRoutes] sends them elsewhere or the configuration is
     * set again.
     */
    external fun nativeTunnelRemove(id: Int)

    /**
     * Reads the WireGuard configuration [text] without setting it, for the import (W7, part 2): `refused WHY`, or
     * `ok` and what it does, a line each and never a key (core/net's `Config::describe`): `endpoint HOST PORT`,
     * `address A/P`, `dns A`, `allowed A/P`, `everything 1|0` (whether `AllowedIPs` carry every destination of
     * each version it has an address of), `preshared 1|0`, `mtu N`, `keepalive N` where set, and last a line for
     * each app it names, `only PACKAGE` (`IncludedApplications`) or `except PACKAGE` (`ExcludedApplications`),
     * which the import offers as the choice of apps for the user to confirm ([org.visadahyu.datapavan.watch.tunnel.Import]).
     * The endpoint is for the screen alone: the dump and the log never print it. The caller zeroes its array after.
     */
    external fun nativeTunnelParse(text: ByteArray): String

    /**
     * Puts the tunnels [ids] first, in that order (W7, part 2): the first is the default tunnel, which flows of no
     * app and ICMP echo take while any app goes through a tunnel. The others stay after them as they were, and
     * each keeps its session.
     */
    external fun nativeTunnelOrder(ids: IntArray)

    /**
     * Sends each app of [uids] through the tunnel at the same place in [tunnels], every other app its other way,
     * and keeps their destinations only where [logDestinations] says ("Log where these apps connect", W6's
     * switch). Replaces every route (W7).
     */
    external fun nativeTunnelRoutes(uids: IntArray, tunnels: IntArray, logDestinations: Boolean)

    /**
     * Every installed app's UID, while Watch routes any app (a configuration or the tool), or null when it routes
     * none (W7, part 2, fix round, the maintainer's word of 2026-11-20): a flow of a UID outside them, an app
     * installed since, waits while the engine asks [WatchVpnService.routeOfApp], and goes nowhere until it answers.
     */
    external fun nativeKnownApps(uids: IntArray?)

    /** Debug builds: the engine's answers for the apps Watch did not name, one per line, `uid direct|tool|tunnel:N|refused`. */
    external fun nativeAppAnswers(): String

    /**
     * Each tunnel's state, one per line: `id handshake received error not-answering plain-dns connected flows
     * configured resolutions`, the times in milliseconds ago and `-` for none; `configured` is 0 for a tunnel apps
     * are routed to whose configuration is not set, whose apps wait. No key, no address, no endpoint. Empty when
     * no engine runs.
     */
    external fun nativeTunnelStates(): String

    /**
     * Debug builds' check (scripts/verify-wireguard.sh): how many of the flows kept went each way, by app, one
     * per line: `uid route count`, the route `direct`, `tool` or `tunnel:N`, the UID `-` for flows of no app. No
     * destination.
     */
    external fun nativeFlowRoutes(): String

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
     * Checks a data pack's signature against [keys] and reads its header, with the same Rust code as the audit
     * ([org.visadahyu.datapavan.datapack.PackNative]), so that Watch reads the pack the audit verifies.
     */
    external fun nativeReadDataPack(pack: ByteArray, keys: String): IntArray

    /** Reads the header of the APK's own data payload; as [nativeReadDataPack]. */
    external fun nativeReadDataPayload(payload: ByteArray): IntArray

    /**
     * Reads the εxodus network signatures of the data pack's `exodus/trackers.tsv` ([table]) and keeps them for
     * [nativeTrackersOf], in place of any before: how many trackers have one, how many alternatives were read
     * and how many were refused as outside the subset Watch matches; empty for a table that is not one. No
     * engine needs to run.
     */
    external fun nativeTrackers(table: ByteArray): IntArray

    /**
     * For each line `host<TAB>port` of [hosts] (a name, or an address as text), the names of the trackers whose
     * network signature matches it, separated by tabs, one line each, empty for none.
     */
    external fun nativeTrackersOf(hosts: String): String

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

/** Watch's Rust reader of data packs (core/engine's `datapack`, through Watch's own library). */
internal object WatchPacks : org.visadahyu.datapavan.datapack.PackNative {
    override fun readDataPack(pack: ByteArray, keys: String): IntArray = Engine.nativeReadDataPack(pack, keys)

    override fun readDataPayload(payload: ByteArray): IntArray = Engine.nativeReadDataPayload(payload)
}
