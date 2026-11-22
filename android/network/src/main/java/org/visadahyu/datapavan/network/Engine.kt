package org.visadahyu.datapavan.network

/**
 * The packet engine in Rust (`core/net`, ADR 0012), through its JNI bridge (`core/network-jni`). One
 * engine runs at a time; it owns the tunnel's descriptor from [nativeStart] or [nativeSwapTunnel] until
 * [nativeStop].
 */
internal object Engine {
    init {
        System.loadLibrary("datapavan_network")
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
        service: NetworkVpnService,
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
     * state because their app's state was told too late (W5, ADR 0046); and at 67 to 70 tracker blocking's
     * (W8, part 3a, ADR 0053): lookups answered with no address, connections refused, of those the ones refused
     * by their address, and connections whose start was held while it read as an unfinished hello. New ones are
     * only appended. None names a destination.
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
     * the network part sets the chain before the engine (unit 12b), or for a moment while the tunnel is set up
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
     * which the import offers as the choice of apps for the user to confirm ([org.visadahyu.datapavan.network.tunnel.Import]).
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
     * Every installed app's UID, while the network part routes any app (a configuration or the tool), or null when it
     * routes none (W7, part 2, fix round, the maintainer's word of 2026-11-20): a flow of a UID outside them, an app
     * installed since, waits while the engine asks [NetworkVpnService.routeOfApp], and goes nowhere until it answers.
     */
    external fun nativeKnownApps(uids: IntArray?)

    /**
     * Debug builds: the engine's answers for the apps the network part did not name, one per line, `uid
     * direct|tool|tunnel:N|refused`.
     */
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
     * Hands the running engine a reading of the apps' states ([org.visadahyu.datapavan.network.activity.States],
     * ADR 0046, decision 1): it places every second the reading covers and cuts the log's segments where an
     * app's state changed. Whether an engine took it; false when none runs or the message is not one of its
     * version.
     */
    external fun nativeStates(message: ByteArray): Boolean

    /**
     * What the live view "Now" draws ([org.visadahyu.datapavan.network.activity.Snapshot]): each app's bytes by
     * state in the last 10 minutes, the last hour and since the screen came on, and its destinations, from
     * the engine's memory. Empty when no engine runs. Cheap: read every second while the view is open.
     */
    external fun nativeActivity(): ByteArray

    /**
     * Checks a data pack's signature against [keys] and reads its header, with the same Rust code as the audit
     * ([org.visadahyu.datapavan.datapack.PackNative]), so that the network part reads the pack the audit verifies.
     */
    external fun nativeReadDataPack(pack: ByteArray, keys: String): IntArray

    /** Reads the header of the APK's own data payload; as [nativeReadDataPack]. */
    external fun nativeReadDataPayload(payload: ByteArray): IntArray

    /**
     * Reads the εxodus network signatures of the data pack's `exodus/trackers.tsv` ([table]) and keeps them for
     * [nativeTrackersOf], in place of any before: how many trackers have one, how many alternatives were read
     * and how many were refused as outside the subset the network part matches; empty for a table that is not one. No
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
     * The messengers' apps whose built-in proxies the engine infers, each UID of [uids] of the family at the same
     * place in [families] (0 Telegram, 1 WhatsApp, 2 Signal), and the proxies Android's setting names, one `host port`
     * a line in [android] (W8, part 2a, ADR 0052), and whether Private DNS is strict on the network part's network
     * ([strictDns]), which hides the apps' lookups from the network part. Kept for the engines to come, as the chain
     * is.
     */
    external fun nativeProxies(families: IntArray, uids: IntArray, android: String, strictDns: Boolean)

    /** The messengers' client packages the engine's table holds (`data/messengers`), one `family package` a line. */
    external fun nativeMessengerClients(): String

    /**
     * The kept flows that went through a proxy, one per line as `protocol app destination uid kind how flags asked
     * proxy-name cover name` (core/network-jni's `proxy_line`); debug builds only. No credential: the engine keeps none.
     */
    external fun nativeFlowProxies(): String

    /**
     * The flows kept, one per line as `protocol app destination uid outcome named-by ech dns network dns-name name`,
     * `dns-name` being the DNS answer's name where it differs from the connection's own; debug builds only.
     */
    external fun nativeFlows(): String

    /**
     * The reply to the engine's exchange [ticket] (W8, part 1; [org.visadahyu.datapavan.network.dns.Exchanger]):
     * [outcome] 200 or 0 with [body], another HTTP status, or -1 (no answer in time), -2 (reset once the TLS hello
     * was out, or a certificate that does not check), -3 (refused, closed, or anything else). Whether a lookup
     * still waited for it. From any thread; it never waits for the engine.
     */
    external fun nativeExchanged(ticket: Long, outcome: Int, body: ByteArray?): Boolean

    /**
     * The encrypted resolver for direct apps' names (W8, part 1): the data pack's ODoH relays, targets and pairs and
     * the presets, and the user's [setting] ([org.visadahyu.datapavan.network.dns.DnsSettings.engineSetting]); kept
     * for the engines to come and set on the one that runs. How many relays, targets, pairs allowed and presets
     * were read.
     */
    external fun nativeDns(relays: String, targets: String, pairs: String, presets: String, setting: String): IntArray

    /** What Android says of the network beneath: validated or not (a captive portal), and its search domains. */
    external fun nativeDnsNetwork(validated: Boolean, domains: String)

    /**
     * The encrypted resolver's state, `key value` lines: `way` (`off`, `none`, the way that answered last, or
     * `fallback SECONDS`, `failing SECONDS`), `strict`, `validated`, `held`, `answers ...`. It names no lookup.
     */
    external fun nativeDnsStatus(): String

    /**
     * Forgets the durations of exchanges the encrypted resolver kept for [nativeDnsStatus]'s `latency` lines, so
     * that they read only the exchanges answered after it: debug builds' `dns-times-clear`, for the speed budget's
     * check (ADR 0039). Nothing when no engine runs.
     */
    external fun nativeDnsTimesClear()

    /**
     * The ways of the four tables for the network screen, as [org.visadahyu.datapavan.network.dns.DnsCatalogue] reads
     * them.
     */
    external fun nativeDnsCatalogue(relays: String, targets: String, pairs: String, presets: String): String

    /**
     * Reads tracker blocking's graded table (W8, part 3a; ADR 0053): [table] is `blocking/hosts.tsv` of the data pack
     * the audit verifies, with a debug build's row for the lab's names after it
     * ([org.visadahyu.datapavan.network.blocking.LabRow]), nine tab-separated columns a row. The library keeps it for
     * [nativeBlocking], in place of any before, and returns how many rows it holds and how many are graded `block`,
     * `keep` and `code`; empty for a table it refuses, which keeps none, so that nothing is blocked by half a table.
     * No engine needs to run. A new table empties the engine's tallies: they count by its rows.
     */
    external fun nativeBlockingTable(table: ByteArray): IntArray

    /**
     * Sets tracker blocking whole ([org.visadahyu.datapavan.network.blocking.Handover.text]), on the table
     * [nativeBlockingTable] last read: one `key value...` a line, `on 0|1`, `tool-dns 0|1`, `paused MS` (the global
     * pause's milliseconds left), `covered UID UID ...`, `graded UID HOST block|keep` (a row's grade decided for one
     * app: a `code` row from the app's code, or an exception's `keep`), `allowed UID MS|-` (an app allowed for MS more
     * milliseconds, or `-` until blocked again) and `entry UID HOST` (one row allowed in one app), HOST written as the
     * table writes it. The library turns the times into deadlines on the time since the phone started, so that a
     * clock set back stretches none, and keeps the setting for the engines to come; stopping the tunnel forgets it.
     */
    external fun nativeBlocking(setting: String)

    /**
     * What blocking counted in the running engine's memory, one line per app and row,
     * `uid<TAB>host<TAB>lookups<TAB>connections<TAB>sinceMs`: lookups answered with no address apart from connections
     * refused, and since when, in milliseconds since 1970 ([org.visadahyu.datapavan.network.blocking.Tallies]). Empty
     * when no engine runs; [nativeClearActivity] clears it. Never written anywhere (ADR 0047): "Now" alone reads it.
     */
    external fun nativeBlocked(): String
}

/** The network part's Rust reader of data packs (core/engine's `datapack`, through the network part's own library). */
internal object NetworkPacks : org.visadahyu.datapavan.datapack.PackNative {
    override fun readDataPack(pack: ByteArray, keys: String): IntArray = Engine.nativeReadDataPack(pack, keys)

    override fun readDataPayload(payload: ByteArray): IntArray = Engine.nativeReadDataPayload(payload)
}
