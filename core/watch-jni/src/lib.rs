//! Thin JNI bridge between Datapavan Watch and [`datapavan_net`], as `datapavan-jni` is for the audit
//! app: `org.visadahyu.datapavan.watch.Engine` starts and stops the engine, and the engine calls back
//! into `WatchVpnService` for `getConnectionOwnerUid` and `protect`, to hand over the log's records, and
//! to ask for a reading of the apps' states. Every export converts its
//! arguments, calls the engine and converts the result; all logic is in the engine, which holds no
//! unsafe code (ADR 0006).

use std::fs::File;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use datapavan_engine::datapack;
use datapavan_net::engine::{Configured, MAX_TUNNELS, TunnelState};
use datapavan_net::organisations::{FilePart, Organisations};
use datapavan_net::socks5::Credentials;
use datapavan_net::trackers::NetworkSignatures;
use datapavan_net::wireguard::Config as WgConfig;
use datapavan_net::{
    Addresses, Chain, ChainSetting, Config, DnsUse, Ech, Engine, Flow, Handover, Limits, NamedBy,
    NetworkKind, Outcome, Platform, TunnelSetting,
};
use jni::errors::{Error, ThrowRuntimeExAndDefault};
use jni::objects::{JByteArray, JClass, JIntArray, JLongArray, JObject, JString};
use jni::sys::{jboolean, jint, jlong};
use jni::{EnvUnowned, JValue, JavaVM, jni_sig, jni_str};
use zeroize::Zeroize;

/// The running engine, if any.
///
/// Never held while the engine's thread is joined (take the engine out, then stop it), and never held
/// across a call into Kotlin that could call back into this file: `ownerUid`, `protectSocket`,
/// `logRecords` and `statesWanted`, reached from the engine, must not call a native method of `Engine`
/// while they run (`statesWanted` only hands a reading to the tracker's own thread, which calls
/// `nativeStates` later, holding nothing of the engine's; it is also reached from `nativeStates` itself,
/// under this lock, when a reading left seconds waiting, and returns at once there too).
/// Two exceptions are kept on purpose, both waits for the engine's thread under the lock:
/// `nativeFlushLog` holds it while that thread flushes the log and hands the records to `logRecords`,
/// at most ten seconds (finding 4: the flush is made between the engine's counts), and
/// `nativeSwapTunnel` while it takes the new tunnel, so that the engine stays in place and a chain set
/// meanwhile reaches it after. That thread never takes this lock, and the Kotlin code it reaches, the
/// three callbacks above, from tokio's blocking threads or from the engine's own thread as its loop ends
/// (`logRecords`), never calls a native method of `Engine`.
static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

fn engine() -> MutexGuard<'static, Option<Engine>> {
    ENGINE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The chain Watch last set, with whether answers go uncached, kept whether or not an engine ran then
/// (ADR 0044, unit 12, fourth check, minor 1). While `nativeStart` swaps engines, none is in [`ENGINE`]:
/// a `nativeChain` that lands then, as from `refreshChain`'s thread, is kept here, and the next engine
/// starts with it, rather than with the older chain the engine before handed over. `nativeStop` clears
/// it, so that no run of the tunnel starts with the chain of one before. Lock order: this, then
/// [`ENGINE`]; neither is held while an engine's thread is joined.
static SET: Mutex<Option<ChainSetting>> = Mutex::new(None);

fn setting() -> MutexGuard<'static, Option<ChainSetting>> {
    SET.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keeps `chain` for the engines to come and sets it on the one that runs, if any: whether a chain is
/// on now, false while no engine runs.
fn set_chain(chain: Option<Chain>) -> bool {
    let mut set = setting();
    let on = chain.is_some();
    let tunnels = set.as_ref().map(|s| s.tunnels.clone()).unwrap_or_default();
    *set = Some(ChainSetting {
        chain: chain.clone(),
        uncached_answers: on,
        tunnels,
    });
    match engine().as_ref() {
        Some(running) => {
            running.chain(chain);
            on
        }
        None => false,
    }
}

/// Changes the `WireGuard` tunnels' setting (W7) for the engines to come, kept beside the chain, and sets it on
/// the one that runs, if any.
fn set_tunnels(change: impl FnOnce(&mut TunnelSetting)) {
    let mut set = setting();
    let kept = set.get_or_insert_with(|| ChainSetting {
        chain: None,
        uncached_answers: false,
        tunnels: TunnelSetting::default(),
    });
    change(&mut kept.tunnels);
    if let Some(running) = engine().as_ref() {
        running.tunnels(&kept.tunnels);
    }
}

/// A tunnel's state as `nativeTunnelStates` writes it: `id handshake received error not-answering plain-dns
/// connected flows configured resolutions`, the times in milliseconds ago and `-` for none; `configured` 0 for a
/// tunnel apps are routed to whose configuration is not set, whose apps wait. No key, no address, no endpoint.
fn state_line(state: &TunnelState) -> String {
    let ms = |d: Option<std::time::Duration>| {
        d.map_or_else(|| "-".to_owned(), |d| d.as_millis().to_string())
    };
    format!(
        "{} {} {} {} {} {} {} {} {} {}",
        state.id,
        ms(state.handshake),
        ms(state.received),
        state.error.unwrap_or("-"),
        u8::from(state.not_answering),
        u8::from(state.plain_dns),
        u8::from(state.connected),
        state.flows,
        u8::from(state.configured),
        state.resolutions,
    )
}

/// What `nativeTunnelParse` says of a configuration: `refused WHY`, or `ok` and then its description, a line
/// each ([`WgConfig::describe`]): what the configuration does, never a key, and last a line for each app it
/// names, `only PACKAGE` (`IncludedApplications`) or `except PACKAGE` (`ExcludedApplications`), for the import's
/// confirmation (W7, part 2).
fn parse_answer(text: &[u8]) -> String {
    match WgConfig::parse(text) {
        Err(refusal) => format!("refused {refusal}"),
        Ok(config) => format!("ok\n{}", config.describe()),
    }
}

/// Puts `configured` in place of the configuration of its number, or after the others: false, with nothing
/// changed, when it is a new one and the engine's bound is reached (W7, part 2), which the screens hold the
/// import to.
fn place_tunnel(tunnels: &mut TunnelSetting, configured: Configured) -> bool {
    let count = tunnels.tunnels.len();
    match tunnels.tunnels.iter_mut().find(|t| t.id == configured.id) {
        Some(place) => *place = configured,
        None if count >= MAX_TUNNELS => return false,
        None => tunnels.tunnels.push(configured),
    }
    true
}

/// Puts the tunnels `ids` first, in that order, the others after them as they were: the first is the default
/// tunnel (W7, part 2). Each keeps its core and its session, since its configuration is the same.
fn order_tunnels(tunnels: &mut TunnelSetting, ids: &[u32]) {
    let mut ordered: Vec<Configured> = Vec::with_capacity(tunnels.tunnels.len());
    for id in ids {
        if let Some(at) = tunnels.tunnels.iter().position(|t| t.id == *id) {
            ordered.push(tunnels.tunnels.remove(at));
        }
    }
    ordered.append(&mut tunnels.tunnels);
    tunnels.tunnels = ordered;
}

/// Reads `resolveEndpoint`'s answer: `encrypted` or `plain`, then addresses; addresses that do not read are
/// left out.
fn resolution(answer: &str) -> Option<datapavan_net::Resolution> {
    let mut words = answer.split_whitespace();
    let encrypted = match words.next()? {
        "encrypted" => true,
        "plain" => false,
        _ => return None,
    };
    Some(datapavan_net::Resolution {
        addresses: words.filter_map(|w| w.parse().ok()).collect(),
        encrypted,
    })
}

/// Keeps whether answers go uncached, where a chain was set to keep it with, and sets it on the engine
/// that runs. With no chain set yet, only the running engine has it, and hands it over.
fn set_uncached(on: bool) {
    let mut set = setting();
    if let Some(set) = set.as_mut() {
        set.uncached_answers = on;
    }
    if let Some(running) = engine().as_ref() {
        running.uncache_answers(on);
    }
}

/// Starts the next engine with `start`, given what the engine before handed over, if one ran, and the
/// chain Watch last set: [`SET`] is held from reading it until the new engine is in [`ENGINE`], so that
/// a chain set meanwhile waits, and then reaches the new engine. Whether it started.
fn start_next(
    handover: Option<Handover>,
    start: impl FnOnce((Option<Handover>, Option<ChainSetting>)) -> io::Result<Engine>,
) -> bool {
    let set = setting();
    let Ok(started) = start((handover, set.clone())) else {
        return false;
    };
    *engine() = Some(started);
    drop(set);
    true
}

/// Hands the engine that runs `fd`, the tunnel set up again with the same addresses on the same VPN
/// network, which it goes on with, keeping its flows (ADR 0044, unit 12b): whether it took it. With no engine running, or one
/// that could not take it, `fd` is closed and the answer is false.
fn swap_tunnel(fd: OwnedFd) -> bool {
    set_non_blocking(&fd);
    engine()
        .as_ref()
        .is_some_and(|running| running.swap_tunnel(fd).is_ok())
}

/// Stops the engine that runs, if any, and forgets the chain set: the tunnel is off.
fn stop_running() {
    // Taken out first: the lock is not held while the engine's thread is joined.
    let previous = engine().take();
    if let Some(mut running) = previous {
        running.stop();
    }
    *setting() = None;
}

/// Answers the engine's questions through `WatchVpnService`.
struct Service {
    vm: JavaVM,
    service: jni::refs::Global<JObject<'static>>,
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

impl Platform for Service {
    fn owner(&self, protocol: u8, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        self.vm
            .attach_current_thread(|env| -> Result<i32, Error> {
                let local_ip = env.byte_array_from_slice(&octets(local.ip()))?;
                let remote_ip = env.byte_array_from_slice(&octets(remote.ip()))?;
                env.call_method(
                    &self.service,
                    jni_str!("ownerUid"),
                    jni_sig!("(I[BI[BI)I"),
                    &[
                        JValue::Int(i32::from(protocol)),
                        JValue::Object(&local_ip),
                        JValue::Int(i32::from(local.port())),
                        JValue::Object(&remote_ip),
                        JValue::Int(i32::from(remote.port())),
                    ],
                )?
                .i()
            })
            .ok()
            .and_then(|uid| u32::try_from(uid).ok())
    }

    fn protect(&self, fd: RawFd) -> bool {
        self.vm
            .attach_current_thread(|env| -> Result<bool, Error> {
                env.call_method(
                    &self.service,
                    jni_str!("protectSocket"),
                    jni_sig!("(I)Z"),
                    &[JValue::Int(fd)],
                )?
                .z()
            })
            .unwrap_or(false)
    }

    fn log(&self, batch: &[u8]) {
        let _ = self.vm.attach_current_thread(|env| -> Result<(), Error> {
            let records = env.byte_array_from_slice(batch)?;
            env.call_method(
                &self.service,
                jni_str!("logRecords"),
                jni_sig!("([B)V"),
                &[JValue::Object(&records)],
            )?;
            Ok(())
        });
    }

    /// Watch's Kotlin side tells the apps' states (ADR 0046, decision 1).
    fn tells_states(&self) -> bool {
        true
    }

    /// `WatchVpnService.resolveEndpoint(name)`: a `WireGuard` endpoint's name asked of Android's own resolver
    /// on the network beneath the tunnel, which uses the user's Private DNS where it is on. Its answer is
    /// `encrypted` or `plain`, then the addresses, by spaces; null where Kotlin has no network to ask.
    fn resolve(&self, name: &str) -> Option<datapavan_net::Resolution> {
        let answer = self
            .vm
            .attach_current_thread(|env| -> Result<Option<String>, Error> {
                let name = JString::from_str(env, name)?;
                let answer = env
                    .call_method(
                        &self.service,
                        jni_str!("resolveEndpoint"),
                        jni_sig!("(Ljava/lang/String;)Ljava/lang/String;"),
                        &[JValue::Object(&name)],
                    )?
                    .l()?;
                if answer.as_raw().is_null() {
                    return Ok(None);
                }
                let answer = JString::cast_local(env, answer)?;
                Ok(Some(answer.try_to_string(env)?))
            })
            .ok()
            .flatten()?;
        resolution(&answer)
    }

    /// `WatchVpnService.statesWanted`, which hands a reading to its tracker's own thread when its rules
    /// allow one, and returns at once.
    fn wants_states(&self) {
        let _ = self.vm.attach_current_thread(|env| -> Result<(), Error> {
            env.call_method(
                &self.service,
                jni_str!("statesWanted"),
                jni_sig!("()V"),
                &[],
            )?;
            Ok(())
        });
    }
}

/// Makes sure the tunnel's descriptor does not block: the engine reads until "would block", so a
/// blocking descriptor would hang its only thread once the tunnel is idle.
fn set_non_blocking(fd: &OwnedFd) {
    let raw = fd.as_raw_fd();
    // SAFETY: `raw` is a valid descriptor owned by `fd` for the whole call; F_GETFL and F_SETFL only
    // read and set its status flags.
    unsafe {
        let flags = libc::fcntl(raw, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// `Engine.nativeStart(service, fd, mtu, keepFlows, tableFd, tableStart, tableLength)`: takes ownership
/// of the tunnel's descriptor `fd` and starts the engine, stopping one that runs. One that runs is a
/// tunnel set up again with other addresses, or one `nativeSwapTunnel` could not hand over (ADR 0044,
/// decision 5 as amended, and unit 12b): it hands the new engine its chain, the
/// network's resolver, its stand-ins, names and counters ([`Engine::hand_over`]) before the new
/// engine reads its first packet, so that no chained app's packet goes directly meanwhile. `keepFlows` is how
/// many of the latest flows to keep for debug builds; release builds pass 0. `tableFd`, if not -1, is a
/// descriptor of the IP-to-organisation table (ADR 0036), which the engine takes over too; the table
/// is its `tableLength` bytes from `tableStart`, an asset inside the APK.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeStart(service: Any,
// fd: Int, mtu: Int, keepFlows: Int, tableFd: Int, tableStart: Long, tableLength: Long): Boolean`,
// unique in this library.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeStart<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    service: JObject<'caller>,
    fd: jint,
    mtu: jint,
    keep_flows: jint,
    table_fd: jint,
    table_start: jlong,
    table_length: jlong,
    spare_addresses: jboolean,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, Error> {
            // Taken out first: the lock is not held while the engine's thread is joined.
            let previous = engine().take();
            let handover = previous.map(Engine::hand_over);
            if fd < 0 {
                return Ok(false);
            }
            // SAFETY: Kotlin passes the result of `ParcelFileDescriptor.detachFd()`, which hands the only
            // owning reference to the descriptor to native code; nothing else closes it.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            set_non_blocking(&fd);
            let platform: Arc<dyn Platform> = Arc::new(Service {
                vm: env.get_java_vm()?,
                service: env.new_global_ref(&service)?,
            });
            let config = Config {
                limits: Limits::for_this_process(),
                mtu: u16::try_from(mtu).unwrap_or(1500),
                keep_flows: usize::try_from(keep_flows).unwrap_or(0),
                // The common addresses, unless the network beneath uses them itself (ADR 0041).
                addresses: if spare_addresses {
                    Addresses::SPARE
                } else {
                    Addresses::COMMON
                },
            };
            let organisations = (table_fd >= 0).then(|| {
                // SAFETY: as for `fd`: Kotlin hands over a duplicate it detached, owned by nothing else.
                let file = File::from(unsafe { OwnedFd::from_raw_fd(table_fd) });
                let part = FilePart::new(
                    file,
                    u64::try_from(table_start).unwrap_or(0),
                    u64::try_from(table_length).unwrap_or(0),
                );
                Organisations::open(Box::new(part)).ok()
            });
            Ok(start_next(handover, |carried| {
                Engine::start_with(fd, config, platform, organisations.flatten(), carried)
            }))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeSwapTunnel(fd)`: takes ownership of the descriptor `fd` of the tunnel set up again with
/// the same addresses on the same VPN network, as `nativeStart` does, and hands it to the engine that
/// runs, which goes on with
/// it in place of the old tunnel and keeps its flows: its NAT, connections, mappings, ping sockets,
/// chain, names, stand-ins and counters (ADR 0044, unit 12b). The engine handles what is still queued
/// on the old tunnel, then closes it, before this returns. Returns whether the engine took it; false,
/// with `fd` closed, when no engine runs or it could not take it, and then `nativeStart` starts one on
/// another descriptor of the new tunnel.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeSwapTunnel(fd: Int):
// Boolean`, unique in this library.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeSwapTunnel<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    fd: jint,
) -> jboolean {
    unowned_env
        .with_env(|_env| -> Result<jboolean, Error> {
            if fd < 0 {
                return Ok(false);
            }
            // SAFETY: Kotlin passes the result of `ParcelFileDescriptor.detachFd()` on a duplicate it
            // made for the call, which hands the only owning reference to native code; nothing else
            // closes it.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(swap_tunnel(fd))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeStop()`: stops the engine and closes the tunnel's descriptor.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeStop()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeStop<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) {
    unowned_env
        .with_env(|_env| -> Result<(), Error> {
            stop_running();
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeNetworkChanged(dns, moved)`: the network beneath the tunnel or its DNS server
/// changed; `dns` is its DNS server's address, or empty when it has none, and `moved` says whether the
/// network itself is another one.
// SAFETY: exported under the JNI name of the Kotlin method
// `external fun nativeNetworkChanged(dns: String, moved: Boolean)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeNetworkChanged<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    dns: JString<'caller>,
    moved: jboolean,
) {
    unowned_env
        .with_env(|env| -> Result<(), Error> {
            let dns: Option<IpAddr> = dns.try_to_string(env).ok().and_then(|s| s.parse().ok());
            if let Some(running) = engine().as_ref() {
                running.network_changed(dns, moved);
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeRouteMtu(fd)`: the MTU the kernel keeps for the route of the connected socket `fd`
/// (`IP_MTU`), or -1 when it says nothing. Kotlin makes the socket, binds it to the network beneath,
/// connects it, and closes it after this returns; it reads the first hop's MTU so, since
/// `android.system.Os` offers no `getsockoptInt` to apps (ADR 0044, decision 5 as amended).
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeRouteMtu(fd: Int): Int`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeRouteMtu<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    fd: jint,
) -> jint {
    unowned_env
        .with_env(|_env| -> Result<jint, Error> {
            if fd < 0 {
                return Ok(-1);
            }
            // SAFETY: Kotlin holds `fd` open for the whole call and closes it only after this returns;
            // the borrow ends with the call, and nothing here closes or keeps it.
            let socket = unsafe { BorrowedFd::borrow_raw(fd) };
            Ok(datapavan_net::engine::route_mtu(&socket)
                .and_then(|mtu| jint::try_from(mtu).ok())
                .unwrap_or(-1))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeOrganisations()`: the release month of the organisation table the running engine
/// reads, such as `2026-11`, or empty when it has none or no engine runs.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeOrganisations(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeOrganisations<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let month = engine()
                .as_ref()
                .and_then(Engine::organisations)
                .unwrap_or_default();
            JString::from_str(env, month)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeFlushLog()`: hands the connection log every waiting record now (debug builds' test).
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeFlushLog()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeFlushLog<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) {
    unowned_env
        .with_env(|_env| -> Result<_, Error> {
            if let Some(engine) = engine().as_ref() {
                engine.flush_log();
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeChain(proxy, port, user, password, toolUid, apps, udp, logDestinations)`: turns chaining
/// on (W6). `proxy` and `port` are the address of the tool's SOCKS5 proxy, `user` and `password` its
/// credentials or null, `toolUid` the tool's UID, `apps` the UIDs of the chained apps or null for every
/// app but the tool, `udp` whether the tool carries UDP, `logDestinations` whether chained flows'
/// destinations go to the log. An empty `proxy` turns chaining off. Returns whether a chain is on.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeChain(proxy: String,
// port: Int, user: ByteArray?, password: ByteArray?, toolUid: Int, apps: IntArray?, udp: Boolean,
// logDestinations: Boolean): Boolean`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeChain<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    proxy: JString<'caller>,
    port: jint,
    user: JByteArray<'caller>,
    password: JByteArray<'caller>,
    tool_uid: jint,
    apps: JIntArray<'caller>,
    udp: jboolean,
    log_destinations: jboolean,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, Error> {
            let address: Option<IpAddr> =
                proxy.try_to_string(env).ok().and_then(|s| s.parse().ok());
            let chain = match (address, u16::try_from(port), u32::try_from(tool_uid)) {
                (Some(ip), Ok(port), Ok(tool)) => {
                    // A null array is no credentials; convert_byte_array refuses it.
                    let credentials = match (
                        env.convert_byte_array(&user).ok(),
                        env.convert_byte_array(&password).ok(),
                    ) {
                        (Some(user), Some(password)) => Credentials::new(&user, &password),
                        _ => None,
                    };
                    let apps = if apps.as_raw().is_null() {
                        None
                    } else {
                        let mut uids = vec![0; apps.len(env)?];
                        apps.get_region(env, 0, &mut uids)?;
                        Some(
                            uids.into_iter()
                                .filter_map(|u| u32::try_from(u).ok())
                                .collect(),
                        )
                    };
                    Some(Chain {
                        proxy: SocketAddr::new(ip, port),
                        credentials,
                        tool,
                        apps,
                        udp,
                        log_destinations,
                    })
                }
                _ => None,
            };
            Ok(set_chain(chain))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeTunnelSet(id, text, localNetwork)`: adds the `WireGuard` configuration `text`, in `wg-quick`'s
/// form, as the tunnel `id` (not 0), or puts it in place of the one of that number (W7, ADR 0035), with "Local
/// network directly" as `localNetwork` says. The text is handed over unwrapped (part 2 keeps it wrapped in the
/// Keystore) and zeroed here once parsed. Returns "" when it is set, else why it is refused, as
/// `datapavan_net::wireguard::Refusal`'s `Display` writes it: a code, a line, a key, never a value.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTunnelSet(id: Int, text:
// ByteArray, localNetwork: Boolean): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTunnelSet<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    id: jint,
    text: JByteArray<'caller>,
    local_network: jboolean,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let mut bytes = env.convert_byte_array(&text)?;
            let parsed = WgConfig::parse(&bytes);
            bytes.zeroize();
            let answer = match (u32::try_from(id).ok().filter(|&id| id != 0), parsed) {
                (None, _) => "bad-id".to_owned(),
                (Some(_), Err(refusal)) => refusal.to_string(),
                (Some(id), Ok(config)) => {
                    let configured = Configured {
                        id,
                        config: Arc::new(config),
                        local_network,
                    };
                    let mut answer = String::new();
                    set_tunnels(|tunnels| {
                        if !place_tunnel(tunnels, configured) {
                            "too-many".clone_into(&mut answer);
                        }
                    });
                    answer
                }
            };
            JString::from_str(env, answer)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeTunnelParse(text)`: reads the `WireGuard` configuration `text` without setting it, for the
/// import: `refused WHY`, or `ok` with the apps `WireGuard`'s app exported with it ([`parse_answer`]), which
/// the import offers as the choice of apps for the user to confirm (the maintainer's answer 2). The copy here
/// is zeroed once read.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTunnelParse(text: ByteArray):
// String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTunnelParse<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    text: JByteArray<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let mut bytes = env.convert_byte_array(&text)?;
            let answer = parse_answer(&bytes);
            bytes.zeroize();
            JString::from_str(env, answer)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeTunnelOrder(ids)`: puts the tunnels `ids` first, in that order, the first the default tunnel
/// (W7, part 2): flows of no app and ICMP echo go through it while any app goes through a tunnel. The others stay
/// after them as they were; each keeps its core and its session.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTunnelOrder(ids: IntArray)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTunnelOrder<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    ids: JIntArray<'caller>,
) {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let mut values = vec![0; ids.len(env)?];
            ids.get_region(env, 0, &mut values)?;
            let ids: Vec<u32> = values
                .into_iter()
                .filter_map(|id| u32::try_from(id).ok())
                .collect();
            set_tunnels(|tunnels| order_tunnels(tunnels, &ids));
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeTunnelRemove(id)`: removes the configuration of the tunnel `id` (W7). The apps routed to it
/// wait, their flows refused and never sent directly, until `nativeTunnelRoutes` sends them elsewhere.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTunnelRemove(id: Int)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTunnelRemove<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    id: jint,
) {
    unowned_env
        .with_env(|_env| -> Result<_, Error> {
            if let Ok(id) = u32::try_from(id) {
                // The routes to it stay: its apps wait, never going directly, until Watch routes them
                // elsewhere or sets its configuration again (fix round, both reviews' first finding).
                set_tunnels(|tunnels| tunnels.tunnels.retain(|t| t.id != id));
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeTunnelRoutes(uids, tunnels, logDestinations)`: the apps sent through a tunnel, each UID in
/// `uids` through the tunnel at the same place in `tunnels`, every other app its other way; and whether
/// their destinations are kept ("Log where these apps connect", as for chained apps). Replaces every route.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTunnelRoutes(uids: IntArray,
// tunnels: IntArray, logDestinations: Boolean)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTunnelRoutes<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    uids: JIntArray<'caller>,
    tunnels: JIntArray<'caller>,
    log_destinations: jboolean,
) {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let read = |array: &JIntArray<'_>, env: &mut jni::Env<'_>| -> Result<Vec<i32>, Error> {
                let mut values = vec![0; array.len(env)?];
                array.get_region(env, 0, &mut values)?;
                Ok(values)
            };
            let (uids, ids) = (read(&uids, env)?, read(&tunnels, env)?);
            let routes = uids
                .into_iter()
                .zip(ids)
                .filter_map(|(uid, id)| Some((u32::try_from(uid).ok()?, u32::try_from(id).ok()?)))
                .filter(|(_, id)| *id != 0)
                .collect();
            set_tunnels(|tunnels| {
                tunnels.routes = routes;
                tunnels.log_destinations = log_destinations;
            });
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeTunnelStates()`: each tunnel's state, one per line as [`state_line`] writes it, in the order
/// set; empty when no engine runs.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTunnelStates(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTunnelStates<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let states = engine()
                .as_ref()
                .map_or_else(Vec::new, Engine::tunnel_states);
            let lines: Vec<String> = states.iter().map(state_line).collect();
            JString::from_str(env, lines.join("\n"))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeUncacheAnswers(on)`: whether the answers of Watch's own DNS address reach the apps
/// with a time to live of 0, so that Android's resolver keeps none of them.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeUncacheAnswers(on: Boolean)`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeUncacheAnswers<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    on: jboolean,
) {
    unowned_env
        .with_env(|_env| -> Result<_, Error> {
            set_uncached(on);
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeCounters()`: the running engine's counters, all `datapavan_net::engine::COUNTERS` of
/// them in the order of `datapavan_net::engine::Counters::snapshot`, or an empty array when none runs.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeCounters(): LongArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeCounters<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JLongArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let values: Vec<i64> = engine().as_ref().map_or_else(Vec::new, |e| {
                e.counters()
                    .iter()
                    .map(|&v| i64::try_from(v).unwrap_or(i64::MAX))
                    .collect()
            });
            let array = JLongArray::new(env, values.len())?;
            array.set_region(env, 0, &values)?;
            Ok(array)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeStates(message)`: a reading of the apps' states (`datapavan_net::states`, ADR 0046,
/// decision 1) for the running engine, which places every second it covers. Whether an engine took it:
/// false when none runs or the message is not one of its version.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeStates(message:
// ByteArray): Boolean`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeStates<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    message: JByteArray<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, Error> {
            let message = env.convert_byte_array(&message)?;
            Ok(engine()
                .as_ref()
                .is_some_and(|running| running.states(&message)))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeActivity()`: what the live view "Now" draws (`datapavan_net::snapshot`), from the
/// running engine's memory, or an empty array when none runs.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeActivity(): ByteArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeActivity<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JByteArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let snapshot = engine().as_ref().map_or_else(Vec::new, Engine::activity);
            env.byte_array_from_slice(&snapshot)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// The network signatures of the trackers table Watch's Kotlin side last handed over, read from the data
/// pack the audit verifies (`Engine.nativeTrackers`), for "Now" and each app's history; none before.
static TRACKERS: Mutex<Option<Arc<NetworkSignatures>>> = Mutex::new(None);

/// `Engine.nativeReadDataPack(pack, keys)`: checks a data pack's signature against the trusted keys
/// (`signify` public key lines separated by `\n`), then reads its header, as the audit's bridge does
/// (`datapack::read_signed`), so that Watch reads the pack the audit verifies, not a copy of its own.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeReadDataPack(pack: ByteArray,
// keys: String): IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeReadDataPack<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    pack: JByteArray<'caller>,
    keys: JString<'caller>,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&pack)?;
            let keys = keys.try_to_string(env)?;
            int_array(env, &datapack::read_signed(&bytes, &keys))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeReadDataPayload(payload)`: reads the header of the APK's own data payload
/// (`datapack::read_payload`).
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeReadDataPayload(payload:
// ByteArray): IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeReadDataPayload<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    payload: JByteArray<'caller>,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&payload)?;
            int_array(env, &datapack::read_payload(&bytes))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeTrackers(table)`: reads the network signatures of `trackers.tsv` and keeps them for
/// `nativeTrackersOf`, in place of any before. Returns how many trackers have one, how many alternatives
/// were read and how many refused as outside the subset (`datapavan_net::trackers`); empty for a table
/// that is not one, which keeps none.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTrackers(table: ByteArray):
// IntArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTrackers<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    table: JByteArray<'caller>,
) -> JIntArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let bytes = env.convert_byte_array(&table)?;
            let read = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| NetworkSignatures::parse(text).ok());
            let counts = read.as_ref().map_or_else(Vec::new, |read| {
                let int = |n: usize| jint::try_from(n).unwrap_or(jint::MAX);
                vec![
                    int(read.trackers().len()),
                    int(read.alternatives()),
                    int(read.refused().len()),
                ]
            });
            *TRACKERS.lock().unwrap_or_else(PoisonError::into_inner) = read.map(Arc::new);
            int_array(env, &counts)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeTrackersOf(hosts)`: for each line `host\tport` (a name, or an address as text), each
/// alternative of a network signature that matches it, as `id␟name␟website␟alternative` (the fields
/// separated by U+001F), separated by tabs, one line each, empty for none or before any table was handed
/// over.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeTrackersOf(hosts: String):
// String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeTrackersOf<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    hosts: JString<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let hosts = hosts.try_to_string(env)?;
            let table = TRACKERS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let lines: Vec<String> = hosts
                .lines()
                .map(|line| {
                    let (host, port) = line.split_once('\t').unwrap_or((line, ""));
                    let port = port.parse().unwrap_or(0);
                    table.as_ref().map_or_else(String::new, |table| {
                        let found: Vec<String> = table
                            .matches(host, port)
                            .into_iter()
                            .filter_map(|(i, alternative)| {
                                let tracker = table.trackers().get(i)?;
                                Some(format!(
                                    "{}\u{1f}{}\u{1f}{}\u{1f}{alternative}",
                                    tracker.id, tracker.name, tracker.website
                                ))
                            })
                            .collect();
                        found.join("\t")
                    })
                })
                .collect();
            JString::from_str(env, lines.join("\n"))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

fn int_array<'local>(
    env: &mut jni::Env<'local>,
    values: &[jint],
) -> Result<JIntArray<'local>, Error> {
    let array = JIntArray::new(env, values.len())?;
    array.set_region(env, 0, values)?;
    Ok(array)
}

/// `Engine.nativeClearActivity()`: forgets everything the live view holds, in the running engine
/// (`datapavan_net::Engine::clear_activity`, for ADR 0047's profile); nothing when none runs.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeClearActivity()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeClearActivity<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) {
    unowned_env
        .with_env(|_env| -> Result<_, Error> {
            if let Some(running) = engine().as_ref() {
                running.clear_activity();
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// How many of `flows` went each way, by app: `uid route count` lines, the route `direct`, `tool` or
/// `tunnel:N`, the UID `-` for flows of no app, in order. No destination.
fn flow_routes(flows: &[Flow]) -> String {
    let mut counts = std::collections::BTreeMap::<(Option<u32>, String), usize>::new();
    for flow in flows {
        let route = match flow.via {
            datapavan_net::Via::Direct => "direct".to_owned(),
            datapavan_net::Via::Tool => "tool".to_owned(),
            datapavan_net::Via::Tunnel(t) => format!("tunnel:{t}"),
        };
        *counts.entry((flow.uid, route)).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((uid, route), n)| {
            let uid = uid.map_or_else(|| "-".to_owned(), |u| u.to_string());
            format!("{uid} {route} {n}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `Engine.nativeFlowRoutes()`: how many of the flows kept went each way, by app ([`flow_routes`]), for
/// W7's emulator check (scripts/verify-wireguard.sh). Empty when the engine keeps none, as in release builds.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeFlowRoutes(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeFlowRoutes<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let flows = engine().as_ref().map_or_else(Vec::new, Engine::flows);
            JString::from_str(env, flow_routes(&flows))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `Engine.nativeFlows()`: the flows the engine kept, one per line as [`flow_line`] writes it, for debug
/// builds and the end-to-end test. Empty when the engine keeps none, as in release builds.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeFlows(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeFlows<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let flows = engine().as_ref().map_or_else(Vec::new, Engine::flows);
            let lines: Vec<String> = flows.iter().map(flow_line).collect();
            JString::from_str(env, lines.join("\n"))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// A flow kept, as `protocol app destination uid outcome named-by ech dns network dns-name name` (`-` for
/// none; `dns` is `plain` or `encrypted`, with `:resolver` when it is a known one; `network` is
/// `as<number>:own`, `:hosting` or `:unlisted`; `dns-name` is the name a DNS answer gave the address,
/// where the connection's own, which names the flow, differs from it (finding 20 of the independent
/// review of 2026-11-09); the name may hold spaces, and comes last).
fn flow_line(f: &Flow) -> String {
    let protocol = if f.protocol == datapavan_net::packet::TCP {
        "tcp"
    } else {
        "udp"
    };
    let uid = f.uid.map_or_else(|| "-".to_owned(), |u| u.to_string());
    let outcome = match f.outcome {
        Outcome::Opened => "opened",
        Outcome::Refused => "refused",
        Outcome::Unreachable => "unreachable",
        Outcome::Failed => "failed",
    };
    let name = f.name.as_deref().unwrap_or("-");
    // A DNS name holds no space.
    let dns_name = f.dns_name.as_deref().unwrap_or("-");
    let named_by = match f.named_by {
        NamedBy::Dns => "dns",
        NamedBy::Tls => "tls",
        NamedBy::Quic => "quic",
        NamedBy::Organisation => "org",
        NamedBy::Unknown => "-",
    };
    let ech = match f.ech {
        Ech::Absent => "-",
        Ech::Offered => "ech",
        Ech::Hidden => "hidden",
    };
    let dns = match (f.dns, f.resolver.as_deref()) {
        (DnsUse::None, _) => "-".to_owned(),
        (DnsUse::Plain, None) => "plain".to_owned(),
        (DnsUse::Plain, Some(r)) => format!("plain:{r}"),
        (DnsUse::Encrypted, None) => "encrypted".to_owned(),
        (DnsUse::Encrypted, Some(r)) => format!("encrypted:{r}"),
    };
    let network = f.network.map_or_else(
        || "-".to_owned(),
        |n| {
            let kind = match n.kind {
                NetworkKind::Own => "own",
                NetworkKind::Hosting => "hosting",
                NetworkKind::Unlisted => "unlisted",
            };
            format!("as{}:{kind}", n.asn)
        },
    );
    format!(
        "{protocol} {} {} {uid} {outcome} {named_by} {ech} {dns} {network} {dns_name} {name}",
        f.app, f.destination
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::io::Read;
    use std::os::unix::net::{UnixDatagram, UnixStream};

    /// The process's engine and chain ([`ENGINE`], [`SET`]): each test that uses them holds this, so
    /// that tests running side by side do not change them under each other.
    static PROCESS: Mutex<()> = Mutex::new(());

    fn process() -> MutexGuard<'static, ()> {
        PROCESS.lock().unwrap_or_else(PoisonError::into_inner)
    }

    struct NoPlatform;

    impl Platform for NoPlatform {
        fn owner(&self, _: u8, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }

        fn protect(&self, _: RawFd) -> bool {
            true
        }

        fn log(&self, _: &[u8]) {}
    }

    /// The dump's flows show the DNS answer's name beside the connection's own where the two differ, and
    /// `-` where they do not, so that a run can read both; the name, which may hold spaces, stays last.
    #[test]
    fn a_flow_line_shows_both_names_where_they_differ() {
        let flow = Flow {
            id: 1,
            protocol: datapavan_net::packet::TCP,
            app: SocketAddr::from(([10, 1, 10, 1], 40_000)),
            destination: SocketAddr::from(([93, 184, 216, 34], 443)),
            uid: Some(2_000),
            outcome: Outcome::Opened,
            name: Some("other.example".into()),
            named_by: NamedBy::Tls,
            dns_name: Some("www.example.com".into()),
            came_in: false,
            ech: Ech::Offered,
            dns: DnsUse::None,
            resolver: None,
            network: None,
            via: datapavan_net::Via::Direct,
        };
        assert_eq!(
            flow_line(&flow),
            "tcp 10.1.10.1:40000 93.184.216.34:443 2000 opened tls ech - - www.example.com other.example"
        );
        let organisation = Flow {
            name: Some("Google LLC".into()),
            named_by: NamedBy::Organisation,
            dns_name: None,
            ech: Ech::Absent,
            network: Some(datapavan_net::Network {
                asn: 15_169,
                kind: NetworkKind::Hosting,
            }),
            ..flow
        };
        assert_eq!(
            flow_line(&organisation),
            "tcp 10.1.10.1:40000 93.184.216.34:443 2000 opened org - - as15169:hosting - Google LLC"
        );
        // W7's check counts the ways flows went, by app, with no destination.
        let tunnelled = Flow {
            via: datapavan_net::Via::Tunnel(3),
            ..organisation.clone()
        };
        let unowned = Flow {
            uid: None,
            via: datapavan_net::Via::Tool,
            ..organisation.clone()
        };
        let routes = flow_routes(&[organisation, tunnelled.clone(), tunnelled, unowned]);
        assert_eq!(routes, "- tool 1\n2000 direct 1\n2000 tunnel:3 2");
        assert!(!routes.contains("93.184"));
    }

    fn a_chain(port: u16) -> Chain {
        Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], port)),
            credentials: None,
            tool: 10_200,
            apps: Some(HashSet::from([10_300])),
            udp: true,
            log_destinations: false,
        }
    }

    /// An engine on one end of a datagram pair, with what it is given: the chain set, which the test
    /// notes in `seen`.
    fn started(
        seen: &mut Vec<Option<ChainSetting>>,
        (handover, setting): (Option<Handover>, Option<ChainSetting>),
    ) -> io::Result<Engine> {
        seen.push(setting.clone());
        let (end, _) = UnixDatagram::pair()?;
        end.set_nonblocking(true)?;
        let config = Config {
            limits: Limits::default(),
            mtu: 1500,
            keep_flows: 0,
            addresses: Addresses::COMMON,
        };
        Engine::start_with(
            OwnedFd::from(end),
            config,
            Arc::new(NoPlatform),
            None,
            (handover, setting),
        )
    }

    /// The port of the proxy of the chain the last engine started with.
    fn port_of(seen: &[Option<ChainSetting>]) -> Option<u16> {
        seen.last()?
            .as_ref()?
            .chain
            .as_ref()
            .map(|chain| chain.proxy.port())
    }

    /// Fourth check of unit 12, minor 1: a chain set while no engine runs, as between `hand_over` and
    /// `start_with` in `nativeStart`, is kept, and the next engine starts with it; one set on a running
    /// engine is the next one's too; and the tunnel's stop forgets it, so that the next run starts with
    /// none, unless a chain is set before its first engine, as Watch now sets it at a start (unit 12b).
    #[test]
    fn a_chain_set_while_no_engine_runs_is_the_next_engines() {
        let _process = process();
        stop_running();
        let mut seen = Vec::new();
        assert!(start_next(None, |given| started(&mut seen, given)));
        assert_eq!(port_of(&seen), None, "a first start with nothing set");
        assert!(
            set_chain(Some(a_chain(10_808))),
            "set on the running engine"
        );

        // As nativeStart does: the engine taken out and handed over, and a chain lands meanwhile.
        let handover = engine().take().map(Engine::hand_over);
        assert!(!set_chain(Some(a_chain(10_809))), "no engine runs");
        assert!(start_next(handover, |given| started(&mut seen, given)));
        assert_eq!(port_of(&seen), Some(10_809));
        let uncached = seen
            .last()
            .and_then(Option::as_ref)
            .is_some_and(|set| set.uncached_answers);
        assert!(uncached, "answers uncached with the chain");

        // A swap with nothing set meanwhile: the chain last set, on the engine that ran.
        let handover = engine().take().map(Engine::hand_over);
        assert!(start_next(handover, |given| started(&mut seen, given)));
        assert_eq!(port_of(&seen), Some(10_809));

        stop_running();
        assert!(start_next(None, |given| started(&mut seen, given)));
        assert_eq!(port_of(&seen), None, "a chain of the run before");

        // Unit 12b: a first start with the chain set before it, as `WatchVpnService.start` sets it now.
        stop_running();
        assert!(!set_chain(Some(a_chain(10_807))), "no engine runs yet");
        assert!(start_next(None, |given| started(&mut seen, given)));
        assert_eq!(
            port_of(&seen),
            Some(10_807),
            "the chain set before the first start"
        );
        stop_running();
    }

    /// W7: tunnels set while no engine runs are the next engine's from its first packet, kept beside a chain set
    /// after them; routes and removal reach the engine that runs, and its states name no key.
    #[test]
    fn tunnels_set_while_no_engine_runs_are_the_next_engines() {
        let _process = process();
        stop_running();
        let text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.77.0.2/32\n\
                    DNS = 10.77.0.1\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                    AllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";
        let Ok(config) = WgConfig::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        let config = Arc::new(config);
        set_tunnels(|tunnels| {
            tunnels.tunnels.push(Configured {
                id: 4,
                config: Arc::clone(&config),
                local_network: false,
            });
            tunnels.routes.insert(10_300, 4);
        });
        set_chain(Some(a_chain(10_808)));
        let mut seen = Vec::new();
        assert!(start_next(None, |given| started(&mut seen, given)));
        let kept = seen.last().and_then(Option::as_ref).map(|s| {
            (
                s.tunnels.tunnels.len(),
                s.tunnels.routes.get(&10_300).copied(),
                s.chain.is_some(),
            )
        });
        assert_eq!(
            kept,
            Some((1, Some(4), true)),
            "the tunnel and the chain, both"
        );
        let states = engine()
            .as_ref()
            .map(Engine::tunnel_states)
            .unwrap_or_default();
        assert_eq!(states.iter().map(|s| s.id).collect::<Vec<_>>(), [4]);
        let line = state_line(&states[0]);
        assert_eq!(line, "4 - - - 0 0 0 0 1 0");
        assert!(!line.contains("192.0.2.1") && !line.contains("yAnz"));
        // `nativeTunnelRemove`: the configuration goes, the route stays, and the tunnel is shown as one
        // whose apps wait for it.
        set_tunnels(|tunnels| tunnels.tunnels.retain(|t| t.id != 4));
        let states = engine()
            .as_ref()
            .map(Engine::tunnel_states)
            .unwrap_or_default();
        assert_eq!(
            states.iter().map(state_line).collect::<Vec<_>>(),
            ["4 - - - 0 0 0 0 0 0"],
            "routed, not configured"
        );
        set_tunnels(|tunnels| tunnels.routes.retain(|_, t| *t != 4));
        let states = engine()
            .as_ref()
            .map(Engine::tunnel_states)
            .unwrap_or_default();
        assert!(states.is_empty(), "removed from the engine that runs");
        stop_running();
        assert!(setting().is_none(), "nothing of the run kept for the next");
    }

    /// W7, part 2: a new order puts the default first and keeps the rest as they were; a configuration past the
    /// engine's bound is refused with `too-many`, while one in place of a set one is not.
    #[test]
    fn tunnels_are_ordered_and_held_to_the_engines_bound() {
        let _process = process();
        stop_running();
        let text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.77.0.2/32\n\
                    DNS = 10.77.0.1\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                    AllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";
        let Ok(config) = WgConfig::parse(text.as_bytes()) else {
            unreachable!("refused")
        };
        let config = Arc::new(config);
        let ids =
            |tunnels: &TunnelSetting| tunnels.tunnels.iter().map(|t| t.id).collect::<Vec<_>>();
        let mut tunnels = TunnelSetting::default();
        for id in [3, 1, 2, 5] {
            tunnels.tunnels.push(Configured {
                id,
                config: Arc::clone(&config),
                local_network: false,
            });
        }
        order_tunnels(&mut tunnels, &[2]);
        assert_eq!(
            ids(&tunnels),
            [2, 3, 1, 5],
            "the default first, the others kept in order"
        );
        order_tunnels(&mut tunnels, &[5, 9, 1]);
        assert_eq!(ids(&tunnels), [5, 1, 2, 3], "an id not set is passed over");
        order_tunnels(&mut tunnels, &[]);
        assert_eq!(ids(&tunnels), [5, 1, 2, 3]);
        let one = |id| Configured {
            id,
            config: Arc::clone(&config),
            local_network: true,
        };
        for id in 6..=u32::try_from(MAX_TUNNELS + 1).unwrap_or(9) {
            let room = tunnels.tunnels.len() < MAX_TUNNELS;
            assert_eq!(place_tunnel(&mut tunnels, one(id)), room, "tunnel {id}");
        }
        assert_eq!(tunnels.tunnels.len(), MAX_TUNNELS);
        assert!(
            place_tunnel(&mut tunnels, one(1)),
            "in place of one set, past the bound"
        );
        assert!(tunnels.tunnels.iter().any(|t| t.id == 1 && t.local_network));
        stop_running();
    }

    /// W7 fix round: the import's reading names the apps a configuration came with, and its refusals; the
    /// resolver's answer reads both ways, and nothing else.
    #[test]
    fn a_configurations_apps_and_the_resolvers_answer_read() {
        let text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.77.0.2/32\n\
                    DNS = 10.77.0.1\nListenPort = 51820\nFwMark = 0x1234\nIncludedApplications = org.example.one, org.example.two\n\
                    [Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\n\
                    Endpoint = 192.0.2.1:51820\n";
        let described = "endpoint 192.0.2.1 51820\naddress 10.77.0.2/32\ndns 10.77.0.1\nallowed 0.0.0.0/0\n\
                         everything 1\npreshared 0\nmtu 1280";
        assert_eq!(
            parse_answer(text.as_bytes()),
            format!("ok\n{described}\nonly org.example.one\nonly org.example.two")
        );
        let except = text.replace("IncludedApplications", "ExcludedApplications");
        assert_eq!(
            parse_answer(except.as_bytes()),
            format!("ok\n{described}\nexcept org.example.one\nexcept org.example.two")
        );
        let plain = text.replace(
            "IncludedApplications = org.example.one, org.example.two\n",
            "",
        );
        assert_eq!(parse_answer(plain.as_bytes()), format!("ok\n{described}"));
        assert!(
            !parse_answer(text.as_bytes()).contains("yAnz"),
            "no key in the description"
        );
        let both = text.replace(
            "ListenPort = 51820\n",
            "ExcludedApplications = org.example.three\n",
        );
        let answer = parse_answer(both.as_bytes());
        assert!(answer.starts_with("refused "), "{answer}");
        assert!(!answer.contains("yAnz"), "no key in a refusal");

        let read = resolution("encrypted 192.0.2.7 2001:db8::7 nonsense");
        assert_eq!(
            read.map(|r| (r.encrypted, r.addresses.len())),
            Some((true, 2))
        );
        assert_eq!(resolution("plain").map(|r| r.encrypted), Some(false));
        assert!(resolution("maybe 192.0.2.7").is_none());
        assert!(resolution("").is_none());
    }

    /// Unit 12b: a tunnel swapped in while no engine runs is refused, and its descriptor closed, so that
    /// nothing holds the new tunnel open behind Kotlin, which starts an engine on its own descriptor of
    /// it instead. With an engine running, one it cannot take, here `/dev/null`, which epoll refuses, is
    /// refused too, once the engine has said so, and the old tunnel stays; a tunnel it can take, it
    /// takes, keeps open, and closes the old one.
    #[test]
    fn a_tunnel_is_swapped_in_only_where_an_engine_takes_it() -> io::Result<()> {
        let _process = process();
        stop_running();
        let (given, peer) = UnixStream::pair()?;
        peer.set_nonblocking(true)?;
        assert!(!swap_tunnel(OwnedFd::from(given)), "no engine runs");
        let read = (&peer).read(&mut [0u8; 1]).map_err(|e| e.kind());
        assert_eq!(read, Ok(0), "the descriptor given is still open");

        let (old, old_peer) = UnixDatagram::pair()?;
        old.set_nonblocking(true)?;
        let config = Config {
            limits: Limits::default(),
            mtu: 1500,
            keep_flows: 0,
            addresses: Addresses::COMMON,
        };
        assert!(start_next(None, |carried| Engine::start_with(
            OwnedFd::from(old),
            config,
            Arc::new(NoPlatform),
            None,
            carried,
        )));
        let null = OwnedFd::from(std::fs::File::open("/dev/null")?);
        assert!(!swap_tunnel(null), "the engine took /dev/null");
        assert_eq!(old_peer.send(b"still")?, 5, "the old tunnel is closed");
        let (new, new_peer) = UnixDatagram::pair()?;
        assert!(swap_tunnel(OwnedFd::from(new)), "the engine took it");
        let sent = old_peer.send(b"after").map_err(|e| e.kind());
        assert_eq!(
            sent,
            Err(io::ErrorKind::ConnectionRefused),
            "the old tunnel is still open"
        );
        assert_eq!(new_peer.send(b"after")?, 5, "the new tunnel is closed");
        stop_running();
        Ok(())
    }
}
