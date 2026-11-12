//! Thin JNI bridge between Datapavan Watch and [`datapavan_net`], as `datapavan-jni` is for the audit
//! app: `org.visadahyu.datapavan.watch.Engine` starts and stops the engine, and the engine calls back
//! into `WatchVpnService` for `getConnectionOwnerUid` and `protect`. Every export converts its
//! arguments, calls the engine and converts the result; all logic is in the engine, which holds no
//! unsafe code (ADR 0006).

use std::fs::File;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex, PoisonError};

use datapavan_net::organisations::{FilePart, Organisations};
use datapavan_net::socks5::Credentials;
use datapavan_net::{
    Addresses, Chain, Config, DnsUse, Ech, Engine, NamedBy, NetworkKind, Outcome, Platform,
};
use jni::errors::{Error, ThrowRuntimeExAndDefault};
use jni::objects::{JByteArray, JClass, JIntArray, JLongArray, JObject, JString};
use jni::sys::{jboolean, jint, jlong};
use jni::{EnvUnowned, JValue, JavaVM, jni_sig, jni_str};

/// The running engine, if any.
static ENGINE: Mutex<Option<Engine>> = Mutex::new(None);

fn engine() -> std::sync::MutexGuard<'static, Option<Engine>> {
    ENGINE.lock().unwrap_or_else(PoisonError::into_inner)
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
/// of the tunnel's descriptor `fd` and starts the engine, stopping one that runs. `keepFlows` is how
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
            if let Some(mut running) = engine().take() {
                running.stop();
            }
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
            let Ok(started) = Engine::start(fd, config, platform, organisations.flatten()) else {
                return Ok(false);
            };
            *engine() = Some(started);
            Ok(true)
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
            if let Some(mut running) = engine().take() {
                running.stop();
            }
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
            let on = chain.is_some();
            Ok(match engine().as_ref() {
                Some(running) => {
                    running.chain(chain);
                    on
                }
                None => false,
            })
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
            if let Some(engine) = engine().as_ref() {
                engine.uncache_answers(on);
            }
            Ok(())
        })
        .resolve::<ThrowRuntimeExAndDefault>();
}

/// `Engine.nativeCounters()`: the running engine's counters, in the order of
/// `datapavan_net::engine::Counters::snapshot`, or an empty array when none runs.
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

/// `Engine.nativeFlows()`: the flows the engine kept, one per line as
/// `protocol app destination uid outcome named-by ech dns network name` (`-` for none; `dns` is
/// `plain` or `encrypted`, with `:resolver` when it is a known one; `network` is `as<number>:own`,
/// `:hosting` or `:unlisted`; the name may hold spaces), for debug builds and the end-to-end test. Empty when the engine keeps none, as in release builds.
// SAFETY: exported under the JNI name of the Kotlin method `external fun nativeFlows(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_Engine_nativeFlows<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let flows = engine().as_ref().map_or_else(Vec::new, Engine::flows);
            let lines: Vec<String> = flows
                .iter()
                .map(|f| {
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
                    // The name last: an organisation's may hold spaces.
                    format!(
                        "{protocol} {} {} {uid} {outcome} {named_by} {ech} {dns} {network} {name}",
                        f.app, f.destination
                    )
                })
                .collect();
            JString::from_str(env, lines.join("\n"))
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}
