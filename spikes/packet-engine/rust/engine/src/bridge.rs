//! The JNI surface, `org.visadahyu.datapavan.watch.spike.RustEngine`: start, stop, stats, and one
//! upcall per new flow to `SpikeVpnService.ownerUid`. The only module with `unsafe`.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use jni::errors::{Error, ThrowRuntimeExAndDefault};
use jni::objects::{JClass, JLongArray, JObject, JString};
use jni::sys::{jboolean, jint};
use jni::{EnvUnowned, JValue, JavaVM, jni_sig, jni_str};
use tokio::sync::watch;

use crate::stats::Stats;
use crate::tun::Tun;
use crate::{Kind, OwnerLookup, system, userspace};

struct Running {
    stop: watch::Sender<bool>,
    thread: JoinHandle<()>,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);
static STATS: Mutex<Option<Arc<Stats>>> = Mutex::new(None);

/// Calls back into the service for `getConnectionOwnerUid`.
struct JavaOwners {
    vm: JavaVM,
    service: jni::refs::Global<JObject<'static>>,
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

impl OwnerLookup for JavaOwners {
    fn owner(&self, protocol: i32, local: SocketAddr, remote: SocketAddr) -> i32 {
        self.vm
            .attach_current_thread(|env| -> Result<i32, Error> {
                let src = env.byte_array_from_slice(&octets(local.ip()))?;
                let dst = env.byte_array_from_slice(&octets(remote.ip()))?;
                env.call_method(
                    &self.service,
                    jni_str!("ownerUid"),
                    jni_sig!("(I[BI[BI)I"),
                    &[
                        JValue::Int(protocol),
                        JValue::Object(&src),
                        JValue::Int(i32::from(local.port())),
                        JValue::Object(&dst),
                        JValue::Int(i32::from(remote.port())),
                    ],
                )?
                .i()
            })
            .unwrap_or(-1)
    }

    fn protect(&self, fd: i32) -> bool {
        self.vm
            .attach_current_thread(|env| -> Result<bool, Error> {
                env.call_method(&self.service, jni_str!("protectSocket"), jni_sig!("(I)Z"), &[JValue::Int(fd)])?.z()
            })
            .unwrap_or(false)
    }
}

/// Makes sure the descriptor does not block: tokio's readiness loop reads until "would block", so a
/// blocking descriptor would hang the engine's only thread once the tunnel is idle.
fn set_non_blocking(fd: &OwnedFd) {
    use std::os::fd::AsRawFd;
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

fn stop_running() {
    let running = RUNNING.lock().unwrap_or_else(PoisonError::into_inner).take();
    if let Some(running) = running {
        let _ = running.stop.send(true);
        let _ = running.thread.join();
    }
}

/// `RustEngine.nativeStart(service, fd, mtu, kind)`: takes ownership of `fd` and runs the engine on a
/// thread of its own, with one tokio thread as VPN.md asks; owner lookups run on tokio's blocking pool.
// SAFETY: exported under the JNI name of the static Kotlin method
// `external fun nativeStart(service: Any, fd: Int, mtu: Int, kind: Int, socks: String): Boolean`, unique in this library.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_spike_RustEngine_nativeStart<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    service: JObject<'caller>,
    fd: jint,
    mtu: jint,
    kind: jint,
    socks: JString<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> Result<jboolean, Error> {
            stop_running();
            let Some(kind) = Kind::from_code(kind) else { return Ok(false) };
            // "host:port" of a SOCKS5 proxy for the system engine's upstream connections, or empty.
            let proxy: Option<SocketAddr> = socks.try_to_string(env).ok().and_then(|s| s.parse().ok());
            if fd < 0 {
                return Ok(false);
            }
            // SAFETY: Kotlin passes the result of `ParcelFileDescriptor.detachFd()`, which hands the
            // only owning reference to the descriptor over to native code; nothing else closes it.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            set_non_blocking(&fd);
            let owners: Arc<dyn OwnerLookup> = Arc::new(JavaOwners { vm: env.get_java_vm()?, service: env.new_global_ref(&service)? });
            let stats = Arc::new(Stats::default());
            *STATS.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&stats));
            let mtu = u16::try_from(mtu).unwrap_or(1500);
            let (stop, stopped) = watch::channel(false);
            let thread = std::thread::Builder::new()
                .name("spike-engine".into())
                .spawn(move || {
                    // ipstack's TCP stream waits in its Drop with `block_in_place`, which needs the
                    // multi-threaded runtime and hangs a current-thread one when it shuts down. The
                    // system engine keeps the one thread VPN.md asks for.
                    let runtime = match kind {
                        Kind::Userspace => tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build(),
                        Kind::System => tokio::runtime::Builder::new_current_thread().enable_all().build(),
                    };
                    let Ok(runtime) = runtime else { return };
                    runtime.block_on(async move {
                        let Ok(tun) = Tun::new(fd, Arc::clone(&stats)) else { return };
                        match kind {
                            Kind::Userspace => userspace::run(tun, mtu, stats, owners, stopped).await,
                            Kind::System => system::run(tun, mtu, stats, owners, proxy, stopped).await,
                        }
                    });
                    runtime.shutdown_background();
                })
                .map_err(|e| Error::ParseFailed(e.to_string()))?;
            *RUNNING.lock().unwrap_or_else(PoisonError::into_inner) = Some(Running { stop, thread });
            Ok(true)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `RustEngine.nativeStop()`: stops the engine and closes the tunnel's descriptor.
// SAFETY: exported under the JNI name of the static Kotlin method `external fun nativeStop()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_spike_RustEngine_nativeStop<'caller>(
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

/// `RustEngine.nativeStats()`: the counters of the last engine started, as `Stats::snapshot` orders them.
// SAFETY: exported under the JNI name of the static Kotlin method `external fun nativeStats(): LongArray`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_spike_RustEngine_nativeStats<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JLongArray<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let values = STATS.lock().unwrap_or_else(PoisonError::into_inner).as_ref().map_or([0; 10], |s| s.snapshot());
            let array = JLongArray::new(env, values.len())?;
            array.set_region(env, 0, &values)?;
            Ok(array)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

/// `RustEngine.nativeLastError()`: the last error an engine met, or "".
// SAFETY: exported under the JNI name of the static Kotlin method `external fun nativeLastError(): String`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_visadahyu_datapavan_watch_spike_RustEngine_nativeLastError<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> JString<'caller> {
    unowned_env
        .with_env(|env| -> Result<_, Error> {
            let last = crate::stats::LAST_ERROR.lock().map(|e| e.clone()).unwrap_or_default();
            JString::from_str(env, &last)
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}
