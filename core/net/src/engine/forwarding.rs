//! The forwarder's stage: plain HTTP in absolute form (RFC 9112, 3.2.2) to the network's own proxy, for a direct app's
//! flow whose `CONNECT` that proxy refused (the proxy record's forwarder; F-PLAN, its audit, and the maintainer's
//! decision of 2026-11-27, «بله، اول CONNECT»).
//!
//! **`CONNECT` first, as S2 does, for every flow.** Only where the proxy refuses a `CONNECT` (a `4xx` other than `407`,
//! by address and then by the flow's own name, S2's steps) is the flow rescued: its SYN is answered once a connection
//! of the stage's own reached the proxy ([`beneath::reach`], so that a proxy gone hands the flow back to S2's tail at
//! the SYN, as M6 of S2's audit built it), and its first head is awaited with no cut but the flow's own
//! `Limits::connect_timeout` (the audit's M2: `HttpURLConnection`, Chromium and `WebView` write late). The refusal is
//! remembered per proxy and port ([`Beneath::refuses`]), so that the next flows there come here at once, with no
//! refused round trip; such a flow's first bytes that are no forwardable head go by S2's `CONNECT` after all, so that a
//! refusal learned from another flow's name never costs this one its tunnel. Only a flow S2 may name to the proxy is
//! rescued ([`beneath::may_name`]): an app Android named, no circumvention tool, its route direct.
//!
//! **A stage behind the relay** (the audit's M4, option a). The relay takes as its upstream one end of a loopback TCP
//! pair; this task holds the other end and the connection to the proxy. The relay's poll, `accept`'s task and the
//! packet loop are S2's: the sniff, the tracker gate and the byte counts see the app's own bytes, as on every flow,
//! and every byte the gate lets go passes here before the proxy. Loopback TCP, so that a reset either way passes on as
//! a reset. Two descriptors and a copy per byte more, for plain HTTP through a proxy only.
//!
//! **The first head** is read whole ([`forward::head_end`]), checked ([`forward::first`]) and its name bound: an answer
//! of Datapavan's own resolvers gave it the flow's address (the audit's M3), the proxy's exclusion list does not name
//! it, and tracker blocking does not refuse it for the app (the gate's own verdict, read again here for a head whose
//! gate let it go unread once its hold ran out). Then the flow is named by that `Host` (M3), the head goes to the
//! proxy rewritten, and every later request is framed and rewritten ([`forward::Forward`]); the proxy's answers are
//! passed through unread, its close included (tinyproxy answers one request per connection, measured).
//!
//! **What is not forwarded:** on a rescued flow, a reset, its outcome the direct way's where that failed, else
//! `Refused` (no other way could carry it); on a flow sent here by a refusal remembered, S2's `CONNECT`, and a reset only
//! if that is refused too; a later head the framer refuses, a reset after the requests before it. An excluded `Host`
//! goes directly where the direct way had not failed and the user did not choose the proxy, as Android goes for an
//! excluded host (the audit's m16), else it is reset. A blocked `Host` is reset and recorded blocked.
//!
//! **Memory** (the audit's m8): a flow waits for its head as an open connection, not a waiting one: two sockets, a task,
//! and up to [`forward::MAX_HEAD`] held, allocated as the head comes, beside the relay's two 16 KiB. Every buffer that
//! holds the app's bytes is `Zeroizing` and grows only by replacement (m3).

use super::beneath::{self, Beneath};
use super::blocks::Path;
use super::upstream::connect_tcp;
use super::{Counters, Outcome, Shared, Via, is_unreachable, lock};
use crate::connect;
use crate::forward::{self, Forward, Why};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use zeroize::Zeroizing;

/// How long after its SYN was answered a flow's first byte counts as late: never a cut, only counted (the audit's M2).
pub(super) const LATE: Duration = Duration::from_millis(250);

/// What the stage needs of a flow whose `CONNECT` the proxy refused.
pub(super) struct Rescue {
    pub(super) beneath: Arc<Beneath>,
    /// Where the direct way goes.
    pub(super) target: SocketAddr,
    /// The app's end and the destination it connected to.
    pub(super) ends: (SocketAddr, SocketAddr),
    pub(super) uid: u32,
    /// When the flow's first try began: its first head is awaited until `Limits::connect_timeout` from here.
    pub(super) began: Instant,
    /// The direct try's error, where it came first and did not run out of its share.
    pub(super) failed: Option<io::ErrorKind>,
    /// Whether it came by a refusal remembered: what is no forwardable head may still go by `CONNECT`.
    pub(super) remembered: bool,
}

/// The rescued flow's upstream for the relay, its proxy reached first; the stage spawned behind it. An error where the
/// proxy cannot be reached now: S2's tail goes on. Boxed and out of line, as the proxy's other ways.
#[cold]
#[inline(never)]
pub(super) fn rescue(
    shared: &Arc<Shared>,
    rescue: Rescue,
) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + '_>> {
    Box::pin(async move {
        let proxy = beneath::reach(shared, &rescue.beneath, rescue.began)
            .await
            .map_err(beneath::Failure::error)?;
        let (relayed, staged) = pair().await?;
        // One of the engine's boxed tasks (ADR 0053), though it carries bytes: only a rescued flow's, already copied
        // once more over loopback, where one indirect call per poll is nothing beside it (the forwarder's size pass).
        super::spawn_task(stage(Arc::clone(shared), staged, proxy, Box::new(rescue)));
        Ok(relayed)
    })
}

/// A connected loopback TCP pair: the end the relay takes, and the stage's. Of the connections the listener, bound
/// for that moment only, accepts, only the engine's own is taken.
///
/// Both by `TcpSocket`, whose connect the engine's other connections use, as `TcpListener::bind` and
/// `TcpStream::connect` would make them (mio 1.2's `SO_REUSEADDR` and backlog of 128 for the listener), with no
/// generic address resolution of their own in the library (the forwarder's size pass).
async fn pair() -> io::Result<(TcpStream, TcpStream)> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let listener = socket.listen(128)?;
    let relayed = TcpSocket::new_v4()?.connect(listener.local_addr()?).await?;
    let own = relayed.local_addr()?;
    for _ in 0..4 {
        let (staged, from) = listener.accept().await?;
        if from == own {
            return Ok((relayed, staged));
        }
    }
    Err(io::ErrorKind::AddrInUse.into())
}

/// Ends `streams` with a reset, so that the relay resets the app, and the proxy's connection with it.
fn reset(streams: &[&TcpStream]) {
    for stream in streams {
        let _ = stream.set_zero_linger();
    }
}

/// The stage of one rescued flow: its first head awaited, checked and sent its way, then the connection pumped.
async fn stage(shared: Arc<Shared>, app: TcpStream, proxy: TcpStream, rescue: Box<Rescue>) {
    let _ = app.set_nodelay(true);
    let _ = proxy.set_nodelay(true);
    let answered = Instant::now();
    let mut app = app;
    let until = tokio::time::Instant::from_std(rescue.began + shared.limits.connect_timeout);
    let mut held = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new(vec![0u8; 4_096]);
    let end = loop {
        let n = match tokio::time::timeout_at(until, app.read(&mut chunk[..])).await {
            // The app closed first: nothing of a head unfinished goes on; the proxy's connection is closed.
            Ok(Ok(0)) => return,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return reset(&[&app, &proxy]),
            Err(_) => break Err(Why::TooLong),
        };
        if held.is_empty() && answered.elapsed() > LATE {
            Counters::add(&shared.counters.beneath.first_wait, 1);
        }
        let before = held.len();
        forward::reserve(&mut held, n);
        held.extend_from_slice(&chunk[..n]);
        match forward::head_end(&held, before) {
            Ok(Some(end)) => break Ok(end),
            Ok(None) if held.len() <= forward::MAX_HEAD => {}
            Ok(None) => break Err(Why::TooLong),
            Err(why) => break Err(why),
        }
    };
    let (_, destination) = rescue.ends;
    let mut out = Zeroizing::new(Vec::new());
    let first = end.and_then(|end| Ok((end, forward::first(&held[..end], destination, &mut out)?)));
    let Ok((end, first)) = first else {
        return other_way(&shared, app, proxy, &rescue, &held).await;
    };
    let id = shared.tcp_flow_of(rescue.ends.0, destination);
    if let Some(name) = &first.name {
        let bound =
            lock(&shared.names).gave(destination.ip().to_canonical(), None, name, Instant::now());
        if !bound {
            return other_way(&shared, app, proxy, &rescue, &held).await;
        }
        if connect::excluded(name, &rescue.beneath.exclusions) {
            drop(proxy);
            return directly(&shared, app, &rescue, &held, id).await;
        }
        if let Some(entry) = shared.verdict(Some(rescue.uid), name, Path::Connection) {
            shared.count_block(Some(rescue.uid), entry, false);
            if let Some(id) = id {
                shared.blocked_flow(id, entry);
            }
            Counters::add(&shared.counters.beneath.forward_reset, 1);
            return reset(&[&app, &proxy]);
        }
        if let Some(id) = id {
            shared.forwarded_name(id, name);
        }
    }
    Counters::add(&shared.counters.beneath.forwarded, 1);
    let mut framer = first.forward;
    let fed = framer.feed(&held[end..], &mut out);
    drop(held);
    let mut proxy = proxy;
    if proxy.write_all(&out).await.is_err() || fed.is_err() {
        Counters::add(
            &shared.counters.beneath.forward_reset,
            u64::from(fed.is_err()),
        );
        return reset(&[&app, &proxy]);
    }
    drop(out);
    pump(&shared, app, proxy, Some(framer)).await;
}

/// A flow whose first bytes `held` are no head the forwarder may carry: by S2's `CONNECT` where it came by a refusal
/// remembered, and so may still open; else, or where that is refused too, reset ([`refuse`]).
async fn other_way(
    shared: &Arc<Shared>,
    app: TcpStream,
    proxy: TcpStream,
    rescue: &Rescue,
    held: &[u8],
) {
    drop(proxy);
    let (from, destination) = rescue.ends;
    if rescue.remembered
        && let Ok(mut tunnel) = beneath::through(
            shared,
            &rescue.beneath,
            Some(rescue.uid),
            destination,
            rescue.began,
        )
        .await
    {
        Counters::add(&shared.counters.beneath.forward_connect, 1);
        if tunnel.write_all(held).await.is_ok() {
            pump(shared, app, tunnel, None).await;
        } else {
            reset(&[&app, &tunnel]);
        }
        return;
    }
    refuse(shared, &app, rescue, shared.tcp_flow_of(from, destination));
}

/// A flow no way can carry: reset, its outcome the direct way's where that failed (M6 of S2's audit), else `Refused`,
/// set without ending it (m14).
fn refuse(shared: &Shared, app: &TcpStream, rescue: &Rescue, id: Option<u64>) {
    let outcome = match rescue.failed {
        Some(io::ErrorKind::ConnectionRefused) | None => Outcome::Refused,
        Some(kind) if is_unreachable(&io::Error::from(kind)) => Outcome::Unreachable,
        Some(_) => Outcome::Failed,
    };
    if let Some(id) = id {
        shared.settle_relayed(id, Some(outcome), None);
    }
    Counters::add(&shared.counters.beneath.forward_reset, 1);
    reset(&[app]);
}

/// A first `Host` the exclusion list names, its head `held`: directly, with the flow's time left, where the direct way
/// had not failed and the user did not choose the proxy, as Android goes for an excluded host (the audit's m16), the
/// flow recorded direct; else reset.
async fn directly(
    shared: &Arc<Shared>,
    app: TcpStream,
    rescue: &Rescue,
    held: &[u8],
    id: Option<u64>,
) {
    if rescue.failed.is_none() && !rescue.beneath.always {
        let left = shared
            .limits
            .connect_timeout
            .saturating_sub(rescue.began.elapsed());
        if let Ok(Ok(mut server)) =
            tokio::time::timeout(left, connect_tcp(shared, rescue.target)).await
        {
            rescue.beneath.direct_opened();
            if let Some(id) = id {
                shared.settle_relayed(id, None, Some(Via::Direct));
            }
            if server.write_all(held).await.is_ok() {
                pump(shared, app, server, None).await;
            } else {
                reset(&[&app, &server]);
            }
            return;
        }
    }
    refuse(shared, &app, rescue, id);
}

/// The connection both ways until both end: the app's bytes framed and rewritten by `framer`, or carried as they are
/// through a tunnel or to the server; the other side's copied unread, its close passed on. A failure either way, or a
/// refusal of the framer after what came before it, resets both, so that the relay resets the app.
async fn pump(
    shared: &Shared,
    mut app: TcpStream,
    mut other: TcpStream,
    mut framer: Option<Forward>,
) {
    let failed = {
        let (mut from_app, mut to_app) = app.split();
        let (mut from_other, mut to_other) = other.split();
        let up = async {
            let mut chunk = Zeroizing::new(vec![0u8; 16 * 1024]);
            let mut out = Zeroizing::new(Vec::new());
            loop {
                let n = match from_app.read(&mut chunk[..]).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return false,
                };
                let Some(framer) = framer.as_mut() else {
                    if to_other.write_all(&chunk[..n]).await.is_err() {
                        return false;
                    }
                    continue;
                };
                out.clear();
                let fed = framer.feed(&chunk[..n], &mut out);
                if to_other.write_all(&out).await.is_err() {
                    return false;
                }
                if fed.is_err() {
                    Counters::add(&shared.counters.beneath.forward_reset, 1);
                    return false;
                }
            }
            let _ = to_other.shutdown().await;
            true
        };
        let down = async {
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                let n = match from_other.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return false,
                };
                if to_app.write_all(&chunk[..n]).await.is_err() {
                    return false;
                }
            }
            let _ = to_app.shutdown().await;
            true
        };
        tokio::pin!(up, down);
        let (mut up_end, mut down_end) = (None, None);
        loop {
            tokio::select! {
                end = &mut up, if up_end.is_none() => up_end = Some(end),
                end = &mut down, if down_end.is_none() => down_end = Some(end),
            }
            if up_end == Some(false) || down_end == Some(false) {
                break true;
            }
            if up_end.is_some() && down_end.is_some() {
                break false;
            }
        }
    };
    if failed {
        reset(&[&app, &other]);
    }
}
