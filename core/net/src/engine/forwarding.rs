//! The forwarder's stage: plain HTTP in absolute form (RFC 9112, 3.2.2) to the network's own proxy, for a direct app's
//! flow whose `CONNECT` that proxy refused (the proxy record's forwarder; F-PLAN, its audit, and the maintainer's
//! decision of 2026-11-27, «بله، اول CONNECT»).
//!
//! **`CONNECT` first, as S2 does, for every flow.** Only where the proxy refuses a `CONNECT` (a `4xx` other than `407`,
//! by address and then by the flow's own name, S2's steps) is the flow rescued: its SYN is answered once a connection
//! of the stage's own reached the proxy ([`beneath::reach`], so that a proxy gone hands the flow back to S2's tail at
//! the SYN, as M6 of S2's audit built it), and its first head is awaited with no cut but the flow's own
//! `Limits::connect_timeout` (the audit's M2: `HttpURLConnection`, Chromium and `WebView` write late). Only a flow S2
//! may name to the proxy is rescued ([`beneath::may_name`]): an app Android named, no circumvention tool, its route
//! direct. A forwarded head teaches the order as an opened `CONNECT` does (proxy first once
//! `Limits::beneath_failures` servers failed directly), and the flow keeps a probe it holds to its end (the review's
//! m1).
//!
//! **The refusal remembered** per proxy and port ([`Beneath::refuses`]; the review's major 1, as the coordinator
//! decided it within the maintainer's "the refusal remembered per proxy and port"): the port's policy, never one
//! site's or one app's. A port is learned only once the proxy refused two distinct names there at both of S2's steps
//! (by address, then by the flow's own name), each for a flow whose first head was then forwarded, within
//! [`beneath::REMEMBERED`] of each other; a flow with no name of its own, or whose first bytes are no forwardable head,
//! teaches nothing, so that port 443 (TLS) is never learned. The flows the forwarder may carry then come here at once,
//! with no refused round trip, for [`beneath::REMEMBERED`] from the last confirmation (a new such refusal); past it the
//! next flows go by `CONNECT` again, so that a port is tried at most that often. A `CONNECT` to the port that opens,
//! for any flow, forgets it. A flow sent here by the memory whose first bytes are no forwardable head goes by S2's
//! `CONNECT` after all, its first request on the stage's own connection to the proxy, so that the memory never costs
//! a flow its tunnel. At most 16 ports are kept, the one confirmed longest ago giving way.
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
//! passed through unread, its close included (tinyproxy answers one request per connection, measured), and its reset
//! only after the bytes the stage already took reached the relay, as the relay drains before its own (the review's
//! m4). A `407` to a forwarded request reaches the app so, unread, and sets no password fact: a proxy that asks a
//! password for requests and not for `CONNECT` is rare (the review's note 4).
//!
//! **What is not forwarded:** on a rescued flow, a reset, its outcome the direct way's where that failed, else
//! `Refused` (no other way could carry it), and the same outcome, with no reset, for a flow its app closed before its
//! head (the review's m5); on a flow sent here by a refusal remembered, S2's `CONNECT`, and a reset only
//! if that is refused too; the same for a first request whose trailer came with its head; a later head the framer
//! refuses, or a trailer once the head went, a reset after the requests before it. An excluded `Host`
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
use tokio::net::tcp::{ReadHalf, WriteHalf};
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
    /// The key of the flow's own name, where the proxy refused it after its address ([`beneath::Steps`]): what a
    /// forwarded head teaches its port ([`Beneath::forwarded`]); `None` for a flow with no name of its own, or sent here
    /// by a refusal remembered.
    pub(super) named: Option<u64>,
    /// Whether the direct way failed first: a forwarded head then teaches the order as an opened `CONNECT` does (the
    /// review's m1).
    pub(super) direct: bool,
    /// The probe the flow holds, kept to its end and given back then (the review's m1).
    pub(super) probe: Option<beneath::Probe>,
}

/// What [`rescue`] gives where the proxy cannot be reached now: the error, and the flow's probe, back to S2's tail.
type Unreached = (io::Error, Option<beneath::Probe>);

/// The rescued flow's upstream for the relay, its proxy reached first; the stage spawned behind it. An error where the
/// proxy cannot be reached now: S2's tail goes on. Boxed and out of line, as the proxy's other ways.
#[cold]
#[inline(never)]
pub(super) fn rescue(
    shared: &Arc<Shared>,
    rescue: Rescue,
) -> Pin<Box<dyn Future<Output = Result<TcpStream, Unreached>> + Send + '_>> {
    Box::pin(async move {
        let reached = async {
            let proxy = beneath::reach(shared, &rescue.beneath, rescue.began)
                .await
                .map_err(beneath::Failure::error)?;
            Ok::<_, io::Error>((proxy, pair().await?))
        }
        .await;
        let (proxy, (relayed, staged)) = match reached {
            Ok(reached) => reached,
            Err(error) => return Err((error, rescue.probe)),
        };
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
        // Never more than the head's bound and one byte held (the review's note 3).
        let room = chunk.len().min(forward::MAX_HEAD + 1 - held.len());
        let n = match tokio::time::timeout_at(until, app.read(&mut chunk[..room])).await {
            // The app closed first: nothing of a head unfinished goes on; the proxy's connection is closed, and the
            // flow recorded as no way carried it (the review's m5).
            Ok(Ok(0)) => return unopened(&shared, &rescue),
            Ok(Ok(n)) => n,
            Ok(Err(_)) => {
                unopened(&shared, &rescue);
                return reset(&[&app, &proxy]);
            }
            Err(_) => break Err(Why::TooLong),
        };
        if held.is_empty() && answered.elapsed() > LATE {
            Counters::add(&shared.counters.beneath.first_wait, 1);
        }
        let before = held.len();
        forward::reserve_within(&mut held, n, forward::MAX_HEAD + 1);
        held.extend_from_slice(&chunk[..n]);
        match forward::head_end(&held, before) {
            Ok(Some(end)) => break Ok(end),
            Ok(None) if held.len() <= forward::MAX_HEAD => {}
            Ok(None) => break Err(Why::TooLong),
            Err(why) => break Err(why),
        }
    };
    let mut out = Zeroizing::new(Vec::new());
    // One write of the first bytes and one pump for every way, so that the task holds each once (the forwarder's
    // size pass): to the proxy, the head rewritten and what followed it framed; else `held` as it came.
    let (mut other, first, framer, fed) = match way(&shared, &rescue, &held, end, &mut out) {
        Way::Forward(framer, fed) => {
            drop(held);
            (proxy, out, Some(framer), fed)
        }
        Way::Reset => return reset(&[&app, &proxy]),
        way => {
            let Some(other) = other_way(&shared, &app, &rescue, way, proxy).await else {
                return;
            };
            (other, held, None, Ok(()))
        }
    };
    if other.write_all(&first).await.is_err() || fed.is_err() {
        Counters::add(
            &shared.counters.beneath.forward_reset,
            u64::from(fed.is_err()),
        );
        return reset(&[&app, &other]);
    }
    drop(first);
    pump(&shared, app, other, framer).await;
}

/// Where a first head sends its flow ([`way`]).
enum Way {
    /// To the proxy: the head rewritten, and what followed it fed to the framer, into `out`; and whether the framer
    /// refused that.
    Forward(Forward, Result<(), Why>),
    /// No head the forwarder may carry, its name not bound to the flow's address, or a trailer with it
    /// ([`other_way`]).
    Connect,
    /// Its `Host` excluded: the flow's row, if it has one ([`other_way`]).
    Directly(Option<u64>),
    /// Its `Host` blocked: reset, recorded blocked.
    Reset,
}

/// The way of a flow whose first bytes `held` end their head at `end`: the head checked ([`forward::first`]) and
/// rewritten into `out`, its name bound to the flow's address, not excluded and not blocked for the app. No await in
/// it, out of line (the forwarder's size pass).
#[inline(never)]
fn way(
    shared: &Shared,
    rescue: &Rescue,
    held: &[u8],
    end: Result<usize, Why>,
    out: &mut Zeroizing<Vec<u8>>,
) -> Way {
    let (_, destination) = rescue.ends;
    let first = end.and_then(|end| Ok((end, forward::first(&held[..end], destination, out)?)));
    let Ok((end, first)) = first else {
        return Way::Connect;
    };
    let id = shared.tcp_flow_of(rescue.ends.0, destination);
    let forward::First {
        forward: mut framer,
        name,
    } = first;
    if let Some(name) = &name {
        let bound =
            lock(&shared.names).gave(destination.ip().to_canonical(), None, name, Instant::now());
        if !bound {
            return Way::Connect;
        }
        if connect::excluded(name, &rescue.beneath.exclusions) {
            return Way::Directly(id);
        }
        if let Some(entry) = shared.verdict(Some(rescue.uid), name, Path::Connection) {
            shared.count_block(Some(rescue.uid), entry, false);
            if let Some(id) = id {
                shared.blocked_flow(id, entry);
            }
            Counters::add(&shared.counters.beneath.forward_reset, 1);
            return Way::Reset;
        }
    }
    let fed = framer.feed(&held[end..], out);
    // The first request's trailer, come with its head: nothing written yet, so the request goes as a head the
    // forwarder may not carry, by `CONNECT` where it still may (no proxy reads the trailer as a request of its own).
    if fed == Err(Why::Trailers) && framer.first_request() {
        return Way::Connect;
    }
    if let (Some(id), Some(name)) = (id, &name) {
        shared.forwarded_name(id, name);
    }
    Counters::add(&shared.counters.beneath.forwarded, 1);
    rescue
        .beneath
        .forwarded(rescue, shared.clock.since_boot(), &shared.limits);
    Way::Forward(framer, fed)
}

/// The connection a flow whose head is not forwarded goes by, its first bytes still to write; `None` once it is
/// refused ([`refuse`]).
/// - [`Way::Connect`]: by S2's `CONNECT` where it came by a refusal remembered, and so may still open, its first
///   request on `proxy`, the stage's own connection (the review's major 1); a `CONNECT` opened forgets the port.
/// - [`Way::Directly`]: directly, with the flow's time left, where the direct way had not failed and the user did
///   not choose the proxy, as Android goes for an excluded host (the audit's m16), the flow recorded direct. Its
///   success teaches the order nothing: S2 never learns from an excluded destination (the review's note 2).
async fn other_way(
    shared: &Arc<Shared>,
    app: &TcpStream,
    rescue: &Rescue,
    way: Way,
    proxy: TcpStream,
) -> Option<TcpStream> {
    let (from, destination) = rescue.ends;
    let id = if let Way::Directly(id) = way {
        drop(proxy);
        if rescue.failed.is_none() && !rescue.beneath.always {
            let left = shared
                .limits
                .connect_timeout
                .saturating_sub(rescue.began.elapsed());
            if let Ok(Ok(server)) =
                tokio::time::timeout(left, connect_tcp(shared, rescue.target)).await
            {
                if let Some(id) = id {
                    shared.settle_relayed(id, None, Some(Via::Direct));
                }
                return Some(server);
            }
        }
        id
    } else {
        let mut steps = beneath::Steps {
            reached: Some(proxy),
            refused_name: None,
        };
        if rescue.remembered
            && let Ok(tunnel) = beneath::through(
                shared,
                &rescue.beneath,
                Some(rescue.uid),
                destination,
                rescue.began,
                &mut steps,
            )
            .await
        {
            Counters::add(&shared.counters.beneath.forward_connect, 1);
            return Some(tunnel);
        }
        shared.tcp_flow_of(from, destination)
    };
    refuse(shared, app, rescue, id);
    None
}

/// What a rescued flow that no way carried is recorded as: the direct way's outcome where that failed (M6 of S2's
/// audit), else `Refused`, where it timed out or was not tried (proxy first, or the user's choice).
fn outcome_of(failed: Option<io::ErrorKind>) -> Outcome {
    match failed {
        Some(io::ErrorKind::ConnectionRefused) | None => Outcome::Refused,
        Some(kind) if is_unreachable(&io::Error::from(kind)) => Outcome::Unreachable,
        Some(_) => Outcome::Failed,
    }
}

/// The flow `id`, recorded as no way carried it ([`outcome_of`]), set without ending it (m14).
fn settle(shared: &Shared, rescue: &Rescue, id: Option<u64>) {
    if let Some(id) = id {
        shared.settle_relayed(id, Some(outcome_of(rescue.failed)), None);
    }
}

/// The flow `rescue` names, its app gone before its head: recorded as no way carried it, with no reset for a close
/// (the review's m5).
fn unopened(shared: &Shared, rescue: &Rescue) {
    let (from, destination) = rescue.ends;
    settle(shared, rescue, shared.tcp_flow_of(from, destination));
}

/// A flow no way can carry: reset, recorded as such.
fn refuse(shared: &Shared, app: &TcpStream, rescue: &Rescue, id: Option<u64>) {
    settle(shared, rescue, id);
    Counters::add(&shared.counters.beneath.forward_reset, 1);
    reset(&[app]);
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
        let up = carry(shared, &mut from_app, &mut to_other, framer.as_mut());
        let down = carry(shared, &mut from_other, &mut to_app, None);
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
        // The bytes each side was already given reach it first, as the relay waits for them before its own reset
        // (the review's m4): a reset never cuts the end of an answer the stage already took from the proxy.
        super::tcp::drain(&app).await;
        super::tcp::drain(&other).await;
        reset(&[&app, &other]);
    }
}

/// One way of [`pump`]'s connection until it ends: what `from` gives, framed and rewritten by `framer` where there is
/// one, else as it came, to `to`, and its close passed on; `false` for a failure or a refusal of the framer. One
/// function for both ways, so that the stage holds one copy of it (the forwarder's size pass): the proxy's answers
/// pass through a buffer that is wiped too.
async fn carry(
    shared: &Shared,
    from: &mut ReadHalf<'_>,
    to: &mut WriteHalf<'_>,
    mut framer: Option<&mut Forward>,
) -> bool {
    let mut chunk = Zeroizing::new(vec![0u8; 16 * 1024]);
    let mut out = Zeroizing::new(Vec::new());
    loop {
        let n = match from.read(&mut chunk[..]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return false,
        };
        let Some(framer) = framer.as_mut() else {
            if to.write_all(&chunk[..n]).await.is_err() {
                return false;
            }
            continue;
        };
        out.clear();
        let fed = framer.feed(&chunk[..n], &mut out);
        if to.write_all(&out).await.is_err() {
            return false;
        }
        if fed.is_err() {
            Counters::add(&shared.counters.beneath.forward_reset, 1);
            return false;
        }
    }
    let _ = to.shutdown().await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rescued flow no way carried is recorded by the direct way's failure, and `Refused` where the direct way ran out
    /// or was not tried, proxy first or the user's choice (the review's m6, the lab's chance kill made a test).
    #[test]
    fn a_flow_no_way_carried_is_recorded_by_its_direct_failure_else_refused() {
        for (failed, outcome) in [
            (None, Outcome::Refused),
            (Some(io::ErrorKind::ConnectionRefused), Outcome::Refused),
            (
                Some(io::ErrorKind::NetworkUnreachable),
                Outcome::Unreachable,
            ),
            (Some(io::ErrorKind::HostUnreachable), Outcome::Unreachable),
            (Some(io::ErrorKind::PermissionDenied), Outcome::Failed),
        ] {
            assert_eq!(outcome_of(failed), outcome, "{failed:?}");
        }
    }
}
