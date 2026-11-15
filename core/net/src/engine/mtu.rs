//! The MTU of the network beneath the tunnel, and of each path past it (ADR 0044, decision 5 as
//! amended on 2026-11-15). Answering an app's datagram as too large makes its kernel fragment the next
//! ones, which the engine puts together again ([`crate::fragments`]), unless the app's socket asked
//! never to fragment; such an app then sends smaller datagrams, as it would without Watch.
//!
//! - **The first hop.** `LinkProperties.getMtu()` is 0 on most networks, which says nothing, so the
//!   engine asks its own kernel: a protected UDP socket of each IP version is connected toward an
//!   address only the default route covers ([`MtuProbe`]), and `IP_MTU` is read from it, the MTU the
//!   engine's sockets meet at the first hop, IPv6's with what router advertisements said. On Linux
//!   `IP_MTU` answers for an IPv6 socket too. Connecting a UDP socket sends nothing. The engine asks at
//!   its start and again at every network change Watch reports, moved or not. A version whose probe
//!   fails (no route, `protect` refused, an error) has no known MTU, and its datagrams are never
//!   answered as too large, as before.
//! - **Beyond it.** The "fragmentation needed" and "packet too big" that routers send to a mapping's
//!   socket give a destination's path MTU, through `IP_RECVERR` ([`super::errors`]). It is kept for
//!   `Limits::mtu_expires`, as Linux keeps it (`net.ipv4.route.mtu_expires`), for at most
//!   `Limits::mtu_learned` destinations, and only where it lowers the first hop's. The app is told at
//!   once, as of an unreachable port. A network that moves forgets them: its paths are others.
//! - **What is answered.** On the direct path, a UDP datagram or an echo request whose outer packet
//!   (an IP header of 20 bytes, or 40 for IPv6, the 8 of UDP and the payload, or the ICMP message)
//!   exceeds the MTU toward its destination, that may not be fragmented (IPv6, or IPv4 with "do not
//!   fragment" set in the app's packet), and that is larger than the least MTU of its IP version (576
//!   bytes, 1,280 for IPv6), is answered "fragmentation needed" or "packet too big", as if by its
//!   destination, with the size the app's own packet may have, and dropped. A datagram the engine put
//!   together from the app's fragments is never answered: its app's kernel fragmented it already, so
//!   it may be fragmented, and the engine's kernel fragments it.
//! - **Not changed:** the chain, whose relay is on the phone, on its loopback or at an address it
//!   holds, so that what the tool sends further is its own; lookups to the tunnel's DNS address; TCP, whose segments Android's own stack sizes;
//!   and writes to the tunnel larger than its MTU, the answers the engine's kernel put together, which
//!   the network lab shows Linux takes (phones are measured in unit 11b).

use super::upstream::protect;
use super::{Counters, Limits, Shared, lock};
use crate::packet::{self, LEAST_MTU_V4, LEAST_MTU_V6};
use nix::sys::socket::{getsockopt, sockopt};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::watch;

/// Where the engine's probe of the first hop's MTU points: an address of each IP version that only the
/// default route covers, so that the route the probe's socket takes is the one the engine's other
/// sockets take to the internet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MtuProbe {
    /// The IPv4 address.
    pub v4: Ipv4Addr,
    /// The IPv6 address.
    pub v6: Ipv6Addr,
}

impl MtuProbe {
    /// Android's: documentation addresses (RFC 5737, RFC 3849), which no network routes on its own.
    /// The probe's socket is only connected, which sends nothing, so nothing ever goes to them.
    pub const DOCUMENTATION: Self = Self {
        v4: Ipv4Addr::new(192, 0, 2, 1),
        v6: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
    };
}

/// The MTUs the engine knows: the first hop's of each IP version, and what routers said of the paths
/// to some destinations.
pub(super) struct Mtus {
    /// IPv4's and IPv6's first hop, 0 while unknown.
    first_hop: [AtomicU32; 2],
    learned: Mutex<Learned>,
}

impl Mtus {
    pub(super) fn new(limits: &Limits) -> Self {
        Self {
            first_hop: [AtomicU32::new(0), AtomicU32::new(0)],
            learned: Mutex::new(Learned {
                by: HashMap::new(),
                capacity: limits.mtu_learned,
                keep: limits.mtu_expires,
            }),
        }
    }

    pub(super) fn first_hop(&self, v4: bool) -> Option<u32> {
        let mtu = self.first_hop[usize::from(!v4)].load(Ordering::Relaxed);
        (mtu > 0).then_some(mtu)
    }

    pub(super) fn set_first_hop(&self, v4: bool, mtu: Option<u32>) {
        self.first_hop[usize::from(!v4)].store(mtu.unwrap_or(0), Ordering::Relaxed);
    }

    /// The MTU toward `target` at `now`: the first hop's of its IP version, lowered by what a router
    /// said of the path to it; `None` while the first hop's is unknown.
    fn toward(&self, target: IpAddr, now: Instant) -> Option<u32> {
        let first_hop = self.first_hop(target.is_ipv4())?;
        let learned = lock(&self.learned).get(target, now);
        Some(learned.map_or(first_hop, |mtu| mtu.min(first_hop)))
    }

    /// A router said at `now` that packets toward `target` pass only up to `mtu` bytes: kept where it
    /// lowers the first hop's.
    pub(super) fn learn(&self, target: IpAddr, mtu: u32, now: Instant) {
        if self
            .first_hop(target.is_ipv4())
            .is_some_and(|first| mtu < first)
        {
            lock(&self.learned).insert(target, mtu, now);
        }
    }

    /// The network beneath is another one: what routers said of the old one's paths is forgotten.
    pub(super) fn forget(&self) {
        lock(&self.learned).by.clear();
    }
}

/// The path MTUs routers gave, by destination, each with when it expires.
struct Learned {
    by: HashMap<IpAddr, (u32, Instant)>,
    capacity: usize,
    keep: Duration,
}

impl Learned {
    fn get(&mut self, target: IpAddr, now: Instant) -> Option<u32> {
        let &(mtu, until) = self.by.get(&target)?;
        if now < until {
            return Some(mtu);
        }
        self.by.remove(&target);
        None
    }

    /// Keeps `mtu` for `target` from `now`, the lower of it and one still kept, as Linux never raises a
    /// path's MTU from an ICMP error. At the capacity, the expired go, then the one that expires first.
    fn insert(&mut self, target: IpAddr, mtu: u32, now: Instant) {
        if self.capacity == 0 {
            return;
        }
        let mtu = match self.by.get(&target) {
            Some(&(kept, until)) if now < until => kept.min(mtu),
            Some(_) => mtu,
            None => {
                if self.by.len() >= self.capacity {
                    self.by.retain(|_, &mut (_, until)| now < until);
                }
                if self.by.len() >= self.capacity {
                    let first = self
                        .by
                        .iter()
                        .min_by_key(|&(_, &(_, until))| until)
                        .map(|(&address, _)| address);
                    if let Some(first) = first {
                        self.by.remove(&first);
                    }
                }
                mtu
            }
        };
        self.by.insert(target, (mtu, now + self.keep));
    }
}

/// Asks the kernel for the first hop's MTU of each IP version, toward `toward`, at the engine's start
/// and again each time Watch reports that the network beneath changed: until the engine stops.
pub(super) async fn probe(
    shared: Arc<Shared>,
    toward: MtuProbe,
    mut changes: watch::Receiver<u64>,
) {
    loop {
        // A change reported while the probe runs makes it run again.
        changes.borrow_and_update();
        for target in [IpAddr::V4(toward.v4), IpAddr::V6(toward.v6)] {
            let mtu = first_hop(&shared, target).await;
            shared.mtus.set_first_hop(target.is_ipv4(), mtu);
        }
        if changes.changed().await.is_err() {
            return;
        }
    }
}

/// The first hop's MTU toward `target`, by `IP_MTU` on a protected socket connected there, or `None`
/// when there is no route, `protect` is refused, or the kernel says nothing.
async fn first_hop(shared: &Arc<Shared>, target: IpAddr) -> Option<u32> {
    let toward = SocketAddr::new(target, 9);
    let socket = UdpSocket::bind(packet::unspecified_like(&toward))
        .await
        .ok()?;
    protect(shared, socket.as_fd()).await.ok()?;
    socket.connect(toward).await.ok()?;
    let mtu = getsockopt(&socket, sockopt::IpMtu).ok()?;
    u32::try_from(mtu).ok().filter(|&mtu| mtu > 0)
}

/// What becomes of an app's packet on the direct path.
pub(super) enum Size {
    /// It leaves.
    Fits,
    /// It is dropped, and the app gets this answer, if any: none for a packet to a multicast or
    /// broadcast address, which no ICMP error answers (RFC 1812 4.3.2.7).
    TooLarge(Option<Vec<u8>>),
}

impl Shared {
    /// Whether the app's `packet`, up to its IP length, whose IP header with its options or extension
    /// headers is `header` bytes long, may leave toward `target`, where it really goes, by the rule of
    /// [`mtu_for`]; one that may not is counted, and answered as if by its `destination`.
    pub(super) fn size(
        &self,
        packet: &[u8],
        header: usize,
        (source, destination): (IpAddr, IpAddr),
        target: IpAddr,
    ) -> Size {
        let Some(mtu) = mtu_for(packet, header, || self.mtus.toward(target, Instant::now())) else {
            return Size::Fits;
        };
        Counters::add(&self.counters.too_big, 1);
        Size::TooLarge(packet::too_big(packet, destination, source, mtu))
    }

    /// What a router on the path to `destination` said, read off a mapping's error queue: the MTU is
    /// kept where it lowers the first hop's, counted, and the app at `app` is told, as if by the
    /// destination, with that MTU, never below the least of its IP version.
    pub(super) fn path_too_big(
        &self,
        app: SocketAddr,
        destination: SocketAddr,
        mtu: u32,
    ) -> Option<Vec<u8>> {
        self.mtus.learn(destination.ip(), mtu, Instant::now());
        Counters::add(&self.counters.path_mtu, 1);
        let least = if destination.is_ipv4() {
            LEAST_MTU_V4
        } else {
            LEAST_MTU_V6
        };
        let quoted = packet::udp(app, destination, &[])?;
        let mtu = mtu.max(u32::try_from(least).unwrap_or(u32::MAX));
        packet::too_big(&quoted, destination.ip(), app.ip(), mtu)
    }
}

/// The MTU the app is told its packet may have, when the packet may not leave: `None` when it may. The
/// rule (ADR 0044, decision 5 as amended): its outer packet, an IP header of 20 bytes or 40 for IPv6
/// and the rest of the app's packet after its own IP header, exceeds the `limit` toward its
/// destination; it may not be fragmented, being IPv6, or IPv4 with "do not fragment" set; and it is
/// larger than the least MTU of its IP version. The MTU told is the limit less the outer IP header
/// plus the app's own, with its options or extension headers, never below the least MTU: the size at
/// which the app's packet makes an outer packet that fits. `limit` is asked only when the rest holds.
fn mtu_for(packet: &[u8], header: usize, limit: impl FnOnce() -> Option<u32>) -> Option<u32> {
    let v4 = packet.first()? >> 4 == 4;
    let (outer, least) = if v4 {
        (20, LEAST_MTU_V4)
    } else {
        (40, LEAST_MTU_V6)
    };
    // IPv4 that may be fragmented leaves as it is, and the engine's kernel fragments it, as a router
    // would.
    if v4 && packet.get(6)? & 0x40 == 0 {
        return None;
    }
    if packet.len() <= least {
        return None;
    }
    let limit = usize::try_from(limit()?).ok()?;
    let rest = packet.len().checked_sub(header)?;
    if outer + rest <= limit {
        return None;
    }
    u32::try_from((limit + header).saturating_sub(outer).max(least)).ok()
}

#[cfg(test)]
mod tests {
    use super::super::tests::shared;
    use super::*;
    use etherparse::PacketBuilder;

    const APP4: [u8; 4] = [10, 1, 10, 1];
    const SERVER4: [u8; 4] = [198, 51, 100, 9];
    const APP6: [u8; 16] = [0xfd, 0, 0, 1, 0xfd, 0, 0, 1, 0xfd, 0, 0, 1, 0xfd, 0, 0, 1];
    const SERVER6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    const MINUTES: Duration = Duration::from_secs(600);

    /// An app's UDP datagram of `payload` bytes, IPv4 with "do not fragment" as `dont_fragment` says.
    fn udp4(payload: usize, dont_fragment: bool) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .udp(40_000, 9_000)
            .write(&mut packet, &vec![7; payload])
            .unwrap_or_default();
        if !dont_fragment {
            packet[6] = 0;
        }
        packet
    }

    fn udp6(payload: usize) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv6(APP6, SERVER6, 64)
            .udp(40_000, 9_000)
            .write(&mut packet, &vec![7; payload])
            .unwrap_or_default();
        packet
    }

    /// The rule, at its edges: an outer packet one byte past the limit is answered, one that fits is
    /// not; IPv4 without "do not fragment" never is, nor anything no larger than the least MTU, nor
    /// anything while the limit is unknown.
    #[test]
    fn a_packet_is_answered_only_when_the_rule_holds() {
        let limit = || Some(1_280);
        // 20 + 8 + 1,252 = 1,280 fits; 1,253 does not, and the app may send 1,280.
        assert_eq!(mtu_for(&udp4(1_252, true), 20, limit), None);
        assert_eq!(mtu_for(&udp4(1_253, true), 20, limit), Some(1_280));
        assert_eq!(mtu_for(&udp4(1_472, false), 20, limit), None);
        assert_eq!(mtu_for(&udp4(1_472, true), 20, || None), None);
        // At the least MTU of each version, never; IPv6 always may not be fragmented.
        assert_eq!(mtu_for(&udp4(548, true), 20, || Some(500)), None);
        assert_eq!(mtu_for(&udp4(549, true), 20, || Some(500)), Some(576));
        assert_eq!(mtu_for(&udp6(1_232), 40, || Some(1_000)), None);
        assert_eq!(mtu_for(&udp6(1_233), 40, || Some(1_280)), Some(1_280));
        assert_eq!(mtu_for(&udp6(1_452), 40, || Some(1_500)), None);
        // The limit is asked only when the rest of the rule holds.
        assert_eq!(
            mtu_for(&udp4(1_472, false), 20, || unreachable!("asked")),
            None
        );
    }

    /// The MTU told is the one the app's own packet may have: with 8 bytes of IPv6 extension headers,
    /// or 4 of IPv4 options, that much more than the outer packet's.
    #[test]
    fn the_mtu_told_counts_the_apps_own_headers() {
        let mut with_options = udp6(1_400);
        with_options.splice(40..40, [packet::UDP, 0, 1, 4, 0, 0, 0, 0]);
        with_options[6] = 0;
        let payload = u16::try_from(with_options.len() - 40).unwrap_or(0);
        with_options[4..6].copy_from_slice(&payload.to_be_bytes());
        assert!(packet::parse(&with_options).is_ok_and(|p| p.transport == 48));
        assert_eq!(mtu_for(&with_options, 48, || Some(1_280)), Some(1_288));
        // An echo request's message counts as UDP's header and payload do.
        let mut ping = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .icmpv4_echo_request(1, 1)
            .write(&mut ping, &[0; 1_400])
            .unwrap_or_default();
        assert_eq!(mtu_for(&ping, 20, || Some(1_400)), Some(1_400));
        assert_eq!(mtu_for(&ping, 20, || Some(1_428)), None);
    }

    /// The first hop's MTU, lowered by what a router said, for `mtu_expires`, a nanosecond before it
    /// and not at it; a router never raises it, and the first hop's is never raised either.
    #[test]
    fn a_learned_mtu_lowers_the_first_hops_until_it_expires() {
        let shared = shared();
        let mtus = &shared.mtus;
        let now = Instant::now();
        let server = IpAddr::from(SERVER4);
        assert_eq!(mtus.toward(server, now), None);
        // While the first hop's is unknown, nothing is learned.
        mtus.learn(server, 1_000, now);
        mtus.set_first_hop(true, Some(1_500));
        assert_eq!(mtus.toward(server, now), Some(1_500));
        assert_eq!(mtus.toward(IpAddr::from(SERVER6), now), None);
        mtus.learn(server, 1_600, now);
        assert_eq!(mtus.toward(server, now), Some(1_500));
        mtus.learn(server, 1_400, now);
        mtus.learn(server, 1_450, now + Duration::from_secs(1));
        let until = now + Duration::from_secs(1) + MINUTES;
        let just_before =
            now + Duration::from_secs(1) + MINUTES.saturating_sub(Duration::from_nanos(1));
        assert_eq!(mtus.toward(server, just_before), Some(1_400));
        assert_eq!(mtus.toward(server, until), Some(1_500));
        // A first hop lowered below what was learned wins.
        mtus.learn(server, 1_400, now);
        mtus.set_first_hop(true, Some(1_300));
        assert_eq!(mtus.toward(server, now), Some(1_300));
        mtus.forget();
        mtus.set_first_hop(true, Some(1_500));
        assert_eq!(mtus.toward(server, now), Some(1_500));
    }

    /// At most `mtu_learned` destinations: past it, an expired one goes first, then the one that
    /// expires first.
    #[test]
    fn learned_mtus_are_bounded() {
        let mut learned = Learned {
            by: HashMap::new(),
            capacity: 2,
            keep: MINUTES,
        };
        let now = Instant::now();
        let at = |last: u8| IpAddr::from([198, 51, 100, last]);
        learned.insert(at(1), 1_400, now);
        learned.insert(at(2), 1_400, now + Duration::from_secs(1));
        learned.insert(at(3), 1_400, now + Duration::from_secs(2));
        assert_eq!(learned.by.len(), 2);
        assert_eq!(learned.get(at(1), now), None);
        assert_eq!(learned.get(at(2), now), Some(1_400));
        // One expired makes room before any other is put out.
        learned.insert(at(4), 1_300, now + MINUTES + Duration::from_secs(1));
        assert_eq!(
            learned.get(at(3), now + MINUTES + Duration::from_secs(1)),
            Some(1_400)
        );
        assert_eq!(learned.by.len(), 2);
        let mut none = Learned {
            by: HashMap::new(),
            capacity: 0,
            keep: MINUTES,
        };
        none.insert(at(1), 1_400, now);
        assert!(none.by.is_empty());
    }

    /// The answer: from the destination to the app, type 3 code 4 or type 2, with the MTU in its
    /// place, quoting the app's packet; counted. None for a datagram to a broadcast address, though
    /// it is dropped and counted all the same.
    #[test]
    fn a_datagram_too_large_is_answered_as_if_by_its_destination() {
        let shared = shared();
        shared.mtus.set_first_hop(true, Some(1_280));
        shared.mtus.set_first_hop(false, Some(1_280));
        let (app, server) = (IpAddr::from(APP4), IpAddr::from(SERVER4));
        let datagram = udp4(1_472, true);
        let Size::TooLarge(Some(answer)) = shared.size(&datagram, 20, (app, server), server) else {
            unreachable!("not answered")
        };
        assert_eq!(
            (&answer[12..16], &answer[16..20]),
            (&SERVER4[..], &APP4[..])
        );
        assert_eq!(&answer[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([answer[26], answer[27]]), 1_280);
        assert_eq!(&answer[28..], &datagram[..576 - 28]);
        let (app6, server6) = (IpAddr::from(APP6), IpAddr::from(SERVER6));
        let datagram6 = udp6(1_452);
        let Size::TooLarge(Some(answer6)) = shared.size(&datagram6, 40, (app6, server6), server6)
        else {
            unreachable!("not answered")
        };
        assert_eq!(&answer6[40..42], &[2, 0]);
        assert_eq!(
            u32::from_be_bytes([answer6[44], answer6[45], answer6[46], answer6[47]]),
            1_280
        );
        assert_eq!(answer6.len(), 1_280);
        let broadcast = IpAddr::from([255, 255, 255, 255]);
        assert!(matches!(
            shared.size(&datagram, 20, (app, broadcast), broadcast),
            Size::TooLarge(None)
        ));
        assert!(matches!(
            shared.size(&udp4(1_252, true), 20, (app, server), server),
            Size::Fits
        ));
        assert_eq!(shared.counters.snapshot()[TOO_BIG], 3);
    }

    /// A router's MTU is passed on to the app as if from the destination, never below the least MTU,
    /// and counted.
    #[test]
    fn a_routers_mtu_is_passed_on_to_the_app() {
        let shared = shared();
        shared.mtus.set_first_hop(true, Some(1_500));
        let app = SocketAddr::from((APP4, 40_000));
        let server = SocketAddr::from((SERVER4, 9_000));
        let told = shared.path_too_big(app, server, 1_400).unwrap_or_default();
        assert_eq!((&told[12..16], &told[16..20]), (&SERVER4[..], &APP4[..]));
        assert_eq!(&told[20..22], &[3, 4]);
        assert_eq!(u16::from_be_bytes([told[26], told[27]]), 1_400);
        // The quoted datagram names the app's socket and the destination's port.
        assert_eq!(
            packet::parse(&told[28..]).map(|p| (p.source, p.destination)),
            Ok((app, server))
        );
        assert_eq!(shared.mtus.toward(server.ip(), Instant::now()), Some(1_400));
        let told = shared.path_too_big(app, server, 300).unwrap_or_default();
        assert_eq!(u16::from_be_bytes([told[26], told[27]]), 576);
        assert_eq!(shared.counters.snapshot()[PATH_MTU], 2);
    }

    const TOO_BIG: usize = 39;
    const PATH_MTU: usize = 40;
}
