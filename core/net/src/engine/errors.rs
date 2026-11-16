//! The ICMP errors that answer the engine's datagrams and echo requests on the network beneath (ADR
//! 0044, decision 1 and unit 11b). A connected socket learns of such an error by itself; an unconnected
//! one, as a mapping's or a ping socket, only with `IP_RECVERR` or `IPV6_RECVERR`. The kernel then
//! queues each error on the socket's error queue, with the destination of the packet it answered, the
//! address of the router or host that sent it (`SO_EE_OFFENDER`), as much of that packet as the error
//! quoted, and for "fragmentation needed" or "packet too big" the MTU the router gave (decision 5 as
//! amended). Each reaches the app as it would without Watch: from that router or host, about what the
//! app sent. nix reads that queue with safe functions: the engine has no unsafe code (ADR 0006).

use super::Counters;
use super::udp::on_the_phone;
use crate::packet;
use nix::errno::Errno;
use nix::libc;
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// At most this many errors are read from a socket at one wake-up.
const AT_ONCE: usize = 64;

/// Asks the kernel to queue the ICMP errors that answer the datagrams of `socket`, of the IP version
/// `ipv4` or IPv6.
pub(super) fn keep(socket: &impl AsFd, ipv4: bool) -> io::Result<()> {
    if ipv4 {
        setsockopt(socket, sockopt::Ipv4RecvErr, &true)
    } else {
        setsockopt(socket, sockopt::Ipv6RecvErr, &true)
    }
    .map_err(io::Error::from)
}

/// What the app is told of an error from the network beneath, as the router or host sent it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Told {
    /// "Destination unreachable" (ICMP's type 3, `ICMPv6`'s type 1), with the code it came with: the
    /// network, the host, the port, a prohibition, and the rest.
    Unreachable(u8),
    /// A router on the path takes packets of at most this many bytes.
    TooBig(u32),
    /// A router on the path found the packet's hop limit spent: "time exceeded in transit" (ICMP's
    /// type 11 code 0, `ICMPv6`'s type 3 code 0), what a traceroute asks each hop for.
    TimeExceeded,
}

/// An error read off a socket's queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Queued {
    /// The destination of the packet it answered.
    pub(super) destination: SocketAddr,
    pub(super) told: Told,
    /// Who sent it, a router on the path or the destination's host, where the kernel names one.
    pub(super) offender: Option<IpAddr>,
    /// The hop limit it arrived with, on a socket that asks for hop limits (`hops::ask`).
    pub(super) hops: Option<u8>,
    /// What it quoted of the packet it answered, from the packet's transport header on, as far as the
    /// reader's room took: for an echo request, its ICMP header and data.
    pub(super) quoted: Vec<u8>,
}

/// The errors queued for `socket` now, read off its queue, which also clears its readiness for errors:
/// a connected socket's own error comes with its next read instead. What each quoted is kept as far as
/// `quote` has room, none when it is empty.
pub(super) fn take(socket: &UdpSocket, quote: &mut [u8]) -> Vec<Queued> {
    let mut found = Vec::new();
    let _ = socket.try_io(Interest::ERROR, || {
        found = queued(socket, quote);
        Err::<(), _>(io::ErrorKind::WouldBlock.into())
    });
    found
}

/// The errors queued for `socket`, read off its queue. Errors the app is not told of are read and left
/// out.
fn queued(socket: &impl AsFd, quote: &mut [u8]) -> Vec<Queued> {
    let fd = socket.as_fd().as_raw_fd();
    let mut found = Vec::new();
    // The error, and the address of the router or host that sent it; and, on a socket that asks for
    // the hop limits of what it reads (`hops::ask`), the error's own, which comes first: without room
    // for both, the error would be cut off.
    let mut control = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6, libc::c_int);
    for _ in 0..AT_ONCE {
        let mut parts = [IoSliceMut::new(&mut *quote)];
        let Ok(message) = recvmsg::<SockaddrStorage>(
            fd,
            &mut parts,
            Some(&mut control),
            MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
        ) else {
            break;
        };
        let destination = message.address.as_ref().and_then(socket_address);
        let quoted = message.bytes;
        let (mut error, mut hops) = (None, None);
        for message in message.cmsgs().into_iter().flatten() {
            match message {
                ControlMessageOwned::Ipv4RecvErr(read, offender) => {
                    error = Some((read, offender.and_then(v4_address)));
                }
                ControlMessageOwned::Ipv6RecvErr(read, offender) => {
                    error = Some((read, offender.and_then(v6_address)));
                }
                ControlMessageOwned::Ipv4Ttl(limit) | ControlMessageOwned::Ipv6HopLimit(limit) => {
                    hops = u8::try_from(limit).ok();
                }
                _ => {}
            }
        }
        let (Some(destination), Some((error, offender))) = (destination, error) else {
            continue;
        };
        if let Some(told) = told(&error) {
            found.push(Queued {
                destination,
                told,
                offender,
                hops,
                quoted: quote[..quoted.min(quote.len())].to_vec(),
            });
        }
    }
    found
}

/// What the app is told of an extended error: "destination unreachable" with its code, but ICMP's
/// "fragmentation needed" (type 3 code 4, RFC 1191) and `ICMPv6`'s "packet too big" (type 2, RFC 8201),
/// which are told with the MTU the kernel gives in `ee_info` (ADR 0044, decision 5 as amended); and
/// "time exceeded in transit" (unit 11b). A router older than RFC 1191 gives an MTU of 0, which says
/// nothing of the path: such an error is left out. The rest, as "parameter problem" or a fragment's
/// reassembly that timed out, are left out too, as are the engine's kernel's own errors.
fn told(error: &libc::sock_extended_err) -> Option<Told> {
    match (error.ee_origin, error.ee_type, error.ee_code) {
        (libc::SO_EE_ORIGIN_ICMP, 3, 4) | (libc::SO_EE_ORIGIN_ICMP6, 2, _) => {
            (error.ee_info > 0).then_some(Told::TooBig(error.ee_info))
        }
        (libc::SO_EE_ORIGIN_ICMP, 3, code) | (libc::SO_EE_ORIGIN_ICMP6, 1, code) => {
            Some(Told::Unreachable(code))
        }
        (libc::SO_EE_ORIGIN_ICMP, 11, 0) | (libc::SO_EE_ORIGIN_ICMP6, 3, 0) => {
            Some(Told::TimeExceeded)
        }
        _ => None,
    }
}

/// The IPv4 address of an error's sender, as the kernel gives it.
fn v4_address(address: libc::sockaddr_in) -> Option<IpAddr> {
    (i32::from(address.sin_family) == libc::AF_INET)
        .then(|| IpAddr::V4(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))))
}

/// The IPv6 address of an error's sender, as the kernel gives it.
fn v6_address(address: libc::sockaddr_in6) -> Option<IpAddr> {
    (i32::from(address.sin6_family) == libc::AF_INET6)
        .then(|| IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
}

/// Whom an error reaches the app from: the router or host that sent it, `offender`, as it would without
/// Watch; but the address the app knows, `shown`, where the kernel names no sender, where the sender is
/// the very address the engine sent to, `target`, which the app may know by another (the tunnel's DNS
/// address for the network's resolver), where it is no address an error may come from, or where it is
/// one of the phone's own. The engine's kernel sends an error from the phone's address on the network
/// beneath when it answers itself, as with "host unreachable" when a neighbour does not answer; the
/// app's kernel would drop such a packet coming in on the tunnel as a martian source, and the app then
/// wait for its timeout, as it did not before this unit.
pub(super) fn sender(offender: Option<IpAddr>, target: IpAddr, shown: IpAddr) -> IpAddr {
    match offender {
        Some(from)
            if from != target
                && from.is_ipv4() == shown.is_ipv4()
                && packet::unicast(from)
                && !on_the_phone(SocketAddr::new(from, 9)) =>
        {
            from
        }
        _ => shown,
    }
}

/// The error `told` for the app at `to`, from `from`, quoting `quoted`, with the hop limit it arrived
/// with where the kernel gave one: what the router or host sent the engine, as it would have reached
/// the app without Watch.
pub(super) fn to_app(
    told: Told,
    quoted: &[u8],
    (from, to): (IpAddr, IpAddr),
    hops: Option<u8>,
) -> Option<Vec<u8>> {
    let v4 = to.is_ipv4();
    let mut error = match told {
        Told::TooBig(mtu) => packet::too_big(quoted, from, to, mtu),
        Told::Unreachable(code) => {
            packet::path_error(quoted, (from, to), (if v4 { 3 } else { 1 }, code), [0; 4])
        }
        Told::TimeExceeded => {
            packet::path_error(quoted, (from, to), (if v4 { 11 } else { 3 }, 0), [0; 4])
        }
    }?;
    if let Some(hops) = hops {
        packet::set_hops(&mut error, hops);
    }
    Some(error)
}

/// The errors from the path that one read passed on, by kind, and those it dropped as answering nothing
/// the app sent, for the counters.
#[derive(Debug, Default)]
pub(super) struct Tally {
    too_big: u64,
    time_exceeded: u64,
    unreachable: u64,
    unasked: u64,
}

impl Tally {
    /// One error of this kind passed on.
    pub(super) fn passed(&mut self, told: Told) {
        let kind = match told {
            Told::TooBig(_) => &mut self.too_big,
            Told::TimeExceeded => &mut self.time_exceeded,
            Told::Unreachable(_) => &mut self.unreachable,
        };
        *kind += 1;
    }

    /// One error dropped: it answered nothing the app sent, or the app was told of one already for
    /// what it answered.
    pub(super) fn unasked(&mut self) {
        self.unasked += 1;
    }

    /// Adds them to the counters, and, for errors that answered echo requests, `echo`, to echo's
    /// own.
    pub(super) fn count(&self, counters: &Counters, echo: bool) {
        Counters::add(&counters.path_mtu, self.too_big);
        Counters::add(&counters.time_exceeded, self.time_exceeded);
        Counters::add(&counters.path_unreachable, self.unreachable);
        Counters::add(&counters.errors_unasked, self.unasked);
        if echo {
            let passed = self.too_big + self.time_exceeded + self.unreachable;
            Counters::add(&counters.echo_errors, passed);
        }
    }
}

/// The address of a datagram's destination, or its sender, without an IPv6 flow label or scope.
pub(super) fn socket_address(address: &SockaddrStorage) -> Option<SocketAddr> {
    let address = match (address.as_sockaddr_in(), address.as_sockaddr_in6()) {
        (Some(v4), _) => SocketAddr::from(SocketAddrV4::from(*v4)),
        (None, Some(v6)) => SocketAddr::from(SocketAddrV6::from(*v6)),
        (None, None) => return None,
    };
    Some(SocketAddr::new(address.ip(), address.port()))
}

/// Whether a read or a send of an unconnected socket failed with the error of an ICMP message the
/// kernel had for it (Linux's `icmp_err_convert` and `icmpv6_err_convert`, and a ping socket's own
/// `EREMOTEIO` for a source quench or a redirect): that call took the error, and the socket goes on.
/// Which destination it was for comes from the error queue.
pub(super) fn from_icmp(error: &io::Error) -> bool {
    error.raw_os_error().map(Errno::from_raw).is_some_and(|e| {
        matches!(
            e,
            Errno::ECONNREFUSED
                | Errno::EHOSTUNREACH
                | Errno::ENETUNREACH
                | Errno::EHOSTDOWN
                | Errno::ENONET
                | Errno::ENOPROTOOPT
                | Errno::EOPNOTSUPP
                | Errno::EMSGSIZE
                | Errno::EPROTO
                | Errno::EACCES
                | Errno::EREMOTEIO
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(origin: u8, kind: u8, code: u8, info: u32) -> libc::sock_extended_err {
        libc::sock_extended_err {
            ee_errno: 0,
            ee_origin: origin,
            ee_type: kind,
            ee_code: code,
            ee_pad: 0,
            ee_info: info,
            ee_data: 0,
        }
    }

    #[test]
    fn the_app_is_told_of_unreachables_time_exceeded_and_the_mtu_a_router_gives() {
        let (icmp, icmp6) = (libc::SO_EE_ORIGIN_ICMP, libc::SO_EE_ORIGIN_ICMP6);
        let told = |origin, kind, code| told(&error(origin, kind, code, 0));
        // Each unreachable with the code it came with.
        assert_eq!(told(icmp, 3, 3), Some(Told::Unreachable(3)));
        assert_eq!(told(icmp6, 1, 4), Some(Told::Unreachable(4)));
        assert_eq!(told(icmp, 3, 0), Some(Told::Unreachable(0)));
        assert_eq!(told(icmp, 3, 13), Some(Told::Unreachable(13)));
        assert_eq!(told(icmp6, 1, 0), Some(Told::Unreachable(0)));
        // Fragmentation needed and packet too big, with the MTU the router gave; with none, as from a
        // router older than RFC 1191, nothing.
        let mtu = |origin, kind, code, info| super::told(&error(origin, kind, code, info));
        assert_eq!(mtu(icmp, 3, 4, 1_280), Some(Told::TooBig(1_280)));
        assert_eq!(mtu(icmp6, 2, 0, 1_400), Some(Told::TooBig(1_400)));
        assert_eq!(mtu(icmp, 3, 4, 0), None);
        assert_eq!(mtu(icmp6, 2, 0, 0), None);
        // Time exceeded in transit, but not a fragment's reassembly that timed out, nor a parameter
        // problem, nor a local error, as the kernel's own "message too long", which says the MTU too.
        assert_eq!(told(icmp, 11, 0), Some(Told::TimeExceeded));
        assert_eq!(told(icmp6, 3, 0), Some(Told::TimeExceeded));
        assert_eq!(told(icmp, 11, 1), None);
        assert_eq!(told(icmp6, 3, 1), None);
        assert_eq!(told(icmp, 12, 0), None);
        assert_eq!(mtu(libc::SO_EE_ORIGIN_LOCAL, 0, 0, 1_280), None);
    }

    /// An error reaches the app from the router or host that sent it; from the address the app knows
    /// where none is named, where it came from the very address the engine sent to, where its sender is
    /// no address an error may come from, or where it is the phone's own.
    #[test]
    fn an_error_reaches_the_app_from_whoever_sent_it() {
        let router = IpAddr::from([192, 0, 2, 1]);
        let (target, shown) = (
            IpAddr::from([198, 51, 100, 53]),
            IpAddr::from([10, 1, 10, 3]),
        );
        assert_eq!(sender(Some(router), target, shown), router);
        assert_eq!(sender(None, target, shown), shown);
        assert_eq!(sender(Some(target), target, shown), shown);
        let multicast = IpAddr::from([224, 0, 0, 1]);
        assert_eq!(sender(Some(multicast), target, shown), shown);
        let own = IpAddr::from([127, 0, 0, 1]);
        assert_eq!(sender(Some(own), target, shown), shown, "the phone's own");
        let unspecified = IpAddr::from([0, 0, 0, 0]);
        assert_eq!(sender(Some(unspecified), target, shown), shown);
        let v6 = IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        assert_eq!(sender(Some(v6), target, shown), shown, "another IP version");
    }
}
