//! The ICMP errors that answer a mapping's datagrams (ADR 0044, decision 1). A connected socket learns
//! of such an error by itself; an unconnected one only with `IP_RECVERR` or `IPV6_RECVERR`. The kernel
//! then queues each error on the socket's error queue, with the destination of the datagram it
//! answered, and for "fragmentation needed" or "packet too big" the MTU the router gave (decision 5
//! as amended). nix reads that queue with safe functions: the engine has no unsafe code (ADR 0006).

use crate::packet::Unreachable;
use nix::errno::Errno;
use nix::libc;
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd};

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

/// What the app is told of an error from the network beneath.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Told {
    /// The destination, or its port, cannot be reached.
    Unreachable(Unreachable),
    /// A router on the path takes packets of at most this many bytes.
    TooBig(u32),
}

/// The errors queued for `socket`, read off its queue: for each, the destination of the datagram it
/// answered, and what the app is told. Errors the app is not told of are read and left out.
pub(super) fn queued(socket: &impl AsFd) -> Vec<(SocketAddr, Told)> {
    let fd = socket.as_fd().as_raw_fd();
    let mut found = Vec::new();
    // The error, and the address of the router or host that sent it.
    let mut control = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in6);
    for _ in 0..AT_ONCE {
        // The quoted datagram is not needed: the destination names it.
        let Ok(message) = recvmsg::<SockaddrStorage>(
            fd,
            &mut [],
            Some(&mut control),
            MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
        ) else {
            break;
        };
        let Some(destination) = message.address.as_ref().and_then(socket_address) else {
            continue;
        };
        let Ok(messages) = message.cmsgs() else {
            continue;
        };
        for message in messages {
            if let ControlMessageOwned::Ipv4RecvErr(error, _)
            | ControlMessageOwned::Ipv6RecvErr(error, _) = message
                && let Some(told) = told(&error)
            {
                found.push((destination, told));
            }
        }
    }
    found
}

/// What the app is told of an extended error: "port unreachable" for ICMP's type 3 code 3 or
/// `ICMPv6`'s type 1 code 4, "host unreachable" for the other unreachables, and the MTU of ICMP's
/// "fragmentation needed" (type 3 code 4, RFC 1191) or `ICMPv6`'s "packet too big" (type 2, RFC 8201),
/// which the kernel gives in `ee_info` (ADR 0044, decision 5 as amended). A router older than RFC 1191
/// gives an MTU of 0, which says nothing of the path: such an error is left out. The rest, as "time
/// exceeded", are left out too.
fn told(error: &libc::sock_extended_err) -> Option<Told> {
    match (error.ee_origin, error.ee_type, error.ee_code) {
        (libc::SO_EE_ORIGIN_ICMP, 3, 3) | (libc::SO_EE_ORIGIN_ICMP6, 1, 4) => {
            Some(Told::Unreachable(Unreachable::Port))
        }
        (libc::SO_EE_ORIGIN_ICMP, 3, 4) | (libc::SO_EE_ORIGIN_ICMP6, 2, _) => {
            (error.ee_info > 0).then_some(Told::TooBig(error.ee_info))
        }
        (libc::SO_EE_ORIGIN_ICMP, 3, _) | (libc::SO_EE_ORIGIN_ICMP6, 1, _) => {
            Some(Told::Unreachable(Unreachable::Host))
        }
        _ => None,
    }
}

/// The address of a datagram's destination, without an IPv6 flow label or scope.
fn socket_address(address: &SockaddrStorage) -> Option<SocketAddr> {
    let address = match (address.as_sockaddr_in(), address.as_sockaddr_in6()) {
        (Some(v4), _) => SocketAddr::from(SocketAddrV4::from(*v4)),
        (None, Some(v6)) => SocketAddr::from(SocketAddrV6::from(*v6)),
        (None, None) => return None,
    };
    Some(SocketAddr::new(address.ip(), address.port()))
}

/// Whether a read of an unconnected socket failed with the error of an ICMP message the kernel had
/// for it (Linux's `icmp_err_convert` and `icmpv6_err_convert`): that read took the error, and the
/// socket goes on. Which destination it was for comes from the error queue.
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
    fn the_app_is_told_of_unreachables_and_of_the_mtu_a_router_gives() {
        let (icmp, icmp6) = (libc::SO_EE_ORIGIN_ICMP, libc::SO_EE_ORIGIN_ICMP6);
        let told = |origin, kind, code| told(&error(origin, kind, code, 0));
        let (port, host) = (
            Some(Told::Unreachable(Unreachable::Port)),
            Some(Told::Unreachable(Unreachable::Host)),
        );
        assert_eq!(told(icmp, 3, 3), port);
        assert_eq!(told(icmp6, 1, 4), port);
        assert_eq!(told(icmp, 3, 1), host);
        assert_eq!(told(icmp, 3, 13), host);
        assert_eq!(told(icmp6, 1, 1), host);
        // Fragmentation needed and packet too big, with the MTU the router gave; with none, as from a
        // router older than RFC 1191, nothing.
        let mtu = |origin, kind, code, info| super::told(&error(origin, kind, code, info));
        assert_eq!(mtu(icmp, 3, 4, 1_280), Some(Told::TooBig(1_280)));
        assert_eq!(mtu(icmp6, 2, 0, 1_400), Some(Told::TooBig(1_400)));
        assert_eq!(mtu(icmp, 3, 4, 0), None);
        assert_eq!(mtu(icmp6, 2, 0, 0), None);
        // Time exceeded, and a local error, as the kernel's own "message too long", which says the
        // MTU too: neither comes from the path.
        assert_eq!(told(icmp, 11, 0), None);
        assert_eq!(mtu(libc::SO_EE_ORIGIN_LOCAL, 0, 0, 1_280), None);
    }
}
