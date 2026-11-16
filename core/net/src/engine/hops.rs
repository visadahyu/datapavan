//! The hop limit across Watch (ADR 0044, unit 11b). Watch is not a hop: what an app sends leaves with the
//! time to live (IPv4) or hop limit (IPv6) the app gave it, copied, not lowered, so that a traceroute
//! through Watch meets the routers it would meet without it. Each datagram carries its own in the
//! ancillary data of its `sendmsg` (`IP_TTL`, `IPV6_HOPLIMIT`), so that the datagrams of one socket with
//! different hop limits, as a traceroute's probes are, need no socket option between them. nix sends
//! them with safe functions: the engine has no unsafe code (ADR 0006).

use nix::libc;
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Sends `payload` from `socket` to `to` with the hop limit `hops`, without waiting for room in the
/// socket's buffer.
pub(super) fn try_send(
    socket: &UdpSocket,
    payload: &[u8],
    to: SocketAddr,
    hops: u8,
) -> io::Result<usize> {
    socket.try_io(Interest::WRITABLE, || send(socket, payload, to, hops))
}

/// As [`try_send`], waiting for room in the socket's buffer.
pub(super) async fn send_waiting(
    socket: &UdpSocket,
    payload: &[u8],
    to: SocketAddr,
    hops: u8,
) -> io::Result<usize> {
    socket
        .async_io(Interest::WRITABLE, || send(socket, payload, to, hops))
        .await
}

/// One `sendmsg` of `payload` to `to`, with `hops` as its ancillary data. IPv4 takes a time to live of 1
/// to 255 (Linux's `ip_cmsg_send`); a packet that came with 0, which no socket could have sent, leaves
/// with the socket's own. IPv6 takes 0 too.
fn send(socket: &impl AsFd, payload: &[u8], to: SocketAddr, hops: u8) -> io::Result<usize> {
    let hops = libc::c_int::from(hops);
    let control = match to {
        SocketAddr::V4(_) if hops == 0 => None,
        SocketAddr::V4(_) => Some(ControlMessage::Ipv4Ttl(&hops)),
        SocketAddr::V6(_) => Some(ControlMessage::Ipv6HopLimit(&hops)),
    };
    sendmsg(
        socket.as_fd().as_raw_fd(),
        &[IoSlice::new(payload)],
        control.as_slice(),
        MsgFlags::MSG_DONTWAIT,
        Some(&SockaddrStorage::from(to)),
    )
    .map_err(io::Error::from)
}
