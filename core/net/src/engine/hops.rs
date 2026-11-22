//! The hop limit across the network part (ADR 0044, unit 11b). The network part is not a hop: what an app sends leaves
//! with the time to live (IPv4) or hop limit (IPv6) the app gave it, copied, not lowered, so that a traceroute
//! through the network part meets the routers it would meet without it. Each datagram carries its own in the
//! ancillary data of its `sendmsg` (`IP_TTL`, `IPV6_HOPLIMIT`), so that the datagrams of one socket with
//! different hop limits, as a traceroute's probes are, need no socket option between them. What comes
//! back reaches the app with the hop limit it arrived with, which the kernel gives each datagram read
//! (`IP_RECVTTL`, `IPV6_RECVHOPLIMIT`), so that ping's `ttl=` and a traceroute's guess of the way back
//! read the network's value. nix sends and reads them with safe functions: the engine has no unsafe
//! code (ADR 0006).

use super::errors::socket_address;
use nix::libc;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg, setsockopt,
    sockopt,
};
use std::io::{self, IoSlice, IoSliceMut};
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd};
use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Asks the kernel for the hop limit each datagram `socket` reads arrived with, of the IP version
/// `ipv4` or IPv6.
pub(super) fn ask(socket: &impl AsFd, ipv4: bool) -> io::Result<()> {
    if ipv4 {
        setsockopt(socket, sockopt::Ipv4RecvTtl, &true)
    } else {
        setsockopt(socket, sockopt::Ipv6RecvHopLimit, &true)
    }
    .map_err(io::Error::from)
}

/// Room for the ancillary data of one datagram read: its hop limit. Made once for each batch of reads,
/// so that a read allocates nothing.
pub(super) fn room() -> Vec<u8> {
    nix::cmsg_space!(libc::c_int)
}

/// What one read gave: how many bytes, from where, and the hop limit they arrived with, if the kernel
/// gave one.
pub(super) type Read = (usize, SocketAddr, Option<u8>);

/// Reads one datagram the socket holds into `buffer`, without waiting, with its hop limit in `control`
/// ([`room`]), where the socket asks for it ([`ask`]).
pub(super) fn try_recv(
    socket: &UdpSocket,
    buffer: &mut [u8],
    control: &mut [u8],
) -> io::Result<Read> {
    socket.try_io(Interest::READABLE, || recv(socket, buffer, control))
}

fn recv(socket: &impl AsFd, buffer: &mut [u8], control: &mut [u8]) -> io::Result<Read> {
    let mut parts = [IoSliceMut::new(buffer)];
    let message = recvmsg::<SockaddrStorage>(
        socket.as_fd().as_raw_fd(),
        &mut parts,
        Some(control),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(io::Error::from)?;
    let from = message
        .address
        .as_ref()
        .and_then(socket_address)
        .ok_or(io::ErrorKind::InvalidData)?;
    let hops = message.cmsgs().ok().and_then(|mut messages| {
        messages.find_map(|message| match message {
            ControlMessageOwned::Ipv4Ttl(limit) | ControlMessageOwned::Ipv6HopLimit(limit) => {
                u8::try_from(limit).ok()
            }
            _ => None,
        })
    });
    Ok((message.bytes, from, hops))
}

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
