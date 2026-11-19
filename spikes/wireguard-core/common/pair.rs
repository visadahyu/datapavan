//! Two of GotaTun's `Tunn`s joined in memory, for the size probe and the benchmark: a phone and a
//! provider's server. Every datagram passes the receiver's `RateLimiter` first, which parses it and checks
//! a handshake's MAC, as GotaTun's own device does; without the device that is the caller's job.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use bytes::BytesMut;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::tun::MtuWatcher;
use gotatun::x25519::{PublicKey, StaticSecret};

/// One end: its tunnel and the rate limiter its datagrams pass first.
pub struct Side {
    pub tunn: Tunn,
    pub limiter: Arc<RateLimiter>,
}

/// Where every datagram is said to come from (TEST-NET-1).
pub const FROM: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 51820));

/// A phone and a server whose keys come from `seed`, with an optional preshared key and the phone's
/// persistent keepalive.
pub fn pair(seed: u8, psk: Option<[u8; 32]>, keepalive: Option<u16>) -> (Side, Side) {
    let phone_secret = StaticSecret::from([seed; 32]);
    let server_secret = StaticSecret::from([seed.wrapping_add(1); 32]);
    let phone_public = PublicKey::from(&phone_secret);
    let server_public = PublicKey::from(&server_secret);
    let side = |secret, own: &PublicKey, peer, keepalive| {
        let limiter = Arc::new(RateLimiter::new(own, 100));
        let tunn = Tunn::new(
            secret,
            peer,
            psk,
            keepalive,
            IndexTable::from_os_rng(),
            Arc::clone(&limiter),
        );
        Side { tunn, limiter }
    };
    (
        side(phone_secret, &phone_public, server_public, keepalive),
        side(server_secret, &server_public, phone_public, None),
    )
}

/// Hands `datagram` to `to` as its UDP socket would.
pub fn deliver(to: &mut Side, datagram: WgKind) -> TunnResult {
    match to.limiter.verify_packet(FROM, Packet::from(datagram)) {
        Ok(kind) => to.tunn.handle_incoming_packet(kind),
        Err(result) => result,
    }
}

/// The handshake, started by `first` from the phone, which waits in the phone's queue until the session
/// stands: the decrypted `first` as the server receives it.
pub fn connect(phone: &mut Side, server: &mut Side, mtu: &mut MtuWatcher, first: Packet) -> Option<Packet> {
    let init = phone.tunn.handle_outgoing_packet(first, Some(mtu))?;
    let TunnResult::WriteToNetwork(response) = deliver(server, init) else {
        return None;
    };
    let TunnResult::WriteToNetwork(keepalive) = deliver(phone, response) else {
        return None;
    };
    let queued: Vec<WgKind> = phone.tunn.get_queued_packets(mtu).collect();
    let TunnResult::WriteToTunnel(empty) = deliver(server, keepalive) else {
        return None;
    };
    if !empty.is_empty() {
        return None;
    }
    let mut first = None;
    for datagram in queued {
        if let TunnResult::WriteToTunnel(packet) = deliver(server, datagram) {
            first.get_or_insert(packet);
        }
    }
    first
}

/// An IPv4 UDP packet of `len` bytes (at least 28), from and to addresses taken from `seed`; its checksums
/// are left at zero, which the tunnel does not read.
pub fn ipv4_udp(seed: u64, len: usize) -> Packet {
    let len = len.max(28);
    let mut bytes = vec![0u8; len];
    let total = u16::try_from(len).unwrap_or(u16::MAX);
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[10, 77, 0, 2]);
    bytes[16..20].copy_from_slice(&(0x0a4d_0001u32 ^ (seed as u32 & 0xff)).to_be_bytes());
    bytes[20..22].copy_from_slice(&40000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&7u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&(total - 20).to_be_bytes());
    for (i, byte) in bytes[28..].iter_mut().enumerate() {
        *byte = (seed as usize).wrapping_add(i) as u8;
    }
    Packet::from_bytes(BytesMut::from(&bytes[..]))
}
