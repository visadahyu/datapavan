//! The protocol core behind one small trait (ADR 0035, Decision): handshake, keys, timers and
//! encryption, fed packet by packet. [`GotaTun`] is the core the network part runs, Mullvad's `noise::Tunn` with no
//! device, TUN or socket; this module is the only one that names it, so that another core (sanstun,
//! `BoringTun`) can take its place here alone.
//!
//! What `GotaTun` asks of its caller without its device (the spike, "The API as of 0.10.3"), each kept
//! here: every datagram passes `RateLimiter::verify_packet` before `Tunn` (the MAC check, and a cookie
//! reply under load), packets are padded through an `MtuWatcher`, the packets queued during a handshake
//! are drained once it completes, and a decrypted packet is cut to its IP length. The caller keeps the
//! rest: `AllowedIPs` after decryption, the endpoint, the timers' tick ([`Core::timers`]), which it must
//! also call before a packet that comes after a pause.

use super::config::Config;
use bytes::BytesMut;
use gotatun::noise::errors::WireGuardError;
use gotatun::noise::index_table::IndexTable;
use gotatun::noise::rate_limiter::RateLimiter;
use gotatun::noise::{Tunn, TunnResult};
use gotatun::packet::{Packet, WgKind};
use gotatun::tun::MtuWatcher;
use gotatun::x25519::{PublicKey, StaticSecret};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

/// How many handshakes a second the rate limiter takes before it asks for cookies: `WireGuard`'s own
/// device's limit.
const HANDSHAKES_PER_SECOND: u64 = 100;

/// At most this many packets wait in `GotaTun`'s queue while a handshake runs; later ones are dropped
/// without a word (`MAX_QUEUE_DEPTH` in its `noise` module), which [`GotaTun`] counts.
pub const QUEUE: usize = 256;

/// What became of an app's packet handed to the core.
#[derive(Debug, PartialEq, Eq)]
pub enum Sent {
    /// Encrypted in a session: the datagram for the server.
    Data(Vec<u8>),
    /// No session: the packet waits in the queue, and a handshake initiation goes first.
    Handshake(Vec<u8>),
    /// No session: the packet waits behind a handshake already sent.
    Queued,
    /// No session and the queue full: the packet is lost.
    Dropped,
}

/// What a datagram from the server gave.
#[derive(Debug, PartialEq, Eq)]
pub enum Received {
    /// Datagrams for the server: a cookie reply's or a handshake's answer, then, once a handshake that
    /// the network part started completes, the packets that waited for it. `established` says it completed.
    Send {
        /// The datagrams, in order.
        datagrams: Vec<Vec<u8>>,
        /// Whether a session began with it.
        established: bool,
    },
    /// A decrypted IP packet, cut to its IP length.
    Packet(Vec<u8>),
    /// The server's keepalive.
    Keepalive,
    /// Refused by the core, with why, which names no byte of it.
    Refused(&'static str),
}

/// What the timers asked for.
#[derive(Debug, PartialEq, Eq)]
pub enum Timers {
    /// Nothing.
    Idle,
    /// A datagram for the server: a handshake retry, a rekey, a keepalive.
    Send(Vec<u8>),
    /// The handshake gave up, or every key expired: no session, and the packets that waited for it, as
    /// many as this says, are lost. The next packet begins anew.
    Expired(usize),
}

/// A `WireGuard` protocol core for one peer.
pub trait Core: Send {
    /// Encrypts an app's IP packet, or queues it behind a handshake.
    fn send(&mut self, packet: &[u8]) -> Sent;
    /// Takes a datagram the server sent from `from`.
    fn receive(&mut self, from: SocketAddr, datagram: &[u8]) -> Received;
    /// Runs the timers, as of now.
    fn timers(&mut self) -> Timers;
    /// A keepalive at once, as after a network change, or a handshake when there is no session.
    fn keepalive(&mut self) -> Option<Vec<u8>>;
    /// A new handshake at once, as after a network change once the session is old.
    fn handshake(&mut self) -> Option<Vec<u8>>;
    /// How long ago the current session's handshake completed, if there is one.
    fn session_age(&self) -> Option<Duration>;
    /// Whether the configuration asks for keepalives, which keep the timers running while idle.
    fn keeps_alive(&self) -> bool;
}

/// Mullvad's `GotaTun` 0.10.3 (ADR 0035), with `aws-lc-rs`.
pub struct GotaTun {
    tunn: Tunn,
    limiter: Arc<RateLimiter>,
    mtu: MtuWatcher,
    /// Packets that wait in the queue now, as far as this can tell: `GotaTun` drops past [`QUEUE`] without
    /// a word, and empties the queue when the handshake gives up.
    queued: usize,
}

impl GotaTun {
    /// A core for `config`'s peer. The keys are copied into `GotaTun`'s own types, which zero the private
    /// key on drop; the preshared key `GotaTun` holds as bytes, unprotected in memory, as Assured's audit
    /// noted (3.5) and wireguard-go does too.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        // The copies made on the way into GotaTun's types are written over once handed in (the engine's
        // review, nit 16).
        let mut bytes = *config.private_key.bytes();
        let private = StaticSecret::from(bytes);
        bytes.zeroize();
        let public = PublicKey::from(&private);
        let limiter = Arc::new(RateLimiter::new(&public, HANDSHAKES_PER_SECOND));
        let mut preshared = config.peer.preshared_key.as_ref().map(|key| *key.bytes());
        let tunn = Tunn::new(
            private,
            PublicKey::from(config.peer.public_key),
            preshared,
            config.peer.persistent_keepalive,
            IndexTable::from_os_rng(),
            Arc::clone(&limiter),
        );
        if let Some(key) = preshared.as_mut() {
            key.zeroize();
        }
        Self {
            tunn,
            limiter,
            mtu: MtuWatcher::new(config.mtu()),
            queued: 0,
        }
    }

    /// The datagrams that waited for the handshake, now that it completed.
    fn drain(&mut self) -> Vec<Vec<u8>> {
        self.queued = 0;
        self.tunn
            .get_queued_packets(&mut self.mtu)
            .map(bytes_of)
            .collect()
    }
}

fn bytes_of(datagram: WgKind) -> Vec<u8> {
    Packet::<[u8]>::from(datagram).as_ref().to_vec()
}

/// A decrypted packet cut to the length its IP header gives: `GotaTun` pads data to 16 bytes.
fn ip_length(packet: &[u8]) -> Option<usize> {
    let length = match packet.first()? >> 4 {
        4 => usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?])),
        6 => 40 + usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?])),
        _ => return None,
    };
    (length <= packet.len()).then_some(length)
}

fn reason(error: &WireGuardError) -> &'static str {
    match error {
        WireGuardError::InvalidMac => "mac",
        WireGuardError::InvalidAeadTag => "aead",
        WireGuardError::DuplicateCounter | WireGuardError::InvalidCounter => "counter",
        WireGuardError::NoCurrentSession => "no-session",
        WireGuardError::WrongIndex => "index",
        WireGuardError::WrongTai64nTimestamp | WireGuardError::InvalidTai64nTimestamp => {
            "timestamp"
        }
        WireGuardError::ConnectionExpired => "expired",
        WireGuardError::InvalidPacket
        | WireGuardError::IncorrectPacketLength
        | WireGuardError::WrongPacketType => "malformed",
        _ => "other",
    }
}

impl Core for GotaTun {
    fn send(&mut self, packet: &[u8]) -> Sent {
        let packet = Packet::from_bytes(BytesMut::from(packet));
        match self
            .tunn
            .handle_outgoing_packet(packet, Some(&mut self.mtu))
        {
            Some(WgKind::Data(data)) => Sent::Data(Packet::<[u8]>::from(data).as_ref().to_vec()),
            Some(other) => {
                self.queued = (self.queued + 1).min(QUEUE);
                Sent::Handshake(bytes_of(other))
            }
            None if self.queued < QUEUE => {
                self.queued += 1;
                Sent::Queued
            }
            None => Sent::Dropped,
        }
    }

    fn receive(&mut self, from: SocketAddr, datagram: &[u8]) -> Received {
        let packet = Packet::from_bytes(BytesMut::from(datagram));
        let kind = match self.limiter.verify_packet(from, packet) {
            Ok(kind) => kind,
            Err(TunnResult::WriteToNetwork(reply)) => {
                return Received::Send {
                    datagrams: vec![bytes_of(reply)],
                    established: false,
                };
            }
            Err(TunnResult::Err(error)) => return Received::Refused(reason(&error)),
            Err(_) => return Received::Refused("other"),
        };
        let response = matches!(kind, WgKind::HandshakeResp(_));
        match self.tunn.handle_incoming_packet(kind) {
            TunnResult::WriteToNetwork(datagram) => {
                let mut datagrams = vec![bytes_of(datagram)];
                if response {
                    datagrams.extend(self.drain());
                }
                Received::Send {
                    datagrams,
                    established: response,
                }
            }
            TunnResult::WriteToTunnel(packet) if packet.is_empty() => Received::Keepalive,
            TunnResult::WriteToTunnel(packet) => match ip_length(&packet) {
                Some(length) => Received::Packet(packet[..length].to_vec()),
                None => Received::Refused("malformed"),
            },
            TunnResult::Done => Received::Send {
                datagrams: Vec::new(),
                established: false,
            },
            TunnResult::Err(error) => Received::Refused(reason(&error)),
        }
    }

    fn timers(&mut self) -> Timers {
        match self.tunn.update_timers() {
            Ok(Some(datagram)) => Timers::Send(bytes_of(datagram)),
            Ok(None) => Timers::Idle,
            Err(_) => Timers::Expired(std::mem::take(&mut self.queued)),
        }
    }

    fn keepalive(&mut self) -> Option<Vec<u8>> {
        match self.send(&[]) {
            Sent::Data(datagram) | Sent::Handshake(datagram) => Some(datagram),
            Sent::Queued | Sent::Dropped => None,
        }
    }

    fn handshake(&mut self) -> Option<Vec<u8>> {
        self.tunn
            .format_handshake_initiation(true)
            .map(|init| Packet::<[u8]>::from(init).as_ref().to_vec())
    }

    fn session_age(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }

    fn keeps_alive(&self) -> bool {
        self.tunn.persistent_keepalive().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_PRIVATE: [u8; 32] = [0x41; 32];
    const PHONE_PRIVATE: [u8; 32] = [0x42; 32];

    fn base64(bytes: &[u8; 32]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            }
        }
        out.push('=');
        out
    }

    /// The phone's configuration for a server whose private key is `server`, and the server's own, its
    /// peer the phone: two cores that talk to each other.
    fn pair(psk: Option<[u8; 32]>) -> (GotaTun, GotaTun) {
        let public = |private: [u8; 32]| PublicKey::from(&StaticSecret::from(private)).to_bytes();
        let config = |own: [u8; 32], peer: [u8; 32]| {
            let psk = psk.map_or_else(String::new, |k| format!("PresharedKey = {}\n", base64(&k)));
            let text = format!(
                "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.2/32\nDNS = 10.77.0.1\n[Peer]\n\
                 PublicKey = {}\n{psk}AllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n",
                base64(&own),
                base64(&public(peer)),
            );
            Config::parse(text.as_bytes())
        };
        let (Ok(phone), Ok(server)) = (
            config(PHONE_PRIVATE, SERVER_PRIVATE),
            config(SERVER_PRIVATE, PHONE_PRIVATE),
        ) else {
            unreachable!("a test configuration was refused")
        };
        (GotaTun::new(&phone), GotaTun::new(&server))
    }

    const FROM: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        51_820,
    );

    /// A minimal IPv4 packet of `length` bytes.
    fn ip(length: u16) -> Vec<u8> {
        let mut packet = vec![0u8; usize::from(length)];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[9] = 17;
        packet
    }

    /// The first packet waits for the handshake and leaves once it completes; data then passes both
    /// ways, cut to its IP length, and a datagram the server's core did not make is refused.
    #[test]
    fn a_packet_waits_for_the_handshake_and_passes_once_it_completes() {
        for psk in [None, Some([0x55; 32])] {
            let (mut phone, mut server) = pair(psk);
            let Sent::Handshake(init) = phone.send(&ip(60)) else {
                unreachable!("no handshake")
            };
            assert_eq!(phone.send(&ip(61)), Sent::Queued);
            let Received::Send { datagrams, .. } = server.receive(FROM, &init) else {
                unreachable!("no response")
            };
            let Received::Send {
                datagrams,
                established,
            } = phone.receive(FROM, &datagrams[0])
            else {
                unreachable!("not established")
            };
            assert!(established);
            // The keepalive that confirms the handshake, then the two queued packets.
            assert_eq!(datagrams.len(), 3);
            assert_eq!(server.receive(FROM, &datagrams[0]), Received::Keepalive);
            assert_eq!(
                server.receive(FROM, &datagrams[1]),
                Received::Packet(ip(60))
            );
            assert_eq!(
                server.receive(FROM, &datagrams[2]),
                Received::Packet(ip(61))
            );
            let Sent::Data(back) = server.send(&ip(77)) else {
                unreachable!("no session on the server")
            };
            assert_eq!(phone.receive(FROM, &back), Received::Packet(ip(77)));
            assert!(phone.session_age().is_some());
            assert_eq!(phone.receive(FROM, &back), Received::Refused("counter"));
            let Sent::Data(mut forged) = server.send(&ip(78)) else {
                unreachable!("no session on the server")
            };
            let last = forged.len() - 1;
            forged[last] ^= 1;
            assert_eq!(phone.receive(FROM, &forged), Received::Refused("aead"));
            assert_eq!(
                phone.receive(FROM, &[1, 2, 3]),
                Received::Refused("malformed")
            );
        }
    }

    /// A preshared key the server does not share ends in no session.
    #[test]
    fn a_wrong_preshared_key_makes_no_session() {
        let (mut phone, _) = pair(Some([0x55; 32]));
        let (_, mut server) = pair(Some([0x66; 32]));
        let Sent::Handshake(init) = phone.send(&ip(60)) else {
            unreachable!("no handshake")
        };
        if let Received::Send { datagrams, .. } = server.receive(FROM, &init) {
            for datagram in datagrams {
                assert!(matches!(
                    phone.receive(FROM, &datagram),
                    Received::Refused(_)
                ));
            }
        }
        assert!(phone.session_age().is_none());
    }

    /// Past the queue's 256 packets, `GotaTun` drops without a word, and the core says so.
    #[test]
    fn the_queue_past_its_bound_drops_and_says_so() {
        let (mut phone, _) = pair(None);
        assert!(matches!(phone.send(&ip(60)), Sent::Handshake(_)));
        for _ in 1..QUEUE {
            assert_eq!(phone.send(&ip(60)), Sent::Queued);
        }
        assert_eq!(phone.send(&ip(60)), Sent::Dropped);
    }

    /// Data is padded to 16 bytes inside the encryption, within the MTU: a 61-byte packet takes as much
    /// room on the wire as a 64-byte one.
    #[test]
    fn data_is_padded_to_sixteen_bytes() {
        let (mut phone, mut server) = pair(None);
        let Sent::Handshake(init) = phone.send(&ip(60)) else {
            unreachable!("no handshake")
        };
        let Received::Send { datagrams, .. } = server.receive(FROM, &init) else {
            unreachable!("no response")
        };
        let _ = phone.receive(FROM, &datagrams[0]);
        let (Sent::Data(a), Sent::Data(b)) = (phone.send(&ip(61)), phone.send(&ip(64))) else {
            unreachable!("no session")
        };
        assert_eq!(a.len(), b.len());
        // 16 bytes of header, 64 of padded data, 16 of tag.
        assert_eq!(a.len(), 16 + 64 + 16);
    }

    #[test]
    fn a_decrypted_packet_is_cut_to_its_ip_length() {
        let mut padded = ip(61);
        padded.extend_from_slice(&[0; 3]);
        assert_eq!(ip_length(&padded), Some(61));
        let mut six = vec![0u8; 48];
        six[0] = 0x60;
        six[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(ip_length(&six), Some(48));
        six[5] = 9;
        assert_eq!(ip_length(&six), None, "longer than what came");
        assert_eq!(ip_length(&[0x50; 20]), None);
        assert_eq!(ip_length(&[]), None);
    }
}
