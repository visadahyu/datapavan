//! The server name in the first packets of a QUIC connection (W3): the `ClientHello` an app sends in
//! its Initial packets (RFC 9000 17.2.2). Anyone can remove their protection, since the keys come from
//! the connection ID sent in the clear and a salt the RFC publishes (RFC 9001 5.2, and RFC 9369 3.3 for
//! QUIC version 2). The `ClientHello` is then read as from TLS ([`tls::from_handshake`]).
//!
//! A `ClientHello` may span several Initial packets and datagrams: Chrome's does, with its
//! post-quantum key share, and Chrome also cuts it into CRYPTO frames sent out of order, mixed with
//! PING and PADDING, so that middleboxes cannot depend on one layout. The frames are put together by
//! their offsets, up to [`tls::MAX_HELLO`] bytes, over at most [`MAX_DATAGRAMS`] datagrams.
//!
//! A packet's protection is removed only when its AES-GCM tag checks, by `RustCrypto`'s `aes-gcm` (ADR 0044,
//! unit 9b, fix round 1): anyone can compute these keys, so a valid tag proves nothing about who sent the
//! packet, but a packet damaged on its way, or bytes that only look like an Initial, then name no flow,
//! where before a reader that removed the protection without the tag took whatever frames happened to
//! parse. The keys come from `RustCrypto`'s `hkdf` over SHA-256 (fix round 2). Both are checked against the
//! RFCs' sample packets below, and what a receiver must discard is discarded here too: a packet whose
//! reserved bits are set (RFC 9000 17.2), or that holds no frame (12.4).
//!
//! The same keys tell a stand-in's answers apart (ADR 0044, unit 9b): [`asked`] reads the connection IDs
//! of the Initial packets an app sends, and [`Answer`] whether what comes back is the server's answer to
//! one of them. An Initial or a Retry is matched through the keys or the integrity key and its tag, which
//! does not keep out a sender who saw the app's packet and can compute them as well, but rules out a
//! chance match (2^-128). A Retry carries no trace of the connection ID it answers but its integrity tag
//! (RFC 9001 5.8), so only the tag can tell which of an app's Initial packets it is for. A packet matched
//! by the app's source connection ID alone is matched at the chance its length gives (2^-32 for 4 bytes),
//! and a Version Negotiation packet, which has no tag, by the two IDs it echoes.
//!
//! The bytes come from any app and any sender, so nothing here may panic or read outside a slice: the
//! fuzz target `quic` fuzzes the hello's reader; `identifiers` what an app's datagram asks and whether
//! anything carries it, which random bytes reach only as far as the tags; and `quic_answers` the
//! server's answers built for the connection IDs it chooses, with a byte changed or not, past the tags.

use std::cell::{Cell, OnceCell};

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::tls::{self, ServerName};

/// The most datagrams of one flow read for a `ClientHello` before giving up.
pub const MAX_DATAGRAMS: usize = 8;
/// The most separate pieces of a `ClientHello` kept while waiting for the gaps between them.
const MAX_PIECES: usize = 64;
/// The longest connection ID of QUIC versions 1 and 2.
const MAX_CID: usize = 20;
/// AES-GCM's tag, at the end of every protected packet.
const TAG: usize = 16;
/// The header protection's sample, taken 4 bytes after the packet number starts.
const SAMPLE: usize = 16;

/// The client's label for its Initial secret.
const CLIENT: &[u8] = b"client in";
/// The server's label for its Initial secret.
const SERVER: &[u8] = b"server in";
/// The shortest connection ID that tells a connection's packets apart by itself: a shorter one would be
/// matched by a stranger's packet by a chance of one in 256 for one byte. A client that chooses one of 4
/// bytes or more, as most do but Chromium's, which chooses none, is matched by it at a chance of 2^-32.
const TOLD_APART: usize = 4;
/// The largest datagram read as a server's Initial or Retry (ADR 0044, unit 9b, fix round 1): a larger one
/// costs no keys and no AEAD, and carries nothing. QUIC never lets IP fragment its datagrams (RFC 9000 14),
/// and before it has probed a larger path a server sends what fits the path it has validated, from 1,200
/// bytes up (RFC 9000 14.1, 14.3); the paths of the internet, and Watch's tunnel (ADR 0044, decision 5 as
/// amended), carry 1,500 bytes at most, so no server's first answer that reaches the app is larger. A Retry's
/// token goes back in the client's next Initial, which must fit the same path.
pub const LARGEST_ANSWER: usize = 1_500;
/// At most this many Initial or Retry packets are opened, keys derived where they are not kept, to tell one
/// datagram that came back (ADR 0044, unit 9b, fix round 1), whatever stand-ins it is checked for: one for
/// each destination ID an app's Initial asked, the latest first. A client that sends no source ID can tell
/// its connections to one server apart only by their addresses, so each of its stand-ins has one connection
/// at a time, and a destination ID it changes only for a Retry, a Version Negotiation or a new attempt.
pub const MOST_OPENED: usize = 16;
/// At most this many long-header packets are read in one datagram of an app's: a client's first flight
/// coalesces an Initial with a 0-RTT or Handshake packet at most (RFC 9000 12.2), and a datagram of more is
/// read no further, so that one datagram of tiny packets costs no more than a few.
const MOST_PACKETS: usize = 16;

/// The QUIC versions whose Initial packets can be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Version {
    /// RFC 9000.
    V1,
    /// RFC 9369.
    V2,
}

impl Version {
    fn from_wire(version: u32) -> Option<Self> {
        match version {
            1 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    fn wire(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 0x6b33_43cf,
        }
    }

    /// Its place among the versions, where something is kept for each.
    fn index(self) -> usize {
        match self {
            Self::V1 => 0,
            Self::V2 => 1,
        }
    }

    fn salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            Self::V2 => &[
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
        }
    }

    /// The labels of the packet key, the IV and the header protection key.
    fn labels(self) -> [&'static [u8]; 3] {
        match self {
            Self::V1 => [b"quic key", b"quic iv", b"quic hp"],
            Self::V2 => [b"quicv2 key", b"quicv2 iv", b"quicv2 hp"],
        }
    }

    /// The long header's two type bits of an Initial packet, and whether the type is Retry, which has
    /// no length field.
    fn kinds(self) -> (u8, u8) {
        match self {
            Self::V1 => (0, 3),
            Self::V2 => (1, 0),
        }
    }

    /// The fixed key and nonce of a Retry packet's integrity tag (RFC 9001 5.8, RFC 9369 3.3.3).
    fn retry(self) -> ([u8; 16], [u8; 12]) {
        match self {
            Self::V1 => (
                [
                    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3,
                    0x68, 0xc8, 0x4e,
                ],
                [
                    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
                ],
            ),
            Self::V2 => (
                [
                    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad,
                    0x7c, 0xcc, 0x92,
                ],
                [
                    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
                ],
            ),
        }
    }
}

/// TLS 1.3's `HKDF-Expand-Label` with an empty context (RFC 8446 7.1), filling `out`, by `RustCrypto`'s
/// `hkdf` (ADR 0044, unit 9b, fix round 2): the output's length, the label's, "tls13 " and the label, then
/// the empty context, as HKDF-Expand's info (RFC 5869 2.3). `None` only for an output longer than HKDF
/// gives, which no caller asks.
fn expand_label(secret: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    let length = u16::try_from(out.len()).ok()?.to_be_bytes();
    let label_length = [u8::try_from(b"tls13 ".len() + label.len()).ok()?];
    secret
        .expand_multi_info(&[&length, &label_length, b"tls13 ", label, &[0]], out)
        .ok()
}

/// The keys of one side's Initial packets.
#[derive(Clone)]
struct Keys {
    aead: Aes128Gcm,
    iv: [u8; 12],
    hp: Aes128,
}

impl Keys {
    /// The Initial keys for the connection ID `cid`, on the side named by `label` (RFC 9001 5.2): the
    /// initial secret extracted from `cid` with the version's salt, the side's secret expanded from it,
    /// and the keys from that. `None` never comes for the lengths used here; it stands for HKDF's own
    /// refusals, which only other lengths meet.
    fn initial(version: Version, cid: &[u8], label: &[u8]) -> Option<Self> {
        let initial = Hkdf::<Sha256>::new(Some(version.salt()), cid);
        let mut secret = [0u8; 32];
        expand_label(&initial, label, &mut secret)?;
        let secret = Hkdf::<Sha256>::from_prk(&secret).ok()?;
        let [key, iv, hp] = version.labels();
        let (mut key16, mut iv12, mut hp16) = ([0u8; 16], [0u8; 12], [0u8; 16]);
        expand_label(&secret, key, &mut key16)?;
        expand_label(&secret, iv, &mut iv12)?;
        expand_label(&secret, hp, &mut hp16)?;
        Some(Self {
            aead: Aes128Gcm::from(aes(&key16)),
            iv: iv12,
            hp: aes(&hp16),
        })
    }

    /// The header protection mask for a sample of the protected payload.
    fn mask(&self, sample: &[u8]) -> [u8; 16] {
        let mut block = aes::Block::default();
        block.copy_from_slice(sample);
        self.hp.encrypt_block(&mut block);
        block.into()
    }

    /// The nonce of packet `pn`: the IV with the packet number in its last eight bytes (RFC 9001 5.3).
    fn nonce(&self, pn: u64) -> Nonce<Aes128Gcm> {
        let mut nonce = self.iv;
        for (byte, pn_byte) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
            *byte ^= pn_byte;
        }
        Nonce::<Aes128Gcm>::from(nonce)
    }
}

fn aes(key: &[u8; 16]) -> Aes128 {
    Aes128::new(&(*key).into())
}

/// The cipher of a Retry packet's integrity tag for `version` (RFC 9001 5.8, RFC 9369 3.3.3), with its
/// nonce.
fn retry_aead(version: Version) -> (Aes128Gcm, Nonce<Aes128Gcm>) {
    let (key, nonce) = version.retry();
    (Aes128Gcm::from(aes(&key)), Nonce::<Aes128Gcm>::from(nonce))
}

/// Reads a variable-length integer (RFC 9000 16) at `at`, moving `at` past it.
fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let first = *bytes.get(*at)?;
    let length = 1usize << (first >> 6);
    let rest = bytes.get(at.checked_add(1)?..at.checked_add(length)?)?;
    let value = rest
        .iter()
        .fold(u64::from(first & 0x3f), |v, &b| v << 8 | u64::from(b));
    *at += length;
    Some(value)
}

fn varint_usize(bytes: &[u8], at: &mut usize) -> Option<usize> {
    usize::try_from(varint(bytes, at)?).ok()
}

/// One long-header packet's place in a datagram.
struct LongPacket {
    version: Version,
    initial: bool,
    /// An Initial's token's length: a server's is always empty (RFC 9000 17.2.2).
    token: usize,
    dcid_start: usize,
    dcid_end: usize,
    scid_start: usize,
    scid_end: usize,
    pn_offset: usize,
    end: usize,
}

/// Reads the long header of the packet at `at`, or `None` where no long-header packet of version 1 or
/// 2 with a length starts.
fn long_packet(datagram: &[u8], at: usize) -> Option<LongPacket> {
    let first = *datagram.get(at)?;
    // The fixed bit is not checked: RFC 9287 lets an endpoint clear it.
    if first & 0x80 == 0 {
        return None;
    }
    let wire = datagram.get(at + 1..at + 5)?;
    let version = Version::from_wire(u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]))?;
    let kind = (first >> 4) & 3;
    let (initial_kind, retry_kind) = version.kinds();
    if kind == retry_kind {
        return None;
    }
    let mut pos = at + 5;
    let dcid_length = usize::from(*datagram.get(pos)?);
    if dcid_length > MAX_CID {
        return None;
    }
    let dcid_start = pos + 1;
    let dcid_end = dcid_start + dcid_length;
    pos = dcid_end;
    let scid_length = usize::from(*datagram.get(pos)?);
    if scid_length > MAX_CID {
        return None;
    }
    let scid_start = pos + 1;
    let scid_end = scid_start + scid_length;
    pos = scid_end;
    let initial = kind == initial_kind;
    let mut token = 0;
    if initial {
        token = varint_usize(datagram, &mut pos)?;
        pos = pos.checked_add(token)?;
    }
    let length = varint_usize(datagram, &mut pos)?;
    let end = pos.checked_add(length)?;
    if end > datagram.len() {
        return None;
    }
    Some(LongPacket {
        version,
        initial,
        token,
        dcid_start,
        dcid_end,
        scid_start,
        scid_end,
        pn_offset: pos,
        end,
    })
}

/// Removes the protection of the packet that starts at `start`, returning its payload without the
/// tag: the header's protection, then the payload's, with AES-GCM, the header with its protection
/// removed as the associated data (RFC 9001 5.3, 5.4). `None` for a packet too short for it, whose tag
/// does not check, or whose reserved bits are set, which a receiver must refuse (RFC 9000 17.2). Those
/// bits are read before the tag: RFC 9001 9.5 asks an endpoint to read them after, so that their timing
/// tells nothing of its keys, but Initial keys are no secret, and a packet with them set is refused
/// either way, so a wrong key costs no AEAD three times in four.
fn open(
    keys: &Keys,
    datagram: &[u8],
    start: usize,
    pn_offset: usize,
    end: usize,
) -> Option<Vec<u8>> {
    if pn_offset + 4 + SAMPLE > end {
        return None;
    }
    let mask = keys.mask(datagram.get(pn_offset + 4..pn_offset + 4 + SAMPLE)?);
    let first = datagram.get(start)? ^ (mask[0] & 0x0f);
    if first & 0x0c != 0 {
        return None;
    }
    let pn_length = usize::from(first & 3) + 1;
    let mut header = datagram.get(start..pn_offset + pn_length)?.to_vec();
    header[0] = first;
    let numbered = pn_offset - start;
    for (byte, m) in header[numbered..].iter_mut().zip(&mask[1..]) {
        *byte ^= m;
    }
    let pn = header[numbered..]
        .iter()
        .fold(0u64, |pn, &b| pn << 8 | u64::from(b));
    let payload_end = end.checked_sub(TAG)?;
    let mut payload = datagram.get(pn_offset + pn_length..payload_end)?.to_vec();
    let tag = Tag::<Aes128Gcm>::try_from(datagram.get(payload_end..end)?).ok()?;
    keys.aead
        .decrypt_inout_detached(
            &keys.nonce(pn),
            &header,
            payload.as_mut_slice().into(),
            &tag,
        )
        .ok()?;
    Some(payload)
}

/// Walks the frames of an Initial packet's payload whose protection is removed, handing each CRYPTO frame's
/// data to `crypto` at its offset: PADDING, PING, ACK with or without ECN counts, CRYPTO and
/// `CONNECTION_CLOSE`, the frames an Initial may carry (RFC 9000 17.2.2, 12.4). `None` for any other, for one
/// cut short, for a payload of no frame at all, which a receiver must refuse (12.4), or when `crypto`
/// refuses.
fn walk_frames(payload: &[u8], mut crypto: impl FnMut(usize, &[u8]) -> Option<()>) -> Option<()> {
    if payload.is_empty() {
        return None;
    }
    let mut at = 0;
    while at < payload.len() {
        match varint(payload, &mut at)? {
            // PADDING and PING.
            0x00 | 0x01 => {}
            // ACK, and ACK with ECN counts.
            kind @ (0x02 | 0x03) => {
                for _ in 0..2 {
                    varint(payload, &mut at)?;
                }
                let ranges = varint(payload, &mut at)?;
                varint(payload, &mut at)?;
                for _ in 0..ranges {
                    varint(payload, &mut at)?;
                    varint(payload, &mut at)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        varint(payload, &mut at)?;
                    }
                }
            }
            0x06 => {
                let offset = varint_usize(payload, &mut at)?;
                let length = varint_usize(payload, &mut at)?;
                let data = payload.get(at..at.checked_add(length)?)?;
                at += length;
                crypto(offset, data)?;
            }
            // CONNECTION_CLOSE: an error code, a frame type and a reason.
            0x1c => {
                varint(payload, &mut at)?;
                varint(payload, &mut at)?;
                let reason = varint_usize(payload, &mut at)?;
                at = at.checked_add(reason).filter(|&end| end <= payload.len())?;
            }
            _ => return None,
        }
    }
    Some(())
}

/// Whether `payload`, an Initial packet's with its protection removed, holds only the frames an Initial
/// may carry, each whole, to its end; nothing of them is kept, so the check costs a pass over the bytes.
fn frames_parse(payload: &[u8]) -> bool {
    walk_frames(payload, |_, _| Some(())).is_some()
}

/// A connection ID, of at most 20 bytes in QUIC versions 1 and 2, kept in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Cid {
    length: u8,
    bytes: [u8; MAX_CID],
}

impl Cid {
    fn new(id: &[u8]) -> Option<Self> {
        let mut bytes = [0u8; MAX_CID];
        bytes.get_mut(..id.len())?.copy_from_slice(id);
        Some(Self {
            length: u8::try_from(id.len()).ok()?,
            bytes,
        })
    }

    fn get(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    /// Whether it tells a connection's packets apart by itself ([`TOLD_APART`]).
    fn tells(&self) -> bool {
        usize::from(self.length) >= TOLD_APART
    }
}

/// What an app's QUIC Initial packet asked, for the server's answers to carry (RFC 9000 17.2, RFC 9001
/// 5): its version, its destination connection ID, from which the server's Initial keys derive, and its
/// source connection ID, which every packet of the server's carries as its destination.
#[derive(Clone)]
pub struct Ids {
    version: Version,
    destination: Cid,
    source: Cid,
    /// The server's Initial keys of `destination`, for each version a server may answer an Initial in
    /// (RFC 9368), derived the first time an answer needs them and kept with the identifier from then on
    /// (ADR 0044, unit 9b, fix round 1).
    server: [OnceCell<Box<Keys>>; 2],
}

impl PartialEq for Ids {
    fn eq(&self, other: &Self) -> bool {
        (self.version, self.destination, self.source)
            == (other.version, other.destination, other.source)
    }
}

impl Eq for Ids {}

impl std::hash::Hash for Ids {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.version, self.destination, self.source).hash(state);
    }
}

impl std::fmt::Debug for Ids {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ids")
            .field("version", &self.version)
            .field("destination", &self.destination.get())
            .field("source", &self.source.get())
            .finish_non_exhaustive()
    }
}

impl Ids {
    fn new(version: Version, destination: Cid, source: Cid) -> Self {
        Self {
            version,
            destination,
            source,
            server: [OnceCell::new(), OnceCell::new()],
        }
    }

    /// The server's Initial keys of the app's destination ID in `version`.
    fn server_keys(&self, version: Version) -> Option<&Keys> {
        let kept = &self.server[version.index()];
        if let Some(keys) = kept.get() {
            return Some(keys);
        }
        let keys = Keys::initial(version, self.destination.get(), SERVER)?;
        Some(kept.get_or_init(|| Box::new(keys)))
    }

    /// For how many versions the server's keys were derived and are kept.
    #[cfg(test)]
    fn keys_kept(&self) -> usize {
        self.server
            .iter()
            .filter(|kept| kept.get().is_some())
            .count()
    }
}

/// The connection IDs of each long-header packet in `datagram`, an app's, when the datagram holds a
/// QUIC Initial packet of version 1 or 2 whose protection, removed with the client's keys, gives a tag
/// that checks and frames that parse to its end; none otherwise, nor when one of its Initial packets
/// fails so. Each distinct pair once: an Initial sent again carries the same. Packets after one to
/// another destination ID than the first are ignored, as RFC 9000 12.2 has a receiver do, and so are
/// those after the first [`MOST_PACKETS`]; the client's keys are derived once for the datagram, all of
/// whose packets share their destination ID.
#[must_use]
pub fn asked(datagram: &[u8]) -> Vec<Ids> {
    let mut asked: Vec<Ids> = Vec::new();
    let mut keys: [Option<Keys>; 2] = [None, None];
    let mut first: Option<Cid> = None;
    let mut initial = false;
    let mut at = 0;
    for _ in 0..MOST_PACKETS {
        let Some(packet) = long_packet(datagram, at) else {
            break;
        };
        let ids = |start: usize, end: usize| Cid::new(datagram.get(start..end)?);
        let (Some(destination), Some(source)) = (
            ids(packet.dcid_start, packet.dcid_end),
            ids(packet.scid_start, packet.scid_end),
        ) else {
            return Vec::new();
        };
        if *first.get_or_insert(destination) != destination {
            break;
        }
        if packet.initial {
            let slot = &mut keys[packet.version.index()];
            if slot.is_none() {
                *slot = Keys::initial(packet.version, destination.get(), CLIENT);
            }
            match slot
                .as_ref()
                .and_then(|keys| open(keys, datagram, at, packet.pn_offset, packet.end))
            {
                Some(payload) if frames_parse(&payload) => initial = true,
                _ => return Vec::new(),
            }
        }
        let ids = Ids::new(packet.version, destination, source);
        if !asked.contains(&ids) {
            asked.push(ids);
        }
        at = packet.end;
    }
    if initial { asked } else { Vec::new() }
}

/// The long header of a packet a server sent: its version as on the wire, its first byte, and where its
/// connection IDs and what follows them are.
struct ServerHeader<'a> {
    first: u8,
    version: u32,
    destination: &'a [u8],
    source: &'a [u8],
    /// What follows the source connection ID.
    rest: usize,
}

impl<'a> ServerHeader<'a> {
    fn read(packet: &'a [u8]) -> Option<Self> {
        let first = *packet.first()?;
        let wire = packet.get(1..5)?;
        let version = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]);
        let length = usize::from(*packet.get(5)?);
        if length > MAX_CID {
            return None;
        }
        let destination = packet.get(6..6 + length)?;
        let at = 6 + length;
        let source_length = usize::from(*packet.get(at)?);
        if source_length > MAX_CID {
            return None;
        }
        let source = packet.get(at + 1..at + 1 + source_length)?;
        Some(Self {
            first,
            version,
            destination,
            source,
            rest: at + 1 + source_length,
        })
    }
}

/// A datagram that came back from where an app sent QUIC, read for whether it answers what the app
/// asked ([`Answer::carries`]). Whatever stand-ins it is checked for, it opens at most [`MOST_OPENED`]
/// packets, and none when it is larger than [`LARGEST_ANSWER`] (ADR 0044, unit 9b, fix round 1). Most
/// checks cost no packet opened ([`Answer::tells`]); the engine spends the opens the others need
/// ([`Answer::opens_for`]) so that each stand-in checked has its newest identifier tried (fix round 2).
pub struct Answer<'a> {
    datagram: &'a [u8],
    /// Its first packet's long header; `None` for a short header.
    long: Option<ServerHeader<'a>>,
    /// How many more packets it may open.
    opens: Cell<usize>,
}

impl<'a> Answer<'a> {
    /// `None` where no QUIC packet with a long header that reads, or a short header, starts it.
    #[must_use]
    pub fn read(datagram: &'a [u8]) -> Option<Self> {
        let first = *datagram.first()?;
        let long = if first & 0x80 == 0 {
            None
        } else {
            Some(ServerHeader::read(datagram)?)
        };
        Some(Self {
            datagram,
            long,
            opens: Cell::new(MOST_OPENED),
        })
    }

    /// How many packets it opened so far, each with keys and its AEAD tag.
    #[must_use]
    pub fn opened(&self) -> usize {
        MOST_OPENED - self.opens.get()
    }

    /// How many more packets it may open.
    #[must_use]
    pub fn opens_left(&self) -> usize {
        self.opens.get()
    }

    /// Whether it is the server's answer to `asked` (RFC 9000 17.2, RFC 9001 5, RFC 9369, RFC 9368): what
    /// [`Answer::tells`] says, or where only an opened packet can tell, what [`Answer::opens_for`] does.
    #[must_use]
    pub fn carries(&self, asked: &Ids) -> bool {
        self.tells(asked).unwrap_or_else(|| self.opens_for(asked))
    }

    /// Whether it is the server's answer to `asked`, where that costs no packet opened; `None` where only
    /// an opened packet can tell ([`Answer::opens_for`]).
    ///
    /// It is when it is a Version Negotiation packet whose source connection ID is the app's destination
    /// and whose destination is the app's source, listing versions in whole words, the app's own not among
    /// them (RFC 9000 6.2, 17.2.1; RFC 9368 2.1); or any packet whose destination ID is the app's source
    /// ID, where that is 4 bytes or more, long enough to tell. It is not when it is a packet the client
    /// would discard whatever its keys: a Retry in another version than the app's (RFC 9369 4.1), or
    /// without a token (RFC 9000 17.2.5.2); a server's Initial with a token (17.2.2). A client that sends
    /// no source ID, as Chromium's, so Cronet's, does, is told only by its Initial keys: by the server's
    /// Version Negotiation, or by its Retry or first Initial packet opened.
    #[must_use]
    pub fn tells(&self, asked: &Ids) -> Option<bool> {
        let source = asked.source.get();
        let Some(header) = &self.long else {
            return Some(
                asked.source.tells() && self.datagram.get(1..1 + source.len()) == Some(source),
            );
        };
        if header.version == 0 {
            return Some(self.negotiates(header, asked));
        }
        let Some(version) = Version::from_wire(header.version) else {
            return Some(false);
        };
        if header.destination != source {
            return Some(false);
        }
        let kind = (header.first >> 4) & 3;
        let (initial, retry) = version.kinds();
        if kind == retry && (version != asked.version || self.datagram.len() <= header.rest + TAG) {
            return Some(false);
        }
        if kind == initial && long_packet(self.datagram, 0).is_none_or(|packet| packet.token != 0) {
            return Some(false);
        }
        if asked.source.tells() {
            return Some(true);
        }
        if (kind != initial && kind != retry) || self.datagram.len() > LARGEST_ANSWER {
            return Some(false);
        }
        None
    }

    /// Opens its first packet, if it may open one more, to tell whether it is the server's answer to
    /// `asked` where [`Answer::tells`] could not, and only then: a Retry whose integrity tag checks with the app's
    /// destination ID, or an Initial whose protection, removed with the server's keys of the app's
    /// destination ID, gives a tag that checks and frames that parse to its end. The Initial may be of
    /// either version this module reads, whichever the app's was: a server that negotiates a compatible
    /// version answers a version 1 Initial in version 2, with version 2's keys of the same destination ID
    /// (RFC 9368 2.3, RFC 9369 4). `false` once it may open no more.
    #[must_use]
    pub fn opens_for(&self, asked: &Ids) -> bool {
        let Some(header) = &self.long else {
            return false;
        };
        let Some(version) = Version::from_wire(header.version) else {
            return false;
        };
        let Some(left) = self.opens.get().checked_sub(1) else {
            return false;
        };
        self.opens.set(left);
        if (header.first >> 4) & 3 == version.kinds().1 {
            self.retry_for(asked, version)
        } else {
            self.initial_for(asked, version)
        }
    }

    /// Whether it is a Version Negotiation packet for `asked`: the IDs crossed, versions listed in whole
    /// 4-byte words, and the app's own version not among them, as a client would have it (RFC 9000 6.2).
    fn negotiates(&self, header: &ServerHeader, asked: &Ids) -> bool {
        let Some(versions) = self.datagram.get(header.rest..) else {
            return false;
        };
        let own = asked.version.wire().to_be_bytes();
        header.source == asked.destination.get()
            && header.destination == asked.source.get()
            && !versions.is_empty()
            && versions.len().is_multiple_of(4)
            && !versions.as_chunks::<4>().0.contains(&own)
    }

    /// Whether it is a Retry of `version` whose integrity tag checks with the app's destination ID (RFC
    /// 9001 5.8). [`Answer::tells`] has refused one without a token, or in another version than the app's.
    fn retry_for(&self, asked: &Ids, version: Version) -> bool {
        let Some(end) = self.datagram.len().checked_sub(TAG) else {
            return false;
        };
        let original = asked.destination.get();
        let mut pseudo = Vec::with_capacity(1 + original.len() + end);
        pseudo.push(asked.destination.length);
        pseudo.extend_from_slice(original);
        pseudo.extend_from_slice(&self.datagram[..end]);
        let (aead, nonce) = retry_aead(version);
        Tag::<Aes128Gcm>::try_from(&self.datagram[end..]).is_ok_and(|tag| {
            aead.decrypt_inout_detached(&nonce, &pseudo, (&mut [0u8; 0][..]).into(), &tag)
                .is_ok()
        })
    }

    /// Whether it is an Initial of `version` that the server's keys of the app's destination ID open, to
    /// frames that parse. [`Answer::tells`] has refused one with a token.
    fn initial_for(&self, asked: &Ids, version: Version) -> bool {
        let Some(packet) = long_packet(self.datagram, 0) else {
            return false;
        };
        packet.initial
            && packet.version == version
            && asked.server_keys(version).is_some_and(|keys| {
                open(keys, self.datagram, 0, packet.pn_offset, packet.end)
                    .is_some_and(|payload| frames_parse(&payload))
            })
    }
}

/// An Initial packet of `version`, protected with `keys` as its sender protects one, whose header names
/// `destination` and `source`, numbered `pn` in `pn_length` bytes (1 to 4), with the `reserved` bits of
/// its first byte (none, but in tests of what a receiver refuses) and `token`, holding `payload` as it is.
fn seal(
    version: Version,
    keys: &Keys,
    (destination, source): (&[u8], &[u8]),
    (pn, pn_length): (u32, usize),
    (reserved, token): (u8, &[u8]),
    payload: &[u8],
) -> Option<Vec<u8>> {
    let numbered = pn.to_be_bytes();
    let pn_bytes = numbered.get(4usize.checked_sub(pn_length)?..)?;
    let first = 0xc0
        | (version.kinds().0 << 4)
        | (reserved & 0x0c)
        | u8::try_from(pn_length.checked_sub(1)?).ok()?;
    let mut header = vec![first];
    header.extend_from_slice(&version.wire().to_be_bytes());
    for id in [destination, source] {
        header.push(
            u8::try_from(id.len())
                .ok()
                .filter(|&n| usize::from(n) <= MAX_CID)?,
        );
        header.extend_from_slice(id);
    }
    header.push(u8::try_from(token.len()).ok().filter(|&n| n < 0x40)?);
    header.extend_from_slice(token);
    let length = u16::try_from(pn_length + payload.len() + TAG)
        .ok()
        .filter(|&n| n <= 0x3fff)?;
    header.extend_from_slice(&(length | 0x4000).to_be_bytes());
    let pn_offset = header.len();
    header.extend_from_slice(pn_bytes);
    let mut ciphertext = payload.to_vec();
    let tag = keys
        .aead
        .encrypt_inout_detached(
            &keys.nonce(u64::from(pn)),
            &header,
            ciphertext.as_mut_slice().into(),
        )
        .ok()?;
    let mut packet = header;
    packet.extend_from_slice(&ciphertext);
    packet.extend_from_slice(&tag);
    let mask = keys.mask(packet.get(pn_offset + 4..pn_offset + 4 + SAMPLE)?);
    packet[0] ^= mask[0] & 0x0f;
    for (byte, m) in packet[pn_offset..pn_offset + pn_length]
        .iter_mut()
        .zip(&mask[1..])
    {
        *byte ^= m;
    }
    Some(packet)
}

/// A server's Initial packet of `version` (1 or `0x6b3343cf`), numbered 0 in two bytes, to the client's
/// source ID `destination`, from `source`, protected with the server's keys of the client's destination
/// ID `original`, holding `frames`. Only for tests, the engine's among them, which build a server's
/// answers with it; [`asked`] and [`Answer`] are checked against RFC 9369's sample, which this seals
/// byte for byte.
#[doc(hidden)]
#[must_use]
pub fn server_initial(
    version: u32,
    original: &[u8],
    (destination, source): (&[u8], &[u8]),
    (pn, frames): (u32, &[u8]),
) -> Option<Vec<u8>> {
    let version = Version::from_wire(version)?;
    let keys = Keys::initial(version, original, SERVER)?;
    seal(
        version,
        &keys,
        (destination, source),
        (pn, 2),
        (0, &[]),
        frames,
    )
}

/// A client's Initial packet of `version` to `destination`, from `source`, numbered `pn` in four
/// bytes, holding `frames` padded with PADDING to `size` bytes, as a client sends its first. Only for
/// tests, as [`server_initial`].
#[doc(hidden)]
#[must_use]
pub fn client_initial(
    version: u32,
    (destination, source): (&[u8], &[u8]),
    (pn, frames): (u32, &[u8]),
    size: usize,
) -> Option<Vec<u8>> {
    let version = Version::from_wire(version)?;
    let keys = Keys::initial(version, destination, CLIENT)?;
    let header = 1 + 4 + 1 + destination.len() + 1 + source.len() + 1 + 2 + 4;
    let mut payload = frames.to_vec();
    payload.resize(size.saturating_sub(header + TAG).max(frames.len()), 0);
    seal(
        version,
        &keys,
        (destination, source),
        (pn, 4),
        (0, &[]),
        &payload,
    )
}

/// A Retry packet of `version` to the client's source ID `destination`, from `source`, with `token`,
/// for the client's destination ID `original`: its integrity tag computed as a server does (RFC 9001
/// 5.8), and its unused bits set, so that it seals the Retry samples of RFC 9001 A.4 and RFC 9369 A.4
/// byte for byte. Only for tests, as [`server_initial`].
#[doc(hidden)]
#[must_use]
pub fn retry(
    version: u32,
    original: &[u8],
    (destination, source): (&[u8], &[u8]),
    token: &[u8],
) -> Option<Vec<u8>> {
    let version = Version::from_wire(version)?;
    // The four unused bits set, as the RFCs' samples have them.
    let mut packet = vec![0xc0 | (version.kinds().1 << 4) | 0x0f];
    packet.extend_from_slice(&version.wire().to_be_bytes());
    for id in [destination, source] {
        packet.push(
            u8::try_from(id.len())
                .ok()
                .filter(|&n| usize::from(n) <= MAX_CID)?,
        );
        packet.extend_from_slice(id);
    }
    packet.extend_from_slice(token);
    let mut pseudo = vec![u8::try_from(original.len()).ok()?];
    pseudo.extend_from_slice(original);
    pseudo.extend_from_slice(&packet);
    let (aead, nonce) = retry_aead(version);
    let tag = aead
        .encrypt_inout_detached(&nonce, &pseudo, (&mut [0u8; 0][..]).into())
        .ok()?;
    packet.extend_from_slice(&tag);
    Some(packet)
}

/// The start of a QUIC connection, read for its `ClientHello` one datagram at a time.
#[derive(Default)]
pub struct Initial {
    /// The last Initial keys, with the version and connection ID they are for.
    keys: Option<(Version, Cid, Keys)>,
    /// The CRYPTO stream as far as it came, gaps filled with zeros.
    crypto: Vec<u8>,
    /// The parts of `crypto` that arrived, sorted and not touching.
    pieces: Vec<(usize, usize)>,
    datagrams: usize,
    quic: bool,
}

impl Initial {
    /// Nothing read yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether an Initial packet with frames that make sense was read: the flow is QUIC.
    #[must_use]
    pub fn is_quic(&self) -> bool {
        self.quic
    }

    /// Reads one datagram the app sent. [`ServerName::None`] means that this flow will not give a
    /// name: its first datagram holds no Initial packet that can be read, an Initial's frames make no
    /// sense, or [`MAX_DATAGRAMS`] passed without a whole `ClientHello`. Its packets are read as [`asked`]
    /// reads them (ADR 0044, unit 9b, fix round 2): those after one to another destination ID than the
    /// first are ignored (RFC 9000 12.2), and so are those after the first [`MOST_PACKETS`].
    pub fn push(&mut self, datagram: &[u8]) -> ServerName {
        self.datagrams += 1;
        let mut read = false;
        let mut at = 0;
        let mut first: Option<Cid> = None;
        for _ in 0..MOST_PACKETS {
            let Some(packet) = long_packet(datagram, at) else {
                break;
            };
            let Some(cid) = datagram
                .get(packet.dcid_start..packet.dcid_end)
                .and_then(Cid::new)
            else {
                break;
            };
            if *first.get_or_insert(cid) != cid {
                break;
            }
            if packet.initial {
                let payload = self
                    .keys_for(packet.version, cid)
                    .and_then(|keys| open(keys, datagram, at, packet.pn_offset, packet.end));
                let Some(payload) = payload else {
                    return ServerName::None;
                };
                if self.frames(&payload).is_none() {
                    return ServerName::None;
                }
                self.quic = true;
                read = true;
            }
            at = packet.end;
        }
        if !read && !self.quic {
            return ServerName::None;
        }
        self.name()
    }

    /// The client's Initial keys of `cid` in `version`: the last ones, when they are for the same, else
    /// derived and kept.
    fn keys_for(&mut self, version: Version, cid: Cid) -> Option<&Keys> {
        if !matches!(&self.keys, Some((kept, known, _)) if *kept == version && *known == cid) {
            self.keys = Some((version, cid, Keys::initial(version, cid.get(), CLIENT)?));
        }
        self.keys.as_ref().map(|(_, _, keys)| keys)
    }

    /// Reads the frames of one Initial packet whose protection is already removed, as [`Self::push`]
    /// reads a datagram. Only for fuzzing: random bytes almost never decrypt to frames, so the fuzzer
    /// reaches the frames and their reassembly through this.
    #[doc(hidden)]
    pub fn push_frames(&mut self, payload: &[u8]) -> ServerName {
        self.datagrams += 1;
        if self.frames(payload).is_none() {
            return ServerName::None;
        }
        self.quic = true;
        self.name()
    }

    /// The `ClientHello` as far as its first bytes came without a gap.
    fn name(&self) -> ServerName {
        let whole = match self.pieces.first() {
            Some(&(0, end)) => end,
            _ => 0,
        };
        match tls::from_handshake(&self.crypto[..whole]) {
            ServerName::Incomplete if self.datagrams >= MAX_DATAGRAMS => ServerName::None,
            name => name,
        }
    }

    /// Reads the frames of an Initial packet's payload, keeping its CRYPTO data. `None` for a frame
    /// that may not be in an Initial packet, or one cut short.
    fn frames(&mut self, payload: &[u8]) -> Option<()> {
        walk_frames(payload, |offset, data| self.keep(offset, data))
    }

    /// Keeps a CRYPTO frame's data at its offset. Data past [`tls::MAX_HELLO`] is dropped; `None` when
    /// the stream comes in more pieces than [`MAX_PIECES`].
    fn keep(&mut self, offset: usize, data: &[u8]) -> Option<()> {
        let end = offset.saturating_add(data.len()).min(tls::MAX_HELLO);
        if offset >= end {
            return Some(());
        }
        if self.crypto.len() < end {
            self.crypto.resize(end, 0);
        }
        self.crypto[offset..end].copy_from_slice(&data[..end - offset]);
        // Insert in order, then join with the neighbours it touches.
        let index = self.pieces.partition_point(|&(start, _)| start < offset);
        self.pieces.insert(index, (offset, end));
        let mut i = index.saturating_sub(1);
        while i + 1 < self.pieces.len() {
            let (start, stop) = self.pieces[i];
            let (next_start, next_stop) = self.pieces[i + 1];
            if next_start <= stop {
                self.pieces[i] = (start, stop.max(next_stop));
                self.pieces.remove(i + 1);
            } else if i > index {
                break;
            } else {
                i += 1;
            }
        }
        (self.pieces.len() <= MAX_PIECES).then_some(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An empty connection ID.
    const EMPTY: Cid = Cid {
        length: 0,
        bytes: [0; MAX_CID],
    };
    use crate::tls::Hello;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => b - b'A' + 10,
            })
            .collect();
        digits
            .chunks(2)
            .map(|pair| pair[0] << 4 | pair[1])
            .collect()
    }

    /// The client's original connection ID in the samples of RFC 9001 A and RFC 9369 A.
    const CID: &str = "8394c8f03e515708";

    /// RFC 5869 A.1, through `RustCrypto`'s `hkdf` as the keys derive: the extract step's PRK, and the
    /// expand step's 42 bytes (fix round 2, review D: the HKDF that was written here gave way).
    #[test]
    fn hkdf_matches_rfc_5869() {
        let (prk, hkdf) =
            Hkdf::<Sha256>::extract(Some(&hex("000102030405060708090a0b0c")), &[0x0b; 22]);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let mut okm = [0u8; 42];
        assert!(hkdf.expand(&hex("f0f1f2f3f4f5f6f7f8f9"), &mut okm).is_ok());
        assert_eq!(
            okm.to_vec(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    /// The secret of `out`'s length that `HKDF-Expand-Label` gives from `secret` under `label`.
    fn expanded<const N: usize>(secret: &Hkdf<Sha256>, label: &[u8]) -> Vec<u8> {
        let mut out = [0u8; N];
        assert_eq!(expand_label(secret, label, &mut out), Some(()));
        out.to_vec()
    }

    /// RFC 9001 A.1's secrets and keys, step by step, and A.2 and A.3's header protection masks.
    #[test]
    fn keys_match_rfc_9001() {
        let (initial, extracted) = Hkdf::<Sha256>::extract(Some(Version::V1.salt()), &hex(CID));
        assert_eq!(
            initial.to_vec(),
            hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        );
        let client = expanded::<32>(&extracted, CLIENT);
        assert_eq!(
            client,
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        let Ok(client) = Hkdf::<Sha256>::from_prk(&client) else {
            unreachable!("a whole SHA-256 output")
        };
        assert_eq!(
            expanded::<16>(&client, b"quic key"),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            expanded::<12>(&client, b"quic iv"),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            expanded::<16>(&client, b"quic hp"),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
        // RFC 9001 A.2 and A.3: the header protection masks of the client's and the server's samples.
        let (Some(keys), Some(server)) = (
            Keys::initial(Version::V1, &hex(CID), CLIENT),
            Keys::initial(Version::V1, &hex(CID), SERVER),
        ) else {
            unreachable!("Initial keys")
        };
        assert_eq!(
            keys.mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"))[..5].to_vec(),
            hex("437b9aec36")
        );
        assert_eq!(
            server.mask(&hex("2cd0991cd25b0aac406a5816b6394100"))[..5].to_vec(),
            hex("2ec0d8356a")
        );
    }

    #[test]
    fn opens_the_server_initial_of_rfc_9369() {
        // RFC 9369 A.3: QUIC version 2's server Initial, protected with the keys of the client's
        // original connection ID (the vector as rustls's tests carry it).
        let protected = hex(
            "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698baeea26b91eb761d9b89237bbf87
             2630179153582300 35f7fd3945d88965cf17f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e4275
             75076980 75b2c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca84bed8521e2e140",
        );
        let plain = hex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a04
             5a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32b
             b9da1a002b00020304",
        );
        let (Some(keys), Some(packet)) = (
            Keys::initial(Version::V2, &hex(CID), SERVER),
            long_packet(&protected, 0),
        ) else {
            unreachable!("keys and a long header")
        };
        assert_eq!(packet.version, Version::V2);
        assert!(packet.initial);
        assert_eq!(packet.end, protected.len());
        let opened = open(&keys, &protected, 0, packet.pn_offset, packet.end);
        assert_eq!(opened, Some(plain));
    }

    /// Protects an Initial packet of `version` from the client to `cid` holding `frames`, padded with
    /// PADDING to `size` bytes, as the sender would.
    pub(crate) fn initial_packet(
        version: u32,
        cid: &[u8],
        pn: u32,
        frames: &[u8],
        size: usize,
    ) -> Vec<u8> {
        client_initial(version, (cid, &[]), (pn, frames), size).unwrap_or_default()
    }

    /// GCM's test cases 1 to 4, from the paper that defined it ("The Galois/Counter Mode of Operation",
    /// appendix B), as `Keys` seals and opens through `RustCrypto`'s `aes-gcm`: no data and one block of
    /// zeros under the all-zero key and nonce, then four whole blocks, and 60 bytes with 20 of associated
    /// data, under another key and nonce.
    #[test]
    fn aes_gcm_matches_gcm_test_cases_1_to_4() {
        let keys = |key: &str, iv: &str| {
            let mut key16 = aes::cipher::Key::<Aes128>::default();
            key16.copy_from_slice(&hex(key));
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&hex(iv));
            Keys {
                aead: Aes128Gcm::from(Aes128::new(&key16)),
                iv: nonce,
                hp: Aes128::new(&key16),
            }
        };
        let zero = keys(
            "00000000000000000000000000000000",
            "000000000000000000000000",
        );
        let other = keys(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
        );
        let plain = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let cipher = hex(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        for (keys, aad, plain, cipher, tag) in [
            (
                &zero,
                &[][..],
                &[][..],
                &[][..],
                "58e2fccefa7e3061367f1d57a4e7455a",
            ),
            (
                &zero,
                &[][..],
                &[0u8; 16][..],
                &hex("0388dace60b6a392f328c2b971b2fe78")[..],
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
            (
                &other,
                &[][..],
                &plain[..],
                &cipher[..],
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            (
                &other,
                &aad[..],
                &plain[..60],
                &cipher[..60],
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
        ] {
            let mut sealed = plain.to_vec();
            let made =
                keys.aead
                    .encrypt_inout_detached(&keys.nonce(0), aad, sealed.as_mut_slice().into());
            assert_eq!(made.map(|tag| tag.to_vec()).ok(), Some(hex(tag)));
            assert_eq!(sealed, cipher);
            let Ok(tag) = Tag::<Aes128Gcm>::try_from(&hex(tag)[..]) else {
                unreachable!("a tag of 16 bytes")
            };
            assert!(
                keys.aead
                    .decrypt_inout_detached(&keys.nonce(0), aad, sealed.as_mut_slice().into(), &tag)
                    .is_ok()
            );
            assert_eq!(sealed, plain);
        }
    }

    const CLIENT_HELLO_FRAME: &str = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c000004130113
         02010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018001000070005
         04616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce1
         5d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c0002400100
         3900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806
         048000ffff";
    const SERVER_FRAMES: &str = "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200
         130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00
         020304";
    const CLIENT_INITIAL_9001: &str = "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c
         0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
         8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89
         eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
         4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e
         610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
         059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7
         961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
         be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7
         fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
         f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf
         330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
         14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff2
         8f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
         c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd
         d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
         fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a07
         1b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
         162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499d
         bd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
         8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723
         c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
         760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905dd
         f3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
         7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934";
    const SERVER_INITIAL_9001: &str = "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a1c69797554780bb3
         8cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84
         022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc42158407dd074ee";
    const RETRY_9001: &str =
        "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba";
    const CLIENT_INITIAL_9369: &str = "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485dd04de806071bf03dceebfa162e75d6c
         96058bdbfb127cdfcbf903388e99ad049f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d
         250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a12834e3f249a78d395e0d18f4d766004
         f1a2674802a747eaa901c3f10cda5500cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68
         18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff3312ae50b187c1433c0f028edcc4c2838b
         6a9bfc226ca4b4530e7a4ccee1bfa2a3d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd
         6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520bcfb7966fc49b393f0061d974a2706df
         8c4a9449f11d7f3d2dcbb90c6b877045636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f
         ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c1216ccce2d0193f958bb3850a833f7ae43
         2b65bc5a53975c155aa4bcb4f7b2c4e54df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4
         fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b8017c25ca9052ca1079d8b78aebd4787
         6d330a30f6a8c6d61dd1ab5589329de714d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9
         9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91abfe43960977c87471cf9ad4074d30e1
         0d6a7f03c63bd5d4317f68ff325ba3bd80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db
         848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18d703dd84045a274ae8bfa73379661388
         d6991fe39b0d93debb41700b41f90a15c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc
         7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61f6b5b984d4d3dfa033c1bb7e4f0037fe
         bf406d91c0dccf32acf423cfa1e7071010d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b
         3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e06ebfde206bfb0fcbc0edc4ebec30966
         1bdd908d532eb0c6adc38b7ca7331dce8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1
         34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1e86215c2d54e6670e07383a27bbffb5a
         ddf47d66aa85a0c6f9f32e59d85a44dd5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3
         8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89d5974ee12e5cf7d5da4d6a31123041f3
         3e61407e76cffcdcfd7e19ba58cf4b536f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19
         9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96ba18b2faa745b6fe189cf772a9f84cbfc";
    const SERVER_INITIAL_9369: &str = "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698baeea26b91eb761d9b89237bbf872630
         17915358230035f7fd3945d88965cf17f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e42757507698075b2
         c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca84bed8521e2e140";
    const RETRY_9369: &str =
        "cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6";

    /// The sample packets of RFC 9001 A.2 to A.4 and RFC 9369 A.2 to A.4, versions 1 and 2: the client's
    /// Initial, the server's and the Retry sealed byte for byte from the RFCs' frames and token, its
    /// unused bits as the samples set them (fix round 2, review D), what the client's Initial
    /// asks read from it, the server's Initial and Retry each carrying it, and the client's hello naming
    /// `example.com`.
    #[test]
    fn the_rfcs_sample_packets_are_sealed_read_and_told() {
        let original = hex(CID);
        let source = hex("f067a5502a4262b5");
        for (version, client, server, retry) in [
            (1, CLIENT_INITIAL_9001, SERVER_INITIAL_9001, RETRY_9001),
            (
                0x6b33_43cf,
                CLIENT_INITIAL_9369,
                SERVER_INITIAL_9369,
                RETRY_9369,
            ),
        ] {
            let (client, server, retry) = (hex(client), hex(server), hex(retry));
            assert_eq!(
                client_initial(
                    version,
                    (&original, &[]),
                    (2, &hex(CLIENT_HELLO_FRAME)),
                    1200
                ),
                Some(client.clone()),
                "A.2 of version {version:#x}"
            );
            assert_eq!(
                server_initial(version, &original, (&[], &source), (1, &hex(SERVER_FRAMES))),
                Some(server.clone()),
                "A.3 of version {version:#x}"
            );
            assert_eq!(
                super::retry(version, &original, (&[], &source), b"token"),
                Some(retry.clone()),
                "A.4 of version {version:#x}"
            );
            let asked = asked(&client);
            assert_eq!(asked.len(), 1);
            assert_eq!(asked[0].destination.get(), original.as_slice());
            for answer in [&server, &retry] {
                assert!(
                    Answer::read(answer).is_some_and(|read| read.carries(&asked[0])),
                    "A.3 or A.4 of version {version:#x}"
                );
            }
            let mut initial = Initial::new();
            assert_eq!(initial.push(&client), found("example.com", false));
            assert!(initial.is_quic());
        }
    }

    /// The hello's reader removes a packet's protection only when its tag checks: a packet whose last
    /// byte changed names no flow and is no QUIC (unit 9b, fix round 1).
    #[test]
    fn the_hello_is_read_only_from_a_packet_whose_tag_checks() {
        let hello = tls::tests::handshake("watch.test", false);
        let packet = initial_packet(1, &hex(CID), 0, &crypto(0, &hello), 1200);
        let mut damaged = packet.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        let mut initial = Initial::new();
        assert_eq!(initial.push(&damaged), ServerName::None);
        assert!(!initial.is_quic());
        assert_eq!(Initial::new().push(&packet), found("watch.test", false));
    }

    /// RFC 9369 A.3's server Initial, sealed byte for byte from its frames, and opened with its tag
    /// checked: it answers the client's original destination ID, and nothing else.
    #[test]
    fn seals_and_tells_the_server_initial_of_rfc_9369() {
        let protected = hex(
            "dc6b3343cf0008f067a5502a4262b5004075d92faaf16f05d8a4398c47089698baeea26b91eb761d9b89237bbf87
             2630179153582300 35f7fd3945d88965cf17f9af6e16886c61bfc703106fbaf3cb4cfa52382dd16a393e4275
             75076980 75b2c984c707f0a0812d8cd5a6881eaf21ceda98f4bd23f6fe1a3e2c43edd9ce7ca84bed8521e2e140",
        );
        let plain = hex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a04
             5a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32b
             b9da1a002b00020304",
        );
        let source = hex("f067a5502a4262b5");
        assert_eq!(
            server_initial(0x6b33_43cf, &hex(CID), (&[], &source), (1, &plain)),
            Some(protected.clone())
        );
        let ids = |version, destination: &[u8]| {
            Ids::new(version, Cid::new(destination).unwrap_or(EMPTY), EMPTY)
        };
        let read = Answer::read(&protected);
        assert!(
            read.as_ref()
                .is_some_and(|a| a.carries(&ids(Version::V2, &hex(CID))))
        );
        assert!(
            !read
                .as_ref()
                .is_some_and(|a| a.carries(&ids(Version::V2, &hex("8394c8f03e515709"))))
        );
        // Version 2's answer to the same destination ID asked in version 1 carries it too: a server that
        // negotiates a compatible version answers so (RFC 9368).
        assert!(
            read.as_ref()
                .is_some_and(|a| a.carries(&ids(Version::V1, &hex(CID))))
        );
        let mut damaged = protected;
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert!(!Answer::read(&damaged).is_some_and(|a| a.carries(&ids(Version::V2, &hex(CID)))));
    }

    /// The Retry packets of RFC 9001 A.4 and RFC 9369 A.4 carry their client's original destination ID
    /// only in their integrity tag, which tells them; one built here, too.
    #[test]
    fn the_retries_of_rfc_9001_and_9369_are_told_by_their_tag() {
        let empty = Cid {
            length: 0,
            bytes: [0; MAX_CID],
        };
        let ids = |version, destination: &[u8]| {
            Ids::new(version, Cid::new(destination).unwrap_or(empty), empty)
        };
        for (version, retry) in [
            (
                Version::V1,
                hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"),
            ),
            (
                Version::V2,
                hex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6"),
            ),
        ] {
            let read = Answer::read(&retry);
            assert!(
                read.as_ref()
                    .is_some_and(|a| a.carries(&ids(version, &hex(CID))))
            );
            assert!(
                !read
                    .as_ref()
                    .is_some_and(|a| a.carries(&ids(version, &hex("0011223344556677"))))
            );
            let mut damaged = retry.clone();
            damaged[10] ^= 1;
            assert!(!Answer::read(&damaged).is_some_and(|a| a.carries(&ids(version, &hex(CID)))));
            let built = super::retry(
                version.wire(),
                &hex(CID),
                (&[], &hex("f067a5502a4262b5")),
                b"token",
            );
            assert!(
                built
                    .as_deref()
                    .and_then(Answer::read)
                    .is_some_and(|a| a.carries(&ids(version, &hex(CID))))
            );
        }
    }

    /// What an app's Initial packet asks: its version and both connection IDs, once however often it
    /// is sent, and nothing from a packet whose tag or frames fail, or from what is no Initial.
    #[test]
    fn asked_reads_the_ids_of_an_apps_initial_and_nothing_else() {
        let hello = tls::tests::handshake("watch.test", false);
        let (destination, source) = (hex("0011223344556677"), hex("a1a2a3a4"));
        for version in [1, 0x6b33_43cf] {
            let Some(packet) = client_initial(
                version,
                (&destination, &source),
                (0, &crypto(0, &hello)),
                1200,
            ) else {
                unreachable!("an Initial packet")
            };
            assert_eq!(packet.len(), 1200);
            let mut twice = packet.clone();
            twice.extend_from_slice(&packet);
            let asked = asked(&twice);
            assert_eq!(asked.len(), 1);
            assert_eq!(asked[0].destination.get(), destination.as_slice());
            assert_eq!(asked[0].source.get(), source.as_slice());
            assert_eq!(asked[0].version.wire(), version);
            let mut damaged = packet.clone();
            damaged[1199] ^= 1;
            assert_eq!(super::asked(&damaged).len(), 0, "a tag that fails");
        }
        // The right tag over frames an Initial may not carry (a STREAM frame).
        let Some(stream) = client_initial(1, (&destination, &[]), (0, &[0x08, 0, 1, 0]), 1200)
        else {
            unreachable!("an Initial packet")
        };
        assert_eq!(asked(&stream).len(), 0);
        assert_eq!(asked(b"\x12\x34 an ordinary datagram").len(), 0);
        assert_eq!(asked(&[0x40; 1200]).len(), 0);
    }

    /// An app's Initial of version 1 with no source ID, as Chromium's sends.
    fn v1_asked(destination: &[u8]) -> (Vec<u8>, Ids) {
        let Some(packet) = client_initial(1, (destination, &[]), (0, &[0x01]), 1200) else {
            unreachable!("an Initial packet")
        };
        let mut asked = asked(&packet);
        assert_eq!(asked.len(), 1);
        (packet, asked.remove(0))
    }

    /// A server that negotiates a compatible version (RFC 9368) answers a version 1 Initial in version 2,
    /// with version 2's keys of the app's destination ID: its Initial carries what the app asked (unit 9b,
    /// fix round 1; reviews A and B, probe 2). Its Retry may not: a server sends one only in the original
    /// version, and the client ignores one in another (RFC 9369 4.1; fix round 2, review D).
    #[test]
    fn a_server_may_answer_in_a_compatible_version() {
        for (asked, other) in [(1, 0x6b33_43cf), (0x6b33_43cf, 1)] {
            let Some(client) = client_initial(asked, (&[0x42; 8], &[]), (0, &[0x01]), 1200) else {
                unreachable!("an Initial packet")
            };
            let ids = &super::asked(&client)[0];
            let carries = |answer: Option<Vec<u8>>| {
                Answer::read(&answer.unwrap_or_default()).is_some_and(|read| read.carries(ids))
            };
            let initial = |version, original: &[u8]| {
                server_initial(
                    version,
                    original,
                    (&[], &[0x5a; 8]),
                    (0, &[0x02, 0, 0, 0, 0]),
                )
            };
            assert!(carries(initial(other, &[0x42; 8])), "{other:#x}'s Initial");
            assert!(carries(initial(asked, &[0x42; 8])), "{asked:#x}'s Initial");
            assert!(!carries(initial(other, &[0x43; 8])));
            let retry = |version| retry(version, &[0x42; 8], (&[], &[0x5a; 8]), b"token");
            assert!(carries(retry(asked)), "{asked:#x}'s Retry");
            assert!(!carries(retry(other)), "{other:#x}'s Retry for {asked:#x}");
        }
    }

    /// An app's datagram asks only what an Initial in it carries: one of a 0-RTT packet alone asks nothing,
    /// one whose second Initial fails its tag asks nothing, packets after one to another destination ID are
    /// ignored (RFC 9000 12.2), and so are those after the first [`MOST_PACKETS`], however many it holds
    /// (unit 9b, fix round 1; review B).
    #[test]
    fn an_apps_datagram_is_read_as_rfc_9000_12_2_has_it_and_no_further() {
        let (packet, _) = v1_asked(&[0x11; 8]);
        // A 0-RTT packet of version 1 (type 1), its length to the end.
        let mut zero_rtt = vec![0xd0, 0, 0, 0, 1, 8];
        zero_rtt.extend_from_slice(&[0x11; 8]);
        zero_rtt.extend_from_slice(&[0, 0x40, 40]);
        zero_rtt.extend_from_slice(&[0x55; 40]);
        assert_eq!(asked(&zero_rtt).len(), 0);
        let mut damaged = packet.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert_eq!(asked(&[packet.clone(), damaged.clone()].concat()).len(), 0);
        let (other, _) = v1_asked(&[0x22; 8]);
        let read = asked(&[packet.clone(), other].concat());
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].destination.get(), &[0x11; 8]);
        // Small Initials, then one whose tag fails, past the packets read.
        let tiny = |pn| client_initial(1, (&[0x11; 8], &[]), (pn, &[0x01]), 0).unwrap_or_default();
        let mut many: Vec<u8> = (0..u32::try_from(MOST_PACKETS).unwrap_or(0))
            .flat_map(tiny)
            .collect();
        let mut late = tiny(99);
        let last = late.len() - 1;
        late[last] ^= 1;
        many.extend_from_slice(&late);
        assert_eq!(
            asked(&many).len(),
            1,
            "a packet after the first {MOST_PACKETS} was read"
        );
    }

    /// Whatever it is checked against, an answer opens at most [`MOST_OPENED`] packets, and none when it
    /// is larger than [`LARGEST_ANSWER`]; the server's keys an identifier was checked with are kept with it
    /// (unit 9b, fix round 1; review A, probe 3, and review B).
    #[test]
    fn an_answer_opens_few_packets_and_keeps_the_keys_it_derived() {
        let ids: Vec<Ids> = (0..64u8).map(|n| v1_asked(&[n; 8]).1).collect();
        for (size, opened) in [(1_400, MOST_OPENED), (LARGEST_ANSWER + 1, 0), (64_000, 0)] {
            let mut forged = vec![0xc0, 0, 0, 0, 1, 0, 0, 0];
            let length = u32::try_from(size - forged.len() - 4).unwrap_or(0) | 0x8000_0000;
            forged.extend_from_slice(&length.to_be_bytes());
            forged.resize(size, 0x5c);
            let Some(read) = Answer::read(&forged) else {
                unreachable!("a long header")
            };
            assert!(!ids.iter().any(|ids| read.carries(ids)));
            assert_eq!(read.opened(), opened, "{size} bytes");
        }
        let kept: usize = ids.iter().map(Ids::keys_kept).sum();
        assert_eq!(kept, MOST_OPENED, "keys kept for the identifiers checked");
        let (_, alone) = v1_asked(&[0x77; 8]);
        let answer = server_initial(1, &[0x77; 8], (&[], &[0x5a; 8]), (0, &[0x02, 0, 0, 0, 0]))
            .unwrap_or_default();
        for _ in 0..2 {
            assert!(Answer::read(&answer).is_some_and(|read| read.carries(&alone)));
        }
        assert_eq!(alone.keys_kept(), 1);
    }

    /// A server Initial whose tag checks with the right keys still answers nothing when its frames are
    /// none an Initial may carry (a STREAM frame): review B's surviving mutant.
    #[test]
    fn an_initial_of_frames_an_initial_may_not_carry_answers_nothing() {
        let (_, ids) = v1_asked(&[0x31; 8]);
        let stream = server_initial(1, &[0x31; 8], (&[], &[0x5a; 8]), (0, &[0x08, 0, 1, 0x61]));
        assert!(!Answer::read(&stream.unwrap_or_default()).is_some_and(|read| read.carries(&ids)));
    }

    /// What a client discards carries nothing, though the right keys protect it or the right integrity
    /// key tags it (fix round 2, review D): a server's Initial with its reserved bits set (RFC 9000 17.2),
    /// with no frame (12.4), or with a token (17.2.2); a Retry without a token (17.2.5.2).
    #[test]
    fn what_a_client_discards_answers_nothing() {
        let (_, ids) = v1_asked(&[0x42; 8]);
        let carries = |packet: Option<Vec<u8>>| {
            Answer::read(&packet.unwrap_or_default()).is_some_and(|read| read.carries(&ids))
        };
        let Some(keys) = Keys::initial(Version::V1, &[0x42; 8], SERVER) else {
            unreachable!("Initial keys")
        };
        let sealed = |(reserved, token): (u8, &[u8]), frames: &[u8]| {
            seal(
                Version::V1,
                &keys,
                (&[], &[0x5a; 8]),
                (0, 4),
                (reserved, token),
                frames,
            )
        };
        assert!(carries(sealed((0, &[]), &[0x01])), "as a server sends it");
        assert!(!carries(sealed((0x04, &[]), &[0x01])), "a reserved bit");
        assert!(!carries(sealed((0x08, &[]), &[0x01])), "the other");
        assert!(!carries(sealed((0, &[]), &[])), "no frame");
        assert!(!carries(sealed((0, b"token"), &[0x01])), "a token");
        let retry = |token: &[u8]| retry(1, &[0x42; 8], (&[], &[0x5a; 8]), token);
        assert!(carries(retry(b"t")));
        assert!(!carries(retry(b"")), "a Retry without a token");
    }

    /// The frames of a server's Initial are read to their end as RFC 9000 19 has them (fix round 2, review
    /// D's surviving mutants): an ACK with ECN counts reads its three counts, which are no frames of their
    /// own, and a `CONNECTION_CLOSE` whose reason runs past the payload is cut short.
    #[test]
    fn a_servers_frames_are_read_to_their_end() {
        let (_, ids) = v1_asked(&[0x42; 8]);
        let carries = |frames: &[u8]| {
            let answer = server_initial(1, &[0x42; 8], (&[], &[0x5a; 8]), (0, frames));
            Answer::read(&answer.unwrap_or_default()).is_some_and(|read| read.carries(&ids))
        };
        // ACK_ECN: largest 0, delay 0, no more ranges, first range 0, then counts 5, 7 and 9, which read
        // as frames would be RESET_STREAM and others an Initial may not carry; then a PING.
        assert!(carries(&[0x03, 0, 0, 0, 0, 5, 7, 9, 0x01]));
        assert!(
            !carries(&[0x02, 0, 0, 0, 0, 5, 7, 9, 0x01]),
            "an ACK without counts"
        );
        assert!(carries(&[0x1c, 0, 0, 3, b'a', b'b', b'c']));
        assert!(
            !carries(&[0x1c, 0, 0, 10, b'a', b'b', b'c']),
            "a reason past the end"
        );
    }

    /// An answer of [`LARGEST_ANSWER`] bytes is opened and told, one byte more is not (fix round 2, review
    /// D's surviving mutant).
    #[test]
    fn the_largest_answer_is_read_and_no_larger() {
        let (_, ids) = v1_asked(&[0x42; 8]);
        // 20 bytes of header and 16 of tag around an ACK and PADDING.
        for (size, told) in [(LARGEST_ANSWER, true), (LARGEST_ANSWER + 1, false)] {
            let mut frames = vec![0x02, 0, 0, 0, 0];
            frames.resize(size - 36, 0);
            let answer =
                server_initial(1, &[0x42; 8], (&[], &[0x5a; 8]), (0, &frames)).unwrap_or_default();
            assert_eq!(answer.len(), size);
            assert_eq!(
                Answer::read(&answer).is_some_and(|read| read.carries(&ids)),
                told,
                "{size} bytes"
            );
        }
    }

    /// A datagram whose Initials are of both versions, to one destination ID, asks each, each opened with
    /// its version's keys; the hello's reader, likewise, derives a version's keys for a destination ID it
    /// read in the other version (fix round 2, review D's surviving mutants).
    #[test]
    fn each_version_has_its_own_keys() {
        let hello = tls::tests::handshake("watch.test", false);
        let cid = [0x42; 8];
        let (half, rest) = hello.split_at(hello.len() / 2);
        let first = initial_packet(1, &cid, 0, &crypto(0, half), 0);
        let second = initial_packet(0x6b33_43cf, &cid, 1, &crypto(half.len(), rest), 0);
        assert_eq!(asked(&[first.clone(), second.clone()].concat()).len(), 2);
        let mut initial = Initial::new();
        assert_eq!(initial.push(&first), ServerName::Incomplete);
        assert_eq!(initial.push(&second), found("watch.test", false));
    }

    /// The hello's reader reads a datagram as [`asked`] does (fix round 2, review D): a packet after one to
    /// another destination ID is not read, nor one after the first [`MOST_PACKETS`], so neither a damaged
    /// one there undoes the name, nor do a datagram's many tiny Initials cost more than a few.
    #[test]
    fn the_hellos_reader_reads_a_datagram_no_further_than_asked_does() {
        let hello = tls::tests::handshake("watch.test", false);
        let packet = initial_packet(1, &hex(CID), 0, &crypto(0, &hello), 0);
        let mut damaged = initial_packet(1, &[0x22; 8], 0, &[0x01], 0);
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert_eq!(
            Initial::new().push(&[packet.clone(), damaged].concat()),
            found("watch.test", false)
        );
        let tiny = |pn| initial_packet(1, &hex(CID), pn, &[0x01], 0);
        let mut many: Vec<u8> = (1..=u32::try_from(MOST_PACKETS).unwrap_or(0))
            .flat_map(tiny)
            .collect();
        let mut late = tiny(99);
        let last = late.len() - 1;
        late[last] ^= 1;
        many.extend_from_slice(&late);
        let mut initial = Initial::new();
        assert_eq!(initial.push(&many), ServerName::Incomplete);
        assert!(initial.is_quic());
    }

    /// A Version Negotiation packet carries the app's IDs crossed, each half of the crossing checked,
    /// then versions listed in whole 4-byte words, not the app's own, which a client would discard (RFC
    /// 9000 6.2; fix round 2, review D); a packet whose destination is the app's source ID carries it
    /// where that ID has 4 bytes or more.
    #[test]
    fn negotiation_and_the_apps_source_id_carry_what_it_asked() {
        let (destination, source) = (hex("0011223344556677"), hex("a1a2a3a4"));
        let asked = |source: &[u8]| {
            Ids::new(
                Version::V1,
                Cid::new(&destination).unwrap_or(EMPTY),
                Cid::new(source).unwrap_or(EMPTY),
            )
        };
        let negotiation = |to: &[u8], from: &[u8], versions: &[u8]| {
            let mut packet = vec![0x80 | 0x2a, 0, 0, 0, 0, u8::try_from(to.len()).unwrap_or(0)];
            packet.extend_from_slice(to);
            packet.push(u8::try_from(from.len()).unwrap_or(0));
            packet.extend_from_slice(from);
            packet.extend_from_slice(versions);
            packet
        };
        let carries =
            |packet: &[u8], ids: &Ids| Answer::read(packet).is_some_and(|a| a.carries(ids));
        // Version 2 and a reserved version (RFC 9000 15), not the app's version 1.
        let versions = [0x6b, 0x33, 0x43, 0xcf, 0x1a, 0x2a, 0x3a, 0x4a];
        assert!(carries(
            &negotiation(&source, &destination, &versions),
            &asked(&source)
        ));
        assert!(carries(
            &negotiation(&[], &destination, &versions),
            &asked(&[])
        ));
        assert!(!carries(
            &negotiation(&destination, &source, &versions),
            &asked(&source)
        ));
        // Each half of the crossing alone.
        assert!(!carries(
            &negotiation(&hex("b1b2b3b4"), &destination, &versions),
            &asked(&source)
        ));
        assert!(!carries(
            &negotiation(&source, &hex("0011223344556678"), &versions),
            &asked(&source)
        ));
        for listed in [&versions[..0], &versions[..3], &versions[..7]] {
            assert!(
                !carries(&negotiation(&source, &destination, listed), &asked(&source)),
                "{} bytes of versions",
                listed.len()
            );
        }
        let mut own = versions.to_vec();
        own.extend_from_slice(&[0, 0, 0, 1]);
        assert!(
            !carries(&negotiation(&source, &destination, &own), &asked(&source)),
            "a list with the app's own version"
        );
        // A short header to the app's source ID, and a Handshake packet (version 1's type 2).
        let mut short = vec![0x41];
        short.extend_from_slice(&source);
        short.extend_from_slice(&[0x55; 40]);
        assert!(carries(&short, &asked(&source)));
        assert!(
            !carries(&short, &asked(&source[..3])),
            "an ID too short to tell"
        );
        let mut handshake = vec![0xe0, 0, 0, 0, 1, 4];
        handshake.extend_from_slice(&source);
        handshake.push(0);
        handshake.extend_from_slice(&[0x55; 40]);
        assert!(carries(&handshake, &asked(&source)));
        assert!(!carries(&handshake, &asked(&hex("b1b2b3b4"))));
        // A Handshake packet to an ID too short to tell is told by nothing, and opens nothing.
        let mut empty = vec![0xe0, 0, 0, 0, 1, 0, 0];
        empty.extend_from_slice(&[0x55; 40]);
        let Some(read) = Answer::read(&empty) else {
            unreachable!("a long header")
        };
        assert!(!read.carries(&asked(&[])));
        assert_eq!(read.opened(), 0);
    }

    /// A CRYPTO frame holding `data` at `offset`.
    pub(crate) fn crypto(offset: usize, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&(u16::try_from(offset).unwrap_or(0) | 0x4000).to_be_bytes());
        frame.extend_from_slice(&(u16::try_from(data.len()).unwrap_or(0) | 0x4000).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    fn found(name: &str, ech: bool) -> ServerName {
        ServerName::Found(Hello {
            name: name.into(),
            ech,
        })
    }

    #[test]
    fn reads_a_hello_in_one_packet_in_both_versions() {
        let hello = tls::tests::handshake("watch.test", false);
        for version in [1, 0x6b33_43cf] {
            let packet = initial_packet(version, &hex(CID), 0, &crypto(0, &hello), 1200);
            assert_eq!(packet.len(), 1200);
            let mut initial = Initial::new();
            assert_eq!(initial.push(&packet), found("watch.test", false));
            assert!(initial.is_quic());
        }
    }

    #[test]
    fn puts_a_hello_together_across_datagrams_and_out_of_order_frames() {
        // As Chrome sends it: the hello cut into pieces, sent out of order, with PING and PADDING
        // between them, over two datagrams whose second packet is coalesced after a 0-RTT one.
        let mut hello = tls::tests::handshake("scattered.example", true);
        hello.resize(hello.len() + 1500, 0);
        let length = u32::try_from(hello.len() - 4).unwrap_or(0).to_be_bytes();
        hello[1..4].copy_from_slice(&length[1..]);
        let (a, b, c, d) = (0, 40, 700, 1300);
        let mut first = crypto(b, &hello[b..c]);
        first.extend_from_slice(&[0x01, 0x00, 0x00]);
        first.extend_from_slice(&crypto(a, &hello[a..b]));
        let mut second = crypto(d, &hello[d..]);
        second.push(0x01);
        second.extend_from_slice(&crypto(c, &hello[c..d]));
        let cid = hex("0011223344556677");
        let one = initial_packet(1, &cid, 0, &first, 1250);
        let mut two = initial_packet(1, &cid, 1, &second, 900);
        // A 0-RTT packet after it in the same datagram, with a length but nothing readable.
        two.extend_from_slice(&[0xd3, 0, 0, 0, 1, 8]);
        two.extend_from_slice(&cid);
        two.extend_from_slice(&[0, 0x40, 20]);
        two.extend_from_slice(&[0xaa; 20]);

        let mut initial = Initial::new();
        assert_eq!(initial.push(&one), ServerName::Incomplete);
        assert_eq!(initial.push(&two), found("scattered.example", true));

        // The same datagrams in the other order.
        let mut initial = Initial::new();
        assert_eq!(initial.push(&two), ServerName::Incomplete);
        assert_eq!(initial.push(&one), found("scattered.example", true));
    }

    #[test]
    fn gives_up_on_what_is_not_a_quic_start() {
        let mut initial = Initial::new();
        assert_eq!(
            initial.push(b"\x12\x34 an ordinary datagram"),
            ServerName::None
        );
        assert!(!initial.is_quic());
        // A short-header packet: the connection began before Watch saw it.
        let mut initial = Initial::new();
        assert_eq!(initial.push(&[0x40; 1200]), ServerName::None);
        // An unknown version.
        let mut packet = initial_packet(1, &hex(CID), 0, &crypto(0, b"\x01\x00\x00\x10"), 1200);
        packet[4] = 9;
        assert_eq!(Initial::new().push(&packet), ServerName::None);
        // Garbage where the frames should be: the payload of another connection ID's keys.
        let mut packet = initial_packet(1, &hex(CID), 0, &crypto(0, b"\x01\x00\x00\x10"), 1200);
        packet[6] ^= 0xff;
        assert_eq!(Initial::new().push(&packet), ServerName::None);
        // A hello that never completes.
        let mut initial = Initial::new();
        let start = initial_packet(1, &hex(CID), 0, &crypto(0, b"\x01\x00\x10\x00"), 1200);
        for _ in 1..MAX_DATAGRAMS {
            assert_eq!(initial.push(&start), ServerName::Incomplete);
        }
        assert_eq!(initial.push(&start), ServerName::None);
        assert!(initial.is_quic());
    }

    #[test]
    fn keeps_pieces_in_order_and_bounded() {
        let mut initial = Initial::new();
        for offset in [10, 0, 30, 5, 20, 25, 15] {
            assert_eq!(initial.keep(offset, &[1; 5]), Some(()));
        }
        assert_eq!(initial.pieces, vec![(0, 35)]);
        let mut initial = Initial::new();
        for i in 0..MAX_PIECES {
            assert_eq!(initial.keep(i * 3, &[1]), Some(()));
        }
        assert_eq!(initial.keep(MAX_PIECES * 3, &[1]), None);
        let mut initial = Initial::new();
        assert_eq!(initial.keep(tls::MAX_HELLO - 1, &[1, 2, 3]), Some(()));
        assert_eq!(initial.crypto.len(), tls::MAX_HELLO);
        assert_eq!(initial.keep(usize::MAX, &[1]), Some(()));
    }
}
