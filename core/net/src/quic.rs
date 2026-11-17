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
//! The AEAD tag is not checked there: anyone can compute these keys, so a valid tag would prove nothing
//! about who sent the packet, and a damaged packet fails to parse. Removing the payload's protection is
//! AES in counter mode as GCM runs it (the counter starts at 2), which is all of GCM a reader needs; HKDF
//! is HMAC over SHA-256. Both are checked against the RFCs' sample packets below.
//!
//! The same keys tell a stand-in's answers apart (ADR 0044, unit 9b): [`asked`] reads the connection IDs
//! of the Initial packets an app sends, and [`Answer`] whether what comes back is the server's answer to
//! one of them. There the tag is checked, by GCM's GHASH written out below from NIST SP 800-38D, with no
//! further dependency: not against a sender who saw the app's packet, who can compute the keys and the
//! tag as well, but so that a datagram of anyone else matches only by a chance of 2^-128 rather than by
//! frames that happen to parse. A Retry carries no trace of the connection ID it answers but its
//! integrity tag (RFC 9001 5.8), so only the tag can tell which of an app's Initial packets it is for.
//!
//! The bytes come from any app, so nothing here may panic or read outside a slice
//! (`fuzz_targets/quic.rs`, `fuzz_targets/identifiers.rs`).

use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use sha2::{Digest, Sha256};

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

/// The QUIC versions whose Initial packets can be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// HMAC-SHA-256 (RFC 2104) of the concatenated `parts`.
fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// TLS 1.3's `HKDF-Expand-Label` with an empty context (RFC 8446 7.1), for at most 32 bytes: one block
/// of HKDF-Expand (RFC 5869).
fn expand_label(secret: &[u8; 32], label: &[u8], length: u8) -> [u8; 32] {
    let label_length = u8::try_from(6 + label.len()).unwrap_or(u8::MAX);
    hmac(
        secret,
        &[&[0, length, label_length], b"tls13 ", label, &[0], &[1]],
    )
}

/// The keys of one side's Initial packets.
#[derive(Clone)]
struct Keys {
    key: Aes128,
    iv: [u8; 12],
    hp: Aes128,
}

impl Keys {
    /// The Initial keys for the connection ID `cid`, on the side named by `label`.
    fn initial(version: Version, cid: &[u8], label: &[u8]) -> Self {
        let initial = hmac(version.salt(), &[cid]);
        let secret = expand_label(&initial, label, 32);
        let [key, iv, hp] = version.labels();
        let key = expand_label(&secret, key, 16);
        let iv = expand_label(&secret, iv, 12);
        let hp = expand_label(&secret, hp, 16);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&iv[..12]);
        Self {
            key: aes(&key),
            iv: nonce,
            hp: aes(&hp),
        }
    }

    /// The header protection mask for a sample of the protected payload.
    fn mask(&self, sample: &[u8]) -> [u8; 16] {
        let mut block = aes::Block::default();
        block.copy_from_slice(sample);
        self.hp.encrypt_block(&mut block);
        block.into()
    }

    /// The nonce of packet `pn`: the IV with the packet number in its last eight bytes (RFC 9001 5.3).
    fn nonce(&self, pn: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        for (byte, pn_byte) in nonce[4..].iter_mut().zip(pn.to_be_bytes()) {
            *byte ^= pn_byte;
        }
        nonce
    }

    /// Removes (or adds) the payload's protection: AES-CTR with GCM's counter blocks for packet `pn`.
    fn apply(&self, pn: u64, data: &mut [u8]) {
        let nonce = self.nonce(pn);
        let mut counter: u32 = 2;
        for chunk in data.chunks_mut(16) {
            let mut block = aes::Block::default();
            block[..12].copy_from_slice(&nonce);
            block[12..].copy_from_slice(&counter.to_be_bytes());
            self.key.encrypt_block(&mut block);
            for (byte, key_byte) in chunk.iter_mut().zip(block.iter()) {
                *byte ^= key_byte;
            }
            counter = counter.wrapping_add(1);
        }
    }
}

fn aes(key: &[u8; 32]) -> Aes128 {
    let mut key16 = aes::cipher::Key::<Aes128>::default();
    key16.copy_from_slice(&key[..16]);
    Aes128::new(&key16)
}

/// `block` encrypted with `key`, as a number, the first byte highest.
fn encrypted(key: &Aes128, block: [u8; 16]) -> u128 {
    let mut out = aes::Block::default();
    out.copy_from_slice(&block);
    key.encrypt_block(&mut out);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&out);
    u128::from_be_bytes(bytes)
}

/// The product of `x` and `y` in GCM's field, GF(2^128) with its bits in GCM's order: the first bit of
/// the block, the number's highest, is the coefficient of x^0 (NIST SP 800-38D 6.3, Algorithm 1).
fn multiply(x: u128, y: u128) -> u128 {
    const R: u128 = 0xe1 << 120;
    let mut product = 0;
    let mut v = y;
    for bit in (0..128).rev() {
        if (x >> bit) & 1 == 1 {
            product ^= v;
        }
        v = if v & 1 == 1 { (v >> 1) ^ R } else { v >> 1 };
    }
    product
}

/// GHASH (SP 800-38D 6.4) under the hash key `h` of `aad` and then `ciphertext`, each padded with zeros
/// to whole blocks, then their lengths in bits.
fn ghash(h: u128, aad: &[u8], ciphertext: &[u8]) -> u128 {
    let mut y = 0;
    for part in [aad, ciphertext] {
        for chunk in part.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            y = multiply(y ^ u128::from_be_bytes(block), h);
        }
    }
    let bits = |part: &[u8]| u128::from(u64::try_from(part.len()).unwrap_or(u64::MAX)) * 8;
    multiply(y ^ (bits(aad) << 64 | bits(ciphertext)), h)
}

/// AES-128-GCM's tag (SP 800-38D 7.1) for a 96-bit `nonce`, over `aad` and `ciphertext`.
fn gcm_tag(key: &Aes128, nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let h = encrypted(key, [0; 16]);
    let mut first = [0u8; 16];
    first[..12].copy_from_slice(nonce);
    first[15] = 1;
    (encrypted(key, first) ^ ghash(h, aad, ciphertext)).to_be_bytes()
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
    if initial {
        let token = varint_usize(datagram, &mut pos)?;
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
        dcid_start,
        dcid_end,
        scid_start,
        scid_end,
        pn_offset: pos,
        end,
    })
}

/// Removes the protection of the packet that starts at `start`, returning its payload without the
/// tag, or `None` if the packet is too short for it.
fn open(
    keys: &Keys,
    datagram: &[u8],
    start: usize,
    pn_offset: usize,
    end: usize,
) -> Option<Vec<u8>> {
    let sample = datagram.get(pn_offset + 4..pn_offset + 4 + SAMPLE)?;
    if pn_offset + 4 + SAMPLE > end {
        return None;
    }
    let mask = keys.mask(sample);
    let first = datagram.get(start)? ^ (mask[0] & 0x0f);
    let pn_length = usize::from(first & 3) + 1;
    let pn = datagram
        .get(pn_offset..pn_offset + pn_length)?
        .iter()
        .zip(&mask[1..])
        .fold(0u64, |pn, (b, m)| pn << 8 | u64::from(b ^ m));
    let payload_end = end.checked_sub(TAG)?;
    let mut payload = datagram.get(pn_offset + pn_length..payload_end)?.to_vec();
    keys.apply(pn, &mut payload);
    Some(payload)
}

/// As [`open`], but only for a packet whose AEAD tag checks: the header, its protection removed, is the
/// associated data (RFC 9001 5.3).
fn open_checked(
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
    let ciphertext = datagram.get(pn_offset + pn_length..payload_end)?;
    let tag = datagram.get(payload_end..end)?;
    if gcm_tag(&keys.key, &keys.nonce(pn), &header, ciphertext) != tag {
        return None;
    }
    let mut payload = ciphertext.to_vec();
    keys.apply(pn, &mut payload);
    Some(payload)
}

/// Whether `payload`, an Initial packet's with its protection removed, holds only the frames an Initial
/// may carry, each whole, to its end (RFC 9000 17.2.2).
fn frames_parse(payload: &[u8]) -> bool {
    Initial::default().frames(payload).is_some()
}

/// A connection ID, of at most 20 bytes in QUIC versions 1 and 2, kept in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ids {
    version: Version,
    destination: Cid,
    source: Cid,
}

/// The connection IDs of each long-header packet in `datagram`, an app's, when the datagram holds a
/// QUIC Initial packet of version 1 or 2 whose protection, removed with the client's keys, gives a tag
/// that checks and frames that parse to its end; none otherwise, nor when one of its Initial packets
/// fails so. Each distinct pair once: an Initial sent again carries the same.
#[must_use]
pub fn asked(datagram: &[u8]) -> Vec<Ids> {
    let mut asked: Vec<Ids> = Vec::new();
    let mut initial = false;
    let mut at = 0;
    while let Some(packet) = long_packet(datagram, at) {
        let ids = |start: usize, end: usize| Cid::new(datagram.get(start..end)?);
        let (Some(destination), Some(source)) = (
            ids(packet.dcid_start, packet.dcid_end),
            ids(packet.scid_start, packet.scid_end),
        ) else {
            return Vec::new();
        };
        if packet.initial {
            let keys = Keys::initial(packet.version, destination.get(), CLIENT);
            match open_checked(&keys, datagram, at, packet.pn_offset, packet.end) {
                Some(payload) if frames_parse(&payload) => initial = true,
                _ => return Vec::new(),
            }
        }
        let ids = Ids {
            version: packet.version,
            destination,
            source,
        };
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
/// asked ([`Answer::carries`]).
pub struct Answer<'a> {
    datagram: &'a [u8],
    /// Its first packet's long header; `None` for a short header.
    long: Option<ServerHeader<'a>>,
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
        Some(Self { datagram, long })
    }

    /// Whether it is the server's answer to `asked` (RFC 9000 17.2, RFC 9001 5, RFC 9369): a Version
    /// Negotiation packet whose source connection ID is the app's destination and whose destination is
    /// the app's source; a Retry whose integrity tag checks with the app's destination ID; an Initial
    /// whose protection, removed with the server's keys of the app's destination ID, gives a tag that
    /// checks and frames that parse to its end; or any packet whose destination ID is the app's source
    /// ID, where that is 4 bytes or more, long enough to tell. A client that sends no source ID, as
    /// Chromium's, so Cronet's, does, is told only by its Initial keys: by the server's Version
    /// Negotiation, Retry or first Initial packet.
    #[must_use]
    pub fn carries(&self, asked: &Ids) -> bool {
        let source = asked.source.get();
        let Some(header) = &self.long else {
            return asked.source.tells() && self.datagram.get(1..1 + source.len()) == Some(source);
        };
        if header.version == 0 {
            let versions = self.datagram.len().saturating_sub(header.rest);
            return header.source == asked.destination.get()
                && header.destination == source
                && versions >= 4
                && versions % 4 == 0;
        }
        if Version::from_wire(header.version) != Some(asked.version) || header.destination != source
        {
            return false;
        }
        if asked.source.tells() {
            return true;
        }
        let kind = (header.first >> 4) & 3;
        let (initial, retry) = asked.version.kinds();
        if kind == retry {
            return self.retry_for(asked);
        }
        kind == initial && self.initial_for(asked)
    }

    /// Whether it is a Retry whose integrity tag checks with the app's destination ID (RFC 9001 5.8).
    fn retry_for(&self, asked: &Ids) -> bool {
        let Some(end) = self.datagram.len().checked_sub(TAG) else {
            return false;
        };
        let Some(header) = &self.long else {
            return false;
        };
        if end < header.rest {
            return false;
        }
        let original = asked.destination.get();
        let mut pseudo = Vec::with_capacity(1 + original.len() + end);
        pseudo.push(asked.destination.length);
        pseudo.extend_from_slice(original);
        pseudo.extend_from_slice(&self.datagram[..end]);
        let (key, nonce) = asked.version.retry();
        let mut key16 = aes::cipher::Key::<Aes128>::default();
        key16.copy_from_slice(&key);
        gcm_tag(&Aes128::new(&key16), &nonce, &pseudo, &[]) == self.datagram[end..]
    }

    /// Whether it is an Initial that the server's keys of the app's destination ID open.
    fn initial_for(&self, asked: &Ids) -> bool {
        let Some(packet) = long_packet(self.datagram, 0) else {
            return false;
        };
        let keys = Keys::initial(asked.version, asked.destination.get(), SERVER);
        packet.initial
            && open_checked(&keys, self.datagram, 0, packet.pn_offset, packet.end)
                .is_some_and(|payload| frames_parse(&payload))
    }
}

/// An Initial packet of `version`, protected with `keys` as its sender protects one, whose header names
/// `destination` and `source`, numbered `pn` in `pn_length` bytes (1 to 4), holding `payload` as it is.
fn seal(
    version: Version,
    keys: &Keys,
    (destination, source): (&[u8], &[u8]),
    (pn, pn_length): (u32, usize),
    payload: &[u8],
) -> Option<Vec<u8>> {
    let numbered = pn.to_be_bytes();
    let pn_bytes = numbered.get(4usize.checked_sub(pn_length)?..)?;
    let first = 0xc0 | (version.kinds().0 << 4) | u8::try_from(pn_length.checked_sub(1)?).ok()?;
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
    // No token.
    header.push(0);
    let length = u16::try_from(pn_length + payload.len() + TAG)
        .ok()
        .filter(|&n| n <= 0x3fff)?;
    header.extend_from_slice(&(length | 0x4000).to_be_bytes());
    let pn_offset = header.len();
    header.extend_from_slice(pn_bytes);
    let mut ciphertext = payload.to_vec();
    keys.apply(u64::from(pn), &mut ciphertext);
    let tag = gcm_tag(&keys.key, &keys.nonce(u64::from(pn)), &header, &ciphertext);
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
    let keys = Keys::initial(version, original, SERVER);
    seal(version, &keys, (destination, source), (pn, 2), frames)
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
    let keys = Keys::initial(version, destination, CLIENT);
    let header = 1 + 4 + 1 + destination.len() + 1 + source.len() + 1 + 2 + 4;
    let mut payload = frames.to_vec();
    payload.resize(size.saturating_sub(header + TAG).max(frames.len()), 0);
    seal(version, &keys, (destination, source), (pn, 4), &payload)
}

/// A Retry packet of `version` to the client's source ID `destination`, from `source`, with `token`,
/// for the client's destination ID `original`: its integrity tag computed as a server does (RFC 9001
/// 5.8). Only for tests, as [`server_initial`].
#[doc(hidden)]
#[must_use]
pub fn retry(
    version: u32,
    original: &[u8],
    (destination, source): (&[u8], &[u8]),
    token: &[u8],
) -> Option<Vec<u8>> {
    let version = Version::from_wire(version)?;
    let mut packet = vec![0xc0 | (version.kinds().1 << 4)];
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
    let (key, nonce) = version.retry();
    let mut key16 = aes::cipher::Key::<Aes128>::default();
    key16.copy_from_slice(&key);
    packet.extend_from_slice(&gcm_tag(&Aes128::new(&key16), &nonce, &pseudo, &[]));
    Some(packet)
}

/// The start of a QUIC connection, read for its `ClientHello` one datagram at a time.
#[derive(Default)]
pub struct Initial {
    /// The last Initial keys, with the version and connection ID they are for.
    keys: Option<(Version, Vec<u8>, Keys)>,
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
    /// sense, or [`MAX_DATAGRAMS`] passed without a whole `ClientHello`.
    pub fn push(&mut self, datagram: &[u8]) -> ServerName {
        self.datagrams += 1;
        let mut read = false;
        let mut at = 0;
        while let Some(packet) = long_packet(datagram, at) {
            if packet.initial {
                let cid = &datagram[packet.dcid_start..packet.dcid_end];
                let keys = match &self.keys {
                    Some((version, known, keys)) if *version == packet.version && known == cid => {
                        keys.clone()
                    }
                    _ => {
                        let keys = Keys::initial(packet.version, cid, CLIENT);
                        self.keys = Some((packet.version, cid.to_vec(), keys.clone()));
                        keys
                    }
                };
                let Some(payload) = open(&keys, datagram, at, packet.pn_offset, packet.end) else {
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
                    self.keep(offset, data)?;
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

    /// No IDs asked.
    const NOTHING: [Ids; 0] = [];
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

    #[test]
    fn hkdf_matches_rfc_5869() {
        // RFC 5869 A.1, the extract step, and one block of the expand step with its info.
        let prk = hmac(&hex("000102030405060708090a0b0c"), &[&[0x0b; 22]]);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = hmac(&prk, &[&hex("f0f1f2f3f4f5f6f7f8f9"), &[1]]);
        assert_eq!(
            okm.to_vec(),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
        );
    }

    #[test]
    fn keys_match_rfc_9001() {
        // RFC 9001 A.1.
        let initial = hmac(Version::V1.salt(), &[&hex(CID)]);
        assert_eq!(
            initial.to_vec(),
            hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44")
        );
        let client = expand_label(&initial, CLIENT, 32);
        assert_eq!(
            client.to_vec(),
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        assert_eq!(
            expand_label(&client, b"quic key", 16)[..16].to_vec(),
            hex("1f369613dd76d5467730efcbe3b1a22d")
        );
        assert_eq!(
            expand_label(&client, b"quic iv", 12)[..12].to_vec(),
            hex("fa044b2f42a3fd3b46fb255c")
        );
        assert_eq!(
            expand_label(&client, b"quic hp", 16)[..16].to_vec(),
            hex("9f50449e04a0e810283a1e9933adedd2")
        );
        // RFC 9001 A.2 and A.3: the header protection masks of the client's and the server's samples.
        let keys = Keys::initial(Version::V1, &hex(CID), CLIENT);
        assert_eq!(
            keys.mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b"))[..5].to_vec(),
            hex("437b9aec36")
        );
        let server = Keys::initial(Version::V1, &hex(CID), b"server in");
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
        let keys = Keys::initial(Version::V2, &hex(CID), b"server in");
        let Some(packet) = long_packet(&protected, 0) else {
            unreachable!("a long header")
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

    /// GCM's first two test cases, from the paper that defined it ("The Galois/Counter Mode of
    /// Operation", appendix B), under the all-zero key and nonce: no data, and one block of zeros.
    #[test]
    fn the_gcm_tag_matches_its_specification() {
        let mut zero = aes::cipher::Key::<Aes128>::default();
        zero.copy_from_slice(&[0; 16]);
        let key = Aes128::new(&zero);
        assert_eq!(
            gcm_tag(&key, &[0; 12], &[], &[]).to_vec(),
            hex("58e2fccefa7e3061367f1d57a4e7455a")
        );
        assert_eq!(
            gcm_tag(
                &key,
                &[0; 12],
                &[],
                &hex("0388dace60b6a392f328c2b971b2fe78")
            )
            .to_vec(),
            hex("ab6e47d42cec13bdf53a67b21257bddf")
        );
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
        let ids = |version, destination: &[u8]| Ids {
            version,
            destination: Cid::new(destination).unwrap_or(Cid {
                length: 0,
                bytes: [0; MAX_CID],
            }),
            source: Cid {
                length: 0,
                bytes: [0; MAX_CID],
            },
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
        assert!(
            !read
                .as_ref()
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
        let ids = |version, destination: &[u8]| Ids {
            version,
            destination: Cid::new(destination).unwrap_or(empty),
            source: empty,
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
            assert_eq!(super::asked(&damaged), NOTHING, "a tag that fails");
        }
        // The right tag over frames an Initial may not carry (a STREAM frame).
        let Some(stream) = client_initial(1, (&destination, &[]), (0, &[0x08, 0, 1, 0]), 1200)
        else {
            unreachable!("an Initial packet")
        };
        assert_eq!(asked(&stream), NOTHING);
        assert_eq!(asked(b"\x12\x34 an ordinary datagram"), NOTHING);
        assert_eq!(asked(&[0x40; 1200]), NOTHING);
    }

    /// A Version Negotiation packet carries the app's IDs crossed, then the versions it lists; a packet
    /// whose destination is the app's source ID carries it where that ID has 4 bytes or more.
    #[test]
    fn negotiation_and_the_apps_source_id_carry_what_it_asked() {
        let (destination, source) = (hex("0011223344556677"), hex("a1a2a3a4"));
        let asked = |source: &[u8]| Ids {
            version: Version::V1,
            destination: Cid::new(&destination).unwrap_or(Cid {
                length: 0,
                bytes: [0; MAX_CID],
            }),
            source: Cid::new(source).unwrap_or(Cid {
                length: 0,
                bytes: [0; MAX_CID],
            }),
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
        let versions = [0, 0, 0, 1, 0x6b, 0x33, 0x43, 0xcf];
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
        assert!(!carries(
            &negotiation(&source, &destination, &[]),
            &asked(&source)
        ));
        assert!(!carries(
            &negotiation(&source, &destination, &versions[..3]),
            &asked(&source)
        ));
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
