//! The apps' IP fragments, put together again (ADR 0044, decision 5 as amended on 2026-11-15). An
//! app's kernel cuts a datagram into fragments when it is larger than the tunnel's MTU, or than the
//! path MTU the engine told it of; the engine puts each datagram together again, and hands it on as
//! any other packet.
//!
//! - **Which fragments.** IPv4 ones (the "more fragments" flag set, or an offset), and IPv6 ones (a
//!   fragment header with an offset or the M flag). An IPv6 atomic fragment, offset 0 with no more to
//!   come, is read as a whole packet by [`crate::packet::parse`] and never comes here (RFC 6946).
//! - **One datagram's fragments:** those with the same source, destination and identification, and in
//!   IPv4 the same protocol (RFC 791, RFC 8200 4.5).
//! - **What drops a whole datagram:** a fragment whose length is not a multiple of 8 unless it is the
//!   last, or that is empty; a datagram longer than 65,535 bytes (IPv4's total length, IPv6's payload
//!   length); a first fragment without the whole upper-layer header, and in IPv6 without every
//!   extension header before it (RFC 1858, RFC 7112); a fragment that overlaps one already held (RFC
//!   5722, RFC 8200 4.5); and a fragment past the datagram's end, or a second end. An exact duplicate,
//!   the same place and the same bytes, is dropped alone, and the rest kept, as RFC 8200 4.5 allows.
//!   No ICMP error answers any of these (RFC 8200 4.5).
//! - **Only what the engine carries.** A datagram of another protocol than TCP, UDP or ICMP (`ICMPv6`
//!   in IPv6) would be skipped once whole, so its fragments are dropped as they come: an IPv4 one by
//!   its header, an IPv6 one when its first fragment says.
//! - **The bounds** ([`Bounds`]): datagrams being put together at once, bytes held across all of them,
//!   and the time from a datagram's first fragment to its last. A fragment of a new datagram that would
//!   pass a bound is dropped: held datagrams are never evicted for it. A fragment of a held datagram
//!   that would pass the bound on bytes drops that datagram, which could never be whole. A datagram
//!   whose last fragment has not come in time is dropped at the next fragment, or when the engine
//!   sweeps. Each datagram's buffer grows as its fragments come, to the end of the furthest; nothing
//!   reserves 64 KiB ahead.
//! - **Shared by every app.** Every app sends from the tunnel's one address, so the bounds are not
//!   kept for each app: one app that fills them makes the others' fragments dropped, as every
//!   fragment was before the engine put them together. That is accepted, since the bounds cap what
//!   fragments can cost the engine, and none of it is kept for longer than the wait.
//!
//! Every function here takes bytes that any app on the phone can choose, so none may panic, loop
//! without end or read outside the slice, whatever the input (`fuzz_targets/packet.rs`).

use crate::packet::{self, ICMP, ICMPV6, Skip, TCP, UDP, extension_length, u16_at, u32_at};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// The longest IPv4 packet, by its total length, and the longest IPv6 payload, by its payload length.
const LARGEST: usize = 65_535;

/// What the place of each fragment held costs beyond its bytes, in the bound on bytes: about a B-tree
/// entry's share of memory. Without it, a datagram cut into 8-byte fragments would hold several times
/// the memory the bound counts.
pub const PLACE_COST: usize = 32;

/// How much the reassembler may hold, and for how long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// At most this many datagrams are being put together at once.
    pub datagrams: usize,
    /// At most this many bytes are held across all of them: the data, the first fragment's headers,
    /// and [`PLACE_COST`] for each fragment.
    pub bytes: usize,
    /// A datagram whose last fragment has not come this long after its first is dropped.
    pub wait: Duration,
}

/// What became of one fragment.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Taken {
    /// The whole datagram, rebuilt, when this fragment completed it. [`packet::parse`] never reads it
    /// as a fragment: one that it would, with a fragment header inside the first, is dropped.
    pub whole: Option<Vec<u8>>,
    /// How many fragments were dropped: this one, if it was, with the others of the datagram it made
    /// the reassembler give up, and those of datagrams that waited too long.
    pub dropped: u64,
}

/// One datagram's fragments are those with the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Key {
    source: IpAddr,
    destination: IpAddr,
    /// IPv4's protocol; IPv6 names it only in the first fragment.
    protocol: Option<u8>,
    id: u32,
}

/// A fragment, as read from its packet.
struct Fragment<'a> {
    key: Key,
    /// Where its data goes in the datagram's, in bytes.
    offset: usize,
    /// Whether more fragments follow it.
    more: bool,
    data: &'a [u8],
    /// The headers before its data, as a packet rebuilt from it as the first fragment begins: IPv4's
    /// header, or IPv6's with the extension headers before the fragment header.
    headers: &'a [u8],
    /// For IPv6: where in `headers` the Next Header field that names the fragment header is, and the
    /// fragment header's own Next Header, which names what follows it.
    v6: Option<(usize, u8)>,
}

impl Fragment<'_> {
    fn end(&self) -> usize {
        self.offset + self.data.len()
    }

    /// The length the rebuilt packet would give in its header if this fragment ended it, with these
    /// headers: IPv4's total length, or IPv6's payload length.
    fn length_with(&self, end: usize) -> usize {
        match self.v6 {
            None => self.headers.len() + end,
            Some(_) => self.headers.len() - 40 + end,
        }
    }
}

/// Reads `packet` as a fragment, or `None` when it is none, as a whole packet, or does not fit.
fn read(packet: &[u8]) -> Option<Fragment<'_>> {
    match packet.first()? >> 4 {
        4 => read4(packet),
        6 => read6(packet),
        _ => None,
    }
}

fn read4(packet: &[u8]) -> Option<Fragment<'_>> {
    let header = usize::from(packet[0] & 0x0f) * 4;
    let length = usize::from(u16_at(packet, 2)?);
    if header < 20 || length < header || length > packet.len() {
        return None;
    }
    let field = u16_at(packet, 6)?;
    let (offset, more) = (usize::from(field & 0x1fff) * 8, field & 0x2000 != 0);
    if offset == 0 && !more {
        return None;
    }
    let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
    let destination: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
    Some(Fragment {
        key: Key {
            source: IpAddr::from(source),
            destination: IpAddr::from(destination),
            protocol: Some(*packet.get(9)?),
            id: u32::from(u16_at(packet, 4)?),
        },
        offset,
        more,
        data: packet.get(header..length)?,
        headers: packet.get(..header)?,
        v6: None,
    })
}

fn read6(packet: &[u8]) -> Option<Fragment<'_>> {
    let payload = usize::from(u16_at(packet, 4)?);
    let packet = packet.get(..40 + payload)?;
    if payload == 0 {
        return None;
    }
    let (named, at) = packet::ipv6_fragment_header(packet)?;
    let field = u16_at(packet, at + 2)?;
    let (offset, more) = (usize::from(field & 0xfff8), field & 1 != 0);
    if offset == 0 && !more {
        return None;
    }
    let source: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
    let destination: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
    Some(Fragment {
        key: Key {
            source: IpAddr::from(source),
            destination: IpAddr::from(destination),
            protocol: None,
            id: u32_at(packet, at + 4)?,
        },
        offset,
        more,
        data: packet.get(at + 8..)?,
        headers: packet.get(..at)?,
        v6: Some((named, *packet.get(at)?)),
    })
}

/// Whether a first fragment holds the whole upper-layer header of what it carries, and, in IPv6, every
/// extension header before it (RFC 1858, RFC 7112): UDP's 8 bytes, TCP's header to its data offset, the
/// 8 bytes of ICMP's or `ICMPv6`'s. Another protocol is none the engine carries.
fn holds_its_header(first: &Fragment<'_>) -> bool {
    let data = first.data;
    let (protocol, at) = match (first.key.protocol, first.v6) {
        (Some(protocol), _) => (protocol, 0),
        (None, Some((_, next))) => {
            let (mut next, mut at) = (next, 0);
            loop {
                match extension_length(data, next, at) {
                    Ok(Some(length)) => match data.get(at) {
                        Some(&after) if at + length <= data.len() => {
                            next = after;
                            at += length;
                        }
                        _ => return false,
                    },
                    Ok(None) => break (next, at),
                    Err(_) => return false,
                }
            }
        }
        (None, None) => return false,
    };
    let needed = match (protocol, first.v6.is_some()) {
        (UDP, _) | (ICMP, false) | (ICMPV6, true) => 8,
        (TCP, _) => match data.get(at + 12) {
            Some(&byte) if byte >> 4 >= 5 => usize::from(byte >> 4) * 4,
            _ => return false,
        },
        _ => return false,
    };
    at + needed <= data.len()
}

/// Whether an IPv4 fragment's protocol is one the engine carries. An IPv6 fragment's is known only from
/// the first.
fn carried(key: &Key) -> bool {
    key.protocol
        .is_none_or(|protocol| [TCP, UDP, ICMP].contains(&protocol))
}

/// The headers of a datagram's first fragment, and for IPv6 what [`Fragment::v6`] says of them.
struct Headers {
    bytes: Vec<u8>,
    v6: Option<(usize, u8)>,
}

/// A datagram being put together.
struct Datagram {
    /// When its first fragment came, whatever its place.
    first: Instant,
    /// The first fragment's headers, once it came.
    headers: Option<Headers>,
    /// The data by offset, as long as the furthest fragment's end; what has not come yet is zeros.
    data: Vec<u8>,
    /// Where each fragment that came lies, from its offset to its end.
    places: BTreeMap<usize, usize>,
    /// The data's length, once the last fragment came.
    length: Option<usize>,
    /// How many bytes of data came.
    received: usize,
}

/// Why a fragment cannot join its datagram.
enum Fault {
    /// The same place and the same bytes as one held: dropped alone.
    Duplicate,
    /// It overlaps one held, or lies past the datagram's end, or gives it another end: the whole
    /// datagram is dropped.
    Conflict,
}

impl Datagram {
    fn new(first: Instant) -> Self {
        Self {
            first,
            headers: None,
            data: Vec::new(),
            places: BTreeMap::new(),
            length: None,
            received: 0,
        }
    }

    /// What it holds, as the bound on bytes counts it.
    fn cost(&self) -> usize {
        let headers = self
            .headers
            .as_ref()
            .map_or(0, |headers| headers.bytes.len());
        self.data.len() + headers + self.places.len() * PLACE_COST
    }

    fn fragments(&self) -> u64 {
        self.places.len() as u64
    }

    /// Whether `fragment` may join it, and what it would add to its cost.
    fn check(&self, fragment: &Fragment<'_>) -> Result<usize, Fault> {
        let (offset, end) = (fragment.offset, fragment.end());
        let beyond_end = match self.length {
            Some(length) => end > length || (end == length) == fragment.more,
            // The last fragment's end must be the furthest.
            None => !fragment.more && self.data.len() > end,
        };
        if beyond_end {
            return Err(Fault::Conflict);
        }
        if let Some((&start, &stop)) = self.places.range(..=offset).next_back() {
            if (start, stop) == (offset, end) {
                return if self.data.get(start..stop) == Some(fragment.data) {
                    Err(Fault::Duplicate)
                } else {
                    Err(Fault::Conflict)
                };
            }
            if stop > offset {
                return Err(Fault::Conflict);
            }
        }
        if self
            .places
            .range(offset + 1..)
            .next()
            .is_some_and(|(&start, _)| start < end)
        {
            return Err(Fault::Conflict);
        }
        let headers = if offset == 0 {
            fragment.headers.len()
        } else {
            0
        };
        Ok(end.saturating_sub(self.data.len()) + headers + PLACE_COST)
    }

    /// Takes in `fragment`, which [`Datagram::check`] let in.
    fn insert(&mut self, fragment: &Fragment<'_>) {
        let (offset, end) = (fragment.offset, fragment.end());
        if offset == 0 {
            self.headers = Some(Headers {
                bytes: fragment.headers.to_vec(),
                v6: fragment.v6,
            });
        }
        if end > self.data.len() {
            // Exactly as much as the fragment needs, so that the cost counted is the memory held.
            self.data.reserve_exact(end - self.data.len());
            self.data.resize(end, 0);
        }
        if let Some(slot) = self.data.get_mut(offset..end) {
            slot.copy_from_slice(fragment.data);
        }
        self.places.insert(offset, end);
        self.received += fragment.data.len();
        if !fragment.more {
            self.length = Some(end);
        }
    }

    /// Whether every fragment came: the data's length is known, and the places, which never overlap,
    /// add up to it.
    fn is_whole(&self) -> bool {
        self.length == Some(self.received) && self.headers.is_some()
    }

    /// The packet rebuilt from the first fragment's headers and the data, or `None` when it would be
    /// too long with those headers. IPv4: the "more fragments" flag and the offset cleared, the total
    /// length set and the header checksum made anew. IPv6: the fragment header taken out, the Next
    /// Header that named it naming what it named, and the payload length set.
    fn rebuild(self) -> Option<Vec<u8>> {
        let Headers {
            bytes: mut packet,
            v6,
        } = self.headers?;
        match v6 {
            None => {
                let total = u16::try_from(packet.len() + self.data.len()).ok()?;
                let field = u16_at(&packet, 6)? & !0x3fff;
                packet.get_mut(2..4)?.copy_from_slice(&total.to_be_bytes());
                packet.get_mut(6..8)?.copy_from_slice(&field.to_be_bytes());
                packet.get_mut(10..12)?.copy_from_slice(&[0, 0]);
                let checksum = packet::header_checksum(&packet);
                packet
                    .get_mut(10..12)?
                    .copy_from_slice(&checksum.to_be_bytes());
            }
            Some((named, next)) => {
                let payload = u16::try_from(packet.len() - 40 + self.data.len()).ok()?;
                *packet.get_mut(named)? = next;
                packet
                    .get_mut(4..6)?
                    .copy_from_slice(&payload.to_be_bytes());
            }
        }
        packet.extend_from_slice(&self.data);
        Some(packet)
    }
}

/// The datagrams being put together, within [`Bounds`].
pub struct Reassembler {
    bounds: Bounds,
    datagrams: HashMap<Key, Datagram>,
    /// What they hold, as [`Bounds::bytes`] counts it.
    bytes: usize,
}

impl Reassembler {
    /// A reassembler holding nothing yet.
    #[must_use]
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            datagrams: HashMap::new(),
            bytes: 0,
        }
    }

    /// How many datagrams are being put together.
    #[must_use]
    pub fn datagrams(&self) -> usize {
        self.datagrams.len()
    }

    /// What they hold, as [`Bounds::bytes`] counts it.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Takes in one packet that [`packet::parse`] read as a fragment, which came `now`: it is held,
    /// completes its datagram, or is dropped. Datagrams that waited too long are dropped first. A packet
    /// that is no fragment, or does not fit, is dropped too.
    pub fn take(&mut self, packet: &[u8], now: Instant) -> Taken {
        let mut dropped = self.sweep(now);
        let Some(fragment) = read(packet) else {
            return Taken {
                whole: None,
                dropped: dropped + 1,
            };
        };
        let whole = match self.add(&fragment, now) {
            Ok(whole) => whole,
            Err(lost) => {
                dropped += lost;
                None
            }
        };
        Taken { whole, dropped }
    }

    /// Drops the datagrams whose last fragment has not come `Bounds::wait` after their first: how many
    /// fragments they held.
    pub fn sweep(&mut self, now: Instant) -> u64 {
        let wait = self.bounds.wait;
        let mut dropped = 0;
        let mut freed = 0;
        self.datagrams.retain(|_, datagram| {
            if now.saturating_duration_since(datagram.first) < wait {
                return true;
            }
            dropped += datagram.fragments();
            freed += datagram.cost();
            false
        });
        self.bytes -= freed;
        dropped
    }

    /// Adds `fragment`: the whole datagram once it completes one, or how many fragments were dropped.
    fn add(&mut self, fragment: &Fragment<'_>, now: Instant) -> Result<Option<Vec<u8>>, u64> {
        let key = fragment.key;
        let malformed = fragment.data.is_empty()
            || (fragment.more && !fragment.data.len().is_multiple_of(8))
            || fragment.length_with(fragment.end()) > LARGEST
            || !carried(&key)
            || (fragment.offset == 0 && !holds_its_header(fragment));
        if malformed {
            return Err(self.abandon(key) + 1);
        }
        let Some(datagram) = self.datagrams.get(&key) else {
            // A new datagram: never one held is given up for it.
            let mut datagram = Datagram::new(now);
            let Ok(cost) = datagram.check(fragment) else {
                return Err(1);
            };
            if self.datagrams.len() >= self.bounds.datagrams
                || self.bytes + cost > self.bounds.bytes
            {
                return Err(1);
            }
            datagram.insert(fragment);
            self.bytes += datagram.cost();
            self.datagrams.insert(key, datagram);
            return Ok(None);
        };
        let growth = match datagram.check(fragment) {
            Ok(growth) => growth,
            Err(Fault::Duplicate) => return Err(1),
            Err(Fault::Conflict) => return Err(self.abandon(key) + 1),
        };
        // A held datagram that cannot take its fragment within the bound could never be whole.
        if self.bytes + growth > self.bounds.bytes {
            return Err(self.abandon(key) + 1);
        }
        let Some(datagram) = self.datagrams.get_mut(&key) else {
            return Err(1);
        };
        let before = datagram.cost();
        datagram.insert(fragment);
        self.bytes = self.bytes - before + datagram.cost();
        if !datagram.is_whole() {
            return Ok(None);
        }
        let Some(datagram) = self.datagrams.remove(&key) else {
            return Err(0);
        };
        self.bytes -= datagram.cost();
        let fragments = datagram.fragments();
        // Too long with the first fragment's headers, or a fragment inside the first: dropped.
        match datagram.rebuild() {
            Some(whole) if !matches!(packet::parse(&whole), Err(Skip::Fragment)) => Ok(Some(whole)),
            _ => Err(fragments),
        }
    }

    /// Gives up the datagram of `key`, if one is held: how many fragments it held.
    fn abandon(&mut self, key: Key) -> u64 {
        match self.datagrams.remove(&key) {
            Some(datagram) => {
                self.bytes -= datagram.cost();
                datagram.fragments()
            }
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::FRAGMENT_HEADER;
    use etherparse::PacketBuilder;

    const APP4: [u8; 4] = [10, 1, 10, 1];
    const SERVER4: [u8; 4] = [198, 51, 100, 9];
    const APP6: [u8; 16] = [0xfd, 0, 0, 1, 0xfd, 0, 0, 1, 0xfd, 0, 0, 1, 0xfd, 0, 0, 1];
    const SERVER6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    const WAIT: Duration = Duration::from_secs(5);
    /// A nanosecond before the wait ends.
    const JUST_UNDER: Duration = Duration::from_nanos(4_999_999_999);

    fn bounds() -> Bounds {
        Bounds {
            datagrams: 64,
            bytes: 1 << 20,
            wait: WAIT,
        }
    }

    /// Bytes that differ from one place to the next, so that a fragment put in the wrong place shows.
    fn payload(length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect()
    }

    /// A whole IPv4 UDP datagram as an app's kernel would cut it: "do not fragment" clear, and an
    /// identification of its own.
    fn udp4(length: usize) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .udp(40_000, 9_000)
            .write(&mut packet, &payload(length))
            .unwrap_or_default();
        packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[6] = 0;
        reseal(&mut packet);
        packet
    }

    fn udp6(length: usize) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv6(APP6, SERVER6, 64)
            .udp(40_000, 9_000)
            .write(&mut packet, &payload(length))
            .unwrap_or_default();
        packet
    }

    /// Makes an IPv4 header's checksum anew.
    fn reseal(packet: &mut [u8]) {
        let header = usize::from(packet[0] & 0x0f) * 4;
        packet[10..12].copy_from_slice(&[0, 0]);
        let checksum = packet::header_checksum(&packet[..header]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    /// The fragment of a whole IPv4 packet that carries `length` bytes of its data from `offset`.
    fn piece4(whole: &[u8], offset: usize, length: usize, more: bool) -> Vec<u8> {
        let header = usize::from(whole[0] & 0x0f) * 4;
        let mut piece = whole[..header].to_vec();
        let total = u16::try_from(header + length).unwrap_or(0);
        piece[2..4].copy_from_slice(&total.to_be_bytes());
        let flags = u16::from_be_bytes([whole[6], whole[7]]) & 0xc000;
        let field = flags | if more { 0x2000 } else { 0 } | u16::try_from(offset / 8).unwrap_or(0);
        piece[6..8].copy_from_slice(&field.to_be_bytes());
        reseal(&mut piece);
        piece.extend_from_slice(&whole[header + offset..header + offset + length]);
        piece
    }

    /// The same in IPv6: a fragment header after the first `unfragmentable` bytes, whose Next Header
    /// field is at `named`.
    fn piece6_after(
        whole: &[u8],
        (named, unfragmentable): (usize, usize),
        offset: usize,
        length: usize,
        more: bool,
    ) -> Vec<u8> {
        let mut piece = whole[..unfragmentable].to_vec();
        let next = piece[named];
        piece[named] = FRAGMENT_HEADER;
        let field = u16::try_from(offset).unwrap_or(0) | u16::from(more);
        piece.extend_from_slice(&[next, 0]);
        piece.extend_from_slice(&field.to_be_bytes());
        piece.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        let start = unfragmentable + offset;
        piece.extend_from_slice(&whole[start..start + length]);
        let payload = u16::try_from(piece.len() - 40).unwrap_or(0);
        piece[4..6].copy_from_slice(&payload.to_be_bytes());
        piece
    }

    fn piece6(whole: &[u8], offset: usize, length: usize, more: bool) -> Vec<u8> {
        piece6_after(whole, (6, 40), offset, length, more)
    }

    /// Cuts the data of a whole packet into pieces of `size` bytes, the last shorter, by `piece`.
    fn cut(
        whole: &[u8],
        headers: usize,
        size: usize,
        piece: impl Fn(&[u8], usize, usize, bool) -> Vec<u8>,
    ) -> Vec<Vec<u8>> {
        let data = whole.len() - headers;
        (0..data)
            .step_by(size)
            .map(|offset| {
                let length = size.min(data - offset);
                piece(whole, offset, length, offset + length < data)
            })
            .collect()
    }

    /// Takes each of `pieces` in turn, a millisecond apart, into `reassembler`: what each gave.
    fn feed(reassembler: &mut Reassembler, pieces: &[Vec<u8>], start: Instant) -> Vec<Taken> {
        pieces
            .iter()
            .zip(0u64..)
            .map(|(piece, ms)| reassembler.take(piece, start + Duration::from_millis(ms)))
            .collect()
    }

    /// What `feed` gave, as (rebuilt, dropped) for each fragment, the rebuilt one compared to `whole`.
    fn outcome(taken: &[Taken], whole: &[u8]) -> Vec<(bool, u64)> {
        taken
            .iter()
            .map(|t| (t.whole.as_deref() == Some(whole), t.dropped))
            .collect()
    }

    #[test]
    fn puts_ipv4_fragments_together_in_order_and_out_of_order() {
        let whole = udp4(3_000);
        assert_eq!(packet::parse(&whole).map(|p| p.length), Ok(3_028));
        let pieces = cut(&whole, 20, 1_480, piece4);
        assert_eq!(pieces.len(), 3);
        assert!(
            pieces
                .iter()
                .all(|p| packet::parse(p) == Err(Skip::Fragment))
        );
        let start = Instant::now();
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(&mut reassembler, &pieces, start);
        // The rebuilt packet is the app's own, byte for byte: MF and the offset cleared, the total
        // length set, and a header checksum that checks out.
        assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 0), (true, 0)]);
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));

        let reversed: Vec<_> = pieces.iter().rev().cloned().collect();
        let taken = feed(&mut reassembler, &reversed, start);
        assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 0), (true, 0)]);
        let middle_first = [pieces[1].clone(), pieces[2].clone(), pieces[0].clone()];
        let taken = feed(&mut reassembler, &middle_first, start);
        assert_eq!(outcome(&taken, &whole)[2], (true, 0));
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
    }

    #[test]
    fn the_first_fragments_header_is_kept_with_its_options_and_do_not_fragment() {
        // An IPv4 header with 4 bytes of options (a No Operation and an End of List, padded), and
        // "do not fragment" set, which a sender that fragments clears; whatever the first fragment says
        // of it is kept.
        let plain = udp4(2_000);
        let mut whole = vec![0x46];
        whole.extend_from_slice(&plain[1..20]);
        whole.extend_from_slice(&[1, 0, 0, 0]);
        whole.extend_from_slice(&plain[20..]);
        let total = u16::try_from(whole.len()).unwrap_or(0);
        whole[2..4].copy_from_slice(&total.to_be_bytes());
        whole[6] = 0x40;
        reseal(&mut whole);
        assert!(packet::parse(&whole).is_ok_and(|p| p.transport == 24));
        let mut pieces = cut(&whole, 24, 1_008, piece4);
        assert_eq!(pieces.len(), 2);
        // A later fragment's header, as a sender writes it, carries no options.
        let mut second = piece4(&plain, 1_008, pieces[1].len() - 24, false);
        second[6] |= 0x40;
        reseal(&mut second);
        pieces[1] = second;
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(&mut reassembler, &pieces, Instant::now());
        assert_eq!(outcome(&taken, &whole), [(false, 0), (true, 0)]);
    }

    #[test]
    fn puts_ipv6_fragments_together_and_takes_out_the_fragment_header() {
        let whole = udp6(3_000);
        let pieces = cut(&whole, 40, 1_448, piece6);
        assert!(
            pieces
                .iter()
                .all(|p| packet::parse(p) == Err(Skip::Fragment))
        );
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(&mut reassembler, &pieces, Instant::now());
        // Next Header names UDP again, and the payload length is the whole datagram's.
        assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 0), (true, 0)]);
        let reversed: Vec<_> = pieces.iter().rev().cloned().collect();
        let taken = feed(&mut reassembler, &reversed, Instant::now());
        assert_eq!(outcome(&taken, &whole)[2], (true, 0));

        // With a hop-by-hop header before the fragment header: its Next Header named the fragment
        // header, and names UDP once it is taken out.
        let mut with_options = whole[..40].to_vec();
        with_options[6] = 0;
        with_options.extend_from_slice(&[UDP, 0, 1, 4, 0, 0, 0, 0]);
        with_options.extend_from_slice(&whole[40..]);
        let payload = u16::try_from(with_options.len() - 40).unwrap_or(0);
        with_options[4..6].copy_from_slice(&payload.to_be_bytes());
        assert!(packet::parse(&with_options).is_ok_and(|p| p.transport == 48));
        let pieces = cut(&with_options, 48, 1_440, |w, o, l, m| {
            piece6_after(w, (40, 48), o, l, m)
        });
        assert_eq!(pieces[0][40], FRAGMENT_HEADER);
        let taken = feed(&mut reassembler, &pieces, Instant::now());
        assert_eq!(
            outcome(&taken, &with_options),
            [(false, 0), (false, 0), (true, 0)]
        );
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
    }

    #[test]
    fn an_overlap_drops_the_whole_datagram() {
        let whole = udp4(3_000);
        let start = Instant::now();
        // The second fragment starts 8 bytes inside the first, as in the attack of RFC 1858.
        let overlapping = [
            piece4(&whole, 0, 1_480, true),
            piece4(&whole, 1_472, 1_480, true),
        ];
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(&mut reassembler, &overlapping, start);
        assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 2)]);
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));

        // One that ends inside a held one, one that starts where it does but is longer, and one that
        // starts inside it.
        for second in [
            piece4(&whole, 0, 16, true),
            piece4(&whole, 8, 1_480, true),
            piece4(&whole, 1_472, 16, true),
        ] {
            let pieces = [piece4(&whole, 8, 1_472, true), second];
            let taken = feed(&mut reassembler, &pieces, start);
            assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 2)]);
        }

        // The same place with other bytes is no duplicate.
        let mut forged = piece4(&whole, 1_480, 1_480, true);
        let last = forged.len() - 1;
        forged[last] ^= 1;
        let pieces = [piece4(&whole, 1_480, 1_480, true), forged];
        let taken = feed(&mut reassembler, &pieces, start);
        assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 2)]);

        // In IPv6 too (RFC 5722).
        let whole6 = udp6(3_000);
        let pieces = [
            piece6(&whole6, 1_448, 1_448, true),
            piece6(&whole6, 0, 1_456, true),
        ];
        let taken = feed(&mut reassembler, &pieces, start);
        assert_eq!(outcome(&taken, &whole6), [(false, 0), (false, 2)]);
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
    }

    #[test]
    fn an_exact_duplicate_is_dropped_alone_and_the_rest_kept() {
        let whole = udp4(3_000);
        let pieces = cut(&whole, 20, 1_480, piece4);
        let with_duplicates = [
            pieces[0].clone(),
            pieces[0].clone(),
            pieces[2].clone(),
            pieces[2].clone(),
            pieces[1].clone(),
        ];
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(&mut reassembler, &with_duplicates, Instant::now());
        assert_eq!(
            outcome(&taken, &whole),
            [(false, 0), (false, 1), (false, 0), (false, 1), (true, 0)]
        );
        let whole6 = udp6(2_000);
        let pieces = cut(&whole6, 40, 1_448, piece6);
        let with_duplicate = [pieces[1].clone(), pieces[1].clone(), pieces[0].clone()];
        let taken = feed(&mut reassembler, &with_duplicate, Instant::now());
        assert_eq!(
            outcome(&taken, &whole6),
            [(false, 0), (false, 1), (true, 0)]
        );
    }

    /// RFC 1858 and RFC 7112: a first fragment that does not hold the whole upper-layer header drops
    /// its datagram, with what was held of it.
    #[test]
    fn a_first_fragment_without_the_whole_header_drops_its_datagram() {
        let mut syn = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .tcp(40_000, 443, 1, 65_535)
            .write(&mut syn, &payload(100))
            .unwrap_or_default();
        syn[6] = 0;
        reseal(&mut syn);
        let start = Instant::now();
        let mut reassembler = Reassembler::new(bounds());
        // TCP's header is 20 bytes: a first fragment of 16 holds only part of it.
        let tiny = [piece4(&syn, 16, 104, false), piece4(&syn, 0, 16, true)];
        let taken = feed(&mut reassembler, &tiny, start);
        assert_eq!(outcome(&taken, &syn), [(false, 0), (false, 2)]);
        // One of 24 holds it.
        let enough = [piece4(&syn, 24, 96, false), piece4(&syn, 0, 24, true)];
        let taken = feed(&mut reassembler, &enough, start);
        assert_eq!(outcome(&taken, &syn), [(false, 0), (true, 0)]);

        // UDP's 8 bytes are enough; ICMP's too.
        let datagram = udp4(100);
        let pieces = [
            piece4(&datagram, 0, 8, true),
            piece4(&datagram, 8, 100, false),
        ];
        let taken = feed(&mut reassembler, &pieces, start);
        assert_eq!(outcome(&taken, &datagram), [(false, 0), (true, 0)]);

        // In IPv6 the first fragment must also hold every extension header before UDP's: here a
        // destination options header of 16 bytes, cut after 8.
        let whole6 = udp6(100);
        let mut with_options = whole6[..40].to_vec();
        with_options[6] = 60;
        with_options.extend_from_slice(&[UDP, 1, 1, 12]);
        with_options.extend_from_slice(&[0; 12]);
        with_options.extend_from_slice(&whole6[40..]);
        let payload = u16::try_from(with_options.len() - 40).unwrap_or(0);
        with_options[4..6].copy_from_slice(&payload.to_be_bytes());
        assert!(packet::parse(&with_options).is_ok_and(|p| p.transport == 56));
        let short = [
            piece6(&with_options, 8, with_options.len() - 48, false),
            piece6(&with_options, 0, 8, true),
        ];
        let taken = feed(&mut reassembler, &short, start);
        assert_eq!(outcome(&taken, &with_options), [(false, 0), (false, 2)]);
        let whole_chain = [
            piece6(&with_options, 24, with_options.len() - 64, false),
            piece6(&with_options, 0, 24, true),
        ];
        let taken = feed(&mut reassembler, &whole_chain, start);
        assert_eq!(outcome(&taken, &with_options), [(false, 0), (true, 0)]);
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
    }

    /// A datagram longer than 65,535 bytes, a fragment not a multiple of 8 that is not the last, an
    /// empty one, a fragment past the datagram's end, and a second end each drop the whole datagram.
    #[test]
    fn malformed_fragments_drop_their_datagram() {
        let whole = udp4(3_000);
        let start = Instant::now();
        let mut reassembler = Reassembler::new(bounds());
        let first = piece4(&whole, 0, 1_480, true);
        // At the last offset IPv4 can name, 16 bytes pass 65,535 with the 20 of the header.
        let mut far = piece4(&whole, 0, 16, false);
        far[6..8].copy_from_slice(&0x1fffu16.to_be_bytes());
        reseal(&mut far);
        let odd = piece4(&whole, 1_480, 1_476, true);
        let empty = piece4(&whole, 1_480, 0, true);
        for bad in [far, odd, empty] {
            let taken = feed(&mut reassembler, &[first.clone(), bad], start);
            assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 2)]);
        }
        // The last fragment says the datagram ends at 3,008; another fragment past that, or another
        // last fragment that ends elsewhere, is wrong.
        let last = piece4(&whole, 2_960, 48, false);
        for bad in [
            piece4(&udp4(4_000), 1_480, 1_536, true),
            piece4(&whole, 1_480, 8, false),
        ] {
            let taken = feed(&mut reassembler, &[last.clone(), bad], start);
            assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 2)]);
        }
        // A last fragment that ends before what was held, before any other last fragment came.
        let taken = feed(
            &mut reassembler,
            &[
                piece4(&whole, 1_480, 1_480, true),
                piece4(&whole, 8, 8, false),
            ],
            start,
        );
        assert_eq!(outcome(&taken, &whole), [(false, 0), (false, 2)]);

        // In IPv6, past 65,535 bytes of payload by the fragment header's offset.
        let whole6 = udp6(100);
        let mut far6 = piece6(&whole6, 0, 16, false);
        far6[42..44].copy_from_slice(&0xfff8u16.to_be_bytes());
        let taken = feed(&mut reassembler, &[far6], start);
        assert_eq!(taken[0].dropped, 1);
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
    }

    /// Only TCP, UDP and ICMP are carried once whole: another protocol's fragments are dropped as they
    /// come, an IPv6 datagram's once its first fragment names it. What is no fragment is dropped too.
    #[test]
    fn fragments_of_what_the_engine_does_not_carry_are_dropped() {
        let mut gre = udp4(2_000);
        gre[9] = 47;
        reseal(&mut gre);
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(
            &mut reassembler,
            &cut(&gre, 20, 1_480, piece4),
            Instant::now(),
        );
        assert_eq!(outcome(&taken, &gre), [(false, 1), (false, 1)]);
        let mut gre6 = udp6(2_000);
        gre6[6] = 47;
        let pieces = cut(&gre6, 40, 1_448, piece6);
        let taken = feed(
            &mut reassembler,
            &[pieces[1].clone(), pieces[0].clone()],
            Instant::now(),
        );
        assert_eq!(outcome(&taken, &gre6), [(false, 0), (false, 2)]);
        // A whole packet, an IPv6 atomic fragment, and bytes that are no packet.
        let atomic = piece6(&udp6(100), 0, 108, false);
        for not_one in [udp4(100), atomic, vec![0x45, 0, 0]] {
            assert_eq!(
                reassembler.take(&not_one, Instant::now()),
                Taken {
                    whole: None,
                    dropped: 1
                }
            );
        }
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
    }

    /// A fragment header inside the first fragment's data: once whole, the packet is still a fragment,
    /// and is dropped; an atomic one inside is read whole, as `parse` reads it.
    #[test]
    fn a_rebuilt_packet_that_is_still_a_fragment_is_dropped() {
        let inner = udp6(100);
        let nested = piece6(&inner, 0, 64, true);
        assert_eq!(packet::parse(&nested), Err(Skip::Fragment));
        // As the outer datagram's data, cut in two.
        let pieces = cut(&nested, 40, 48, |w, o, l, m| {
            let mut piece = piece6(w, o, l, m);
            piece[44..48].copy_from_slice(&7u32.to_be_bytes());
            piece
        });
        assert_eq!(pieces.len(), 2);
        let mut reassembler = Reassembler::new(bounds());
        let taken = feed(&mut reassembler, &pieces, Instant::now());
        assert_eq!(outcome(&taken, &nested), [(false, 0), (false, 2)]);

        let atomic = piece6(&inner, 0, 108, false);
        assert!(packet::parse(&atomic).is_ok());
        let pieces = cut(&atomic, 40, 48, |w, o, l, m| {
            let mut piece = piece6(w, o, l, m);
            piece[44..48].copy_from_slice(&8u32.to_be_bytes());
            piece
        });
        let taken = feed(&mut reassembler, &pieces, Instant::now());
        assert_eq!(
            outcome(&taken, &atomic),
            [(false, 0), (false, 0), (true, 0)]
        );
    }

    /// A fragment of a new datagram beyond the bound on datagrams, or on bytes, is dropped, and the
    /// datagrams held are not; a held datagram whose next fragment would pass the bound on bytes is
    /// dropped, since it could never be whole.
    #[test]
    fn each_bound_holds_without_evicting_a_held_datagram() {
        let start = Instant::now();
        let datagram = |id: u16| {
            let mut whole = udp4(2_000);
            whole[4..6].copy_from_slice(&id.to_be_bytes());
            reseal(&mut whole);
            whole
        };
        let (one, two, three) = (datagram(1), datagram(2), datagram(3));
        let mut reassembler = Reassembler::new(Bounds {
            datagrams: 2,
            ..bounds()
        });
        let firsts = [
            piece4(&one, 0, 1_480, true),
            piece4(&two, 0, 1_480, true),
            piece4(&three, 0, 1_480, true),
        ];
        let taken = feed(&mut reassembler, &firsts, start);
        assert_eq!(
            taken.iter().map(|t| t.dropped).collect::<Vec<_>>(),
            [0, 0, 1]
        );
        assert_eq!(reassembler.datagrams(), 2);
        let taken = reassembler.take(&piece4(&one, 1_480, 528, false), start);
        assert_eq!(taken.whole.as_deref(), Some(&one[..]));
        // Room again for a third.
        let taken = feed(&mut reassembler, &cut(&three, 20, 1_480, piece4), start);
        assert_eq!(outcome(&taken, &three), [(false, 0), (true, 0)]);

        // Bytes: what a first fragment of 1,480 bytes costs, with its header and its place.
        let first = 1_480 + 20 + 32;
        let mut reassembler = Reassembler::new(Bounds {
            bytes: 2 * first,
            ..bounds()
        });
        let taken = feed(&mut reassembler, &firsts, start);
        assert_eq!(
            taken.iter().map(|t| t.dropped).collect::<Vec<_>>(),
            [0, 0, 1]
        );
        assert_eq!(reassembler.bytes(), 2 * first);
        // The second's last fragment would pass the bound: that datagram goes, the first stays.
        let taken = reassembler.take(&piece4(&two, 1_480, 528, false), start);
        assert_eq!((taken.whole, taken.dropped), (None, 2));
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (1, first));
        let taken = reassembler.take(&piece4(&one, 1_480, 528, false), start);
        assert_eq!(taken.whole.as_deref(), Some(&one[..]));
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));

        // A far fragment costs the data before it too, which the buffer holds as zeros.
        let mut reassembler = Reassembler::new(bounds());
        let far = piece4(&udp4(4_000), 2_960, 1_048, false);
        assert_eq!(reassembler.take(&far, start).dropped, 0);
        assert_eq!(reassembler.bytes(), 4_008 + 32);
        // Each place costs beyond its bytes, so that a datagram cut into the smallest fragments holds
        // no more memory than the bound counts: here 8 bytes of data each.
        let tiny = udp4(56);
        let mut reassembler = Reassembler::new(bounds());
        let pieces = cut(&tiny, 20, 8, piece4);
        let taken = feed(&mut reassembler, &pieces[..7], start);
        assert!(taken.iter().all(|t| t.dropped == 0));
        assert_eq!(reassembler.bytes(), 56 + 20 + 7 * 32);
    }

    /// A datagram is put together if its last fragment comes less than the wait after its first; at
    /// the wait it is dropped, at the next fragment or by a sweep.
    #[test]
    fn a_datagram_whose_last_fragment_comes_too_late_is_dropped() {
        let start = Instant::now();
        let whole = udp4(2_000);
        let pieces = cut(&whole, 20, 1_480, piece4);
        let mut reassembler = Reassembler::new(bounds());
        assert_eq!(reassembler.take(&pieces[0], start).dropped, 0);
        let just_in_time = reassembler.take(&pieces[1], start + JUST_UNDER);
        assert_eq!(just_in_time.whole.as_deref(), Some(&whole[..]));

        assert_eq!(reassembler.take(&pieces[0], start).dropped, 0);
        // The last fragment at the wait finds its datagram gone, and starts another.
        let late = reassembler.take(&pieces[1], start + WAIT);
        assert_eq!((late.whole, late.dropped), (None, 1));
        assert_eq!(reassembler.datagrams(), 1);
        assert_eq!(reassembler.sweep(start + WAIT + JUST_UNDER), 0);
        assert_eq!(reassembler.sweep(start + 2 * WAIT), 1);
        assert_eq!((reassembler.datagrams(), reassembler.bytes()), (0, 0));
        // Another datagram's fragment sweeps what waited too long.
        assert_eq!(reassembler.take(&pieces[0], start).dropped, 0);
        let other = udp6(2_000);
        let taken = reassembler.take(&piece6(&other, 0, 1_448, true), start + WAIT);
        assert_eq!(taken.dropped, 1);
        assert_eq!(reassembler.datagrams(), 1);
    }
}
