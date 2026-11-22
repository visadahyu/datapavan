//! IP packets as they come from and go to the tunnel: the parts the engine reads, the rewriting of
//! addresses and ports with incremental checksums (RFC 1624), and the few packets the engine builds
//! itself: TCP resets, UDP datagrams, ICMP and `ICMPv6` errors, and echo replies.
//!
//! Every function here takes bytes that any app on the phone can choose, so none may panic, loop
//! without end or read outside the slice, whatever the input (`fuzz_targets/packet.rs`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// IP protocol number of TCP.
pub const TCP: u8 = 6;
/// IP protocol number of UDP.
pub const UDP: u8 = 17;
/// IP protocol number of ICMP.
pub const ICMP: u8 = 1;
/// IP protocol number of `ICMPv6`.
pub const ICMPV6: u8 = 58;

/// TCP flags.
pub const FIN: u8 = 0x01;
/// TCP flags.
pub const SYN: u8 = 0x02;
/// TCP flags.
pub const RST: u8 = 0x04;
/// TCP flags.
pub const ACK: u8 = 0x10;

/// ICMP's echo request (RFC 792).
pub const ECHO_REQUEST: u8 = 8;
/// ICMP's echo reply.
pub const ECHO_REPLY: u8 = 0;
/// `ICMPv6`'s echo request (RFC 4443 4.1).
pub const ECHO_REQUEST_V6: u8 = 128;
/// `ICMPv6`'s echo reply.
pub const ECHO_REPLY_V6: u8 = 129;

/// The hop limit of packets the engine builds: Linux's default. An answer or an echo reply that came
/// with a hop limit of its own is given that one instead ([`set_hops`]), so that a tool that reads it
/// sees the network's value (ADR 0044, unit 11b); one from the tool's relay, or one whose hop limit the
/// kernel did not give, keeps this one.
pub const HOPS: u8 = 64;
/// IPv6 extension headers followed before giving up on a packet.
const MAX_EXTENSIONS: usize = 8;

/// What the engine reads of one TCP or UDP packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    /// [`TCP`] or [`UDP`].
    pub protocol: u8,
    /// Where the TCP or UDP header starts.
    pub transport: usize,
    /// The packet's length by its IP header; bytes after it are padding.
    pub length: usize,
    /// The sender's address and port.
    pub source: SocketAddr,
    /// The receiver's address and port.
    pub destination: SocketAddr,
    /// The time to live (IPv4) or hop limit (IPv6) the app sent it with.
    pub hops: u8,
}

/// What the engine reads of an ICMP or `ICMPv6` echo request (ping) from an app.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Echo {
    /// Where the ICMP header starts.
    pub icmp: usize,
    /// The packet's length by its IP header; bytes after it are padding.
    pub length: usize,
    /// The app's address.
    pub source: IpAddr,
    /// The address it pings.
    pub destination: IpAddr,
    /// The echo identifier: for an unprivileged ping socket, the one its kernel chose.
    pub id: u16,
    /// The sequence number.
    pub sequence: u16,
    /// The time to live (IPv4) or hop limit (IPv6) the app sent it with.
    pub hops: u8,
}

/// Why a packet is not one the engine forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Too short, a wrong version, lengths that do not fit, or an echo request whose checksum is
    /// wrong.
    Malformed,
    /// A fragment, which the engine puts together with the rest of its datagram
    /// ([`crate::fragments`]). An IPv6 atomic fragment, offset 0 with no more to come, is read as a
    /// whole packet (RFC 6946).
    Fragment,
    /// Another protocol, by its number: ICMP, for example, which [`echo_request`] reads when it is
    /// an echo request.
    Other(u8),
}

/// What an IP header says of its packet.
pub(crate) struct Ip {
    pub(crate) protocol: u8,
    /// Where the upper-layer header starts.
    pub(crate) transport: usize,
    pub(crate) length: usize,
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) hops: u8,
}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at.checked_add(1)?)?,
    ]))
}

pub(crate) fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a TCP or UDP packet from the tunnel.
///
/// # Errors
/// [`Skip`] says why the packet is not one the engine forwards.
pub fn parse(packet: &[u8]) -> Result<Packet, Skip> {
    let Ip {
        protocol,
        transport,
        length,
        source,
        destination,
        hops,
    } = ip(packet)?;
    let minimum = match protocol {
        TCP => 20,
        UDP => 8,
        other => return Err(Skip::Other(other)),
    };
    if transport
        .checked_add(minimum)
        .is_none_or(|end| end > length)
    {
        return Err(Skip::Malformed);
    }
    if protocol == TCP {
        let offset = usize::from(packet[transport + 12] >> 4) * 4;
        if offset < 20 || transport + offset > length {
            return Err(Skip::Malformed);
        }
    }
    let port = |at| u16_at(packet, at).ok_or(Skip::Malformed);
    Ok(Packet {
        protocol,
        transport,
        length,
        source: SocketAddr::new(source, port(transport)?),
        destination: SocketAddr::new(destination, port(transport + 2)?),
        hops,
    })
}

/// Reads an ICMP echo request in IPv4, or an `ICMPv6` one in IPv6, from the tunnel. The engine
/// rebuilds what it sends on, so a request whose checksum is wrong, which the destination's kernel
/// would drop, is refused here rather than sent with a checksum made anew.
///
/// # Errors
/// [`Skip::Other`] for any other ICMP message, as an error or ICMP in IPv6, and [`Skip::Malformed`]
/// for a request cut short or whose checksum is wrong.
pub fn echo_request(packet: &[u8]) -> Result<Echo, Skip> {
    let Ip {
        protocol,
        transport,
        length,
        source,
        destination,
        hops,
    } = ip(packet)?;
    let request = match (source, protocol) {
        (IpAddr::V4(_), ICMP) => ECHO_REQUEST,
        (IpAddr::V6(_), ICMPV6) => ECHO_REQUEST_V6,
        _ => return Err(Skip::Other(protocol)),
    };
    let message = packet.get(transport..length).ok_or(Skip::Malformed)?;
    let (Some(&kind), Some(&code), Some(id), Some(sequence)) = (
        message.first(),
        message.get(1),
        u16_at(message, 4),
        u16_at(message, 6),
    ) else {
        return Err(Skip::Malformed);
    };
    if (kind, code) != (request, 0) {
        return Err(Skip::Other(protocol));
    }
    // ICMP's checksum covers the message alone, `ICMPv6`'s a pseudo-header too (RFC 4443 2.3). Summed
    // with its checksum, a message that checks out gives all ones.
    let pseudo = if protocol == ICMP {
        0
    } else {
        pseudo_sum(source, destination, ICMPV6, message.len())
    };
    if fold(pseudo + sum_words(message)) != 0xffff {
        return Err(Skip::Malformed);
    }
    Ok(Echo {
        icmp: transport,
        length,
        source,
        destination,
        id,
        sequence,
        hops,
    })
}

/// Reads the IP header of a packet from the tunnel, IPv4 or IPv6, following IPv6's extension headers.
pub(crate) fn ip(packet: &[u8]) -> Result<Ip, Skip> {
    let first = *packet.first().ok_or(Skip::Malformed)?;
    let (protocol, transport, length, source, destination, hops) = match first >> 4 {
        4 => {
            let header = usize::from(first & 0x0f) * 4;
            let length = usize::from(u16_at(packet, 2).ok_or(Skip::Malformed)?);
            if header < 20 || length < header || length > packet.len() {
                return Err(Skip::Malformed);
            }
            let fragment = u16_at(packet, 6).ok_or(Skip::Malformed)?;
            if fragment & 0x3fff != 0 {
                return Err(Skip::Fragment);
            }
            let source: [u8; 4] = packet
                .get(12..16)
                .and_then(|b| b.try_into().ok())
                .ok_or(Skip::Malformed)?;
            let destination: [u8; 4] = packet
                .get(16..20)
                .and_then(|b| b.try_into().ok())
                .ok_or(Skip::Malformed)?;
            (
                packet[9],
                header,
                length,
                IpAddr::from(source),
                IpAddr::from(destination),
                packet[8],
            )
        }
        6 => {
            let payload = usize::from(u16_at(packet, 4).ok_or(Skip::Malformed)?);
            let length = 40 + payload;
            // A payload length of 0 means a jumbogram, which no tunnel of ours carries.
            if payload == 0 || length > packet.len() {
                return Err(Skip::Malformed);
            }
            let source: [u8; 16] = packet
                .get(8..24)
                .and_then(|b| b.try_into().ok())
                .ok_or(Skip::Malformed)?;
            let destination: [u8; 16] = packet
                .get(24..40)
                .and_then(|b| b.try_into().ok())
                .ok_or(Skip::Malformed)?;
            let (protocol, transport) = ipv6_transport(&packet[..length])?;
            (
                protocol,
                transport,
                length,
                IpAddr::from(source),
                IpAddr::from(destination),
                packet[7],
            )
        }
        _ => return Err(Skip::Malformed),
    };
    Ok(Ip {
        protocol,
        transport,
        length,
        source,
        destination,
        hops,
    })
}

/// Follows IPv6 extension headers to the upper-layer protocol and where its header starts.
fn ipv6_transport(packet: &[u8]) -> Result<(u8, usize), Skip> {
    let mut next = packet[6];
    let mut at = 40;
    for _ in 0..MAX_EXTENSIONS {
        // A fragment header with an offset or the "more" flag: an atomic fragment is read whole.
        if next == FRAGMENT_HEADER && u16_at(packet, at + 2).ok_or(Skip::Malformed)? & 0xfff9 != 0 {
            return Err(Skip::Fragment);
        }
        let Some(length) = extension_length(packet, next, at)? else {
            return Ok((next, at));
        };
        next = *packet.get(at).ok_or(Skip::Malformed)?;
        at += length;
        if at > packet.len() {
            return Err(Skip::Malformed);
        }
    }
    Err(Skip::Malformed)
}

/// IPv6's Next Header value of a fragment header.
pub(crate) const FRAGMENT_HEADER: u8 = 44;

/// The length of the IPv6 extension header `next` that starts at `at` in `packet`, or `None` when
/// `next` names an upper-layer protocol instead.
pub(crate) fn extension_length(packet: &[u8], next: u8, at: usize) -> Result<Option<usize>, Skip> {
    let length = |at: usize| packet.get(at + 1).copied().ok_or(Skip::Malformed);
    Ok(Some(match next {
        // Hop-by-hop options, routing, destination options: (length + 1) * 8 bytes.
        0 | 43 | 60 => (usize::from(length(at)?) + 1) * 8,
        // Fragment: 8 bytes, with the offset and the "more" flag.
        FRAGMENT_HEADER => 8,
        // Authentication header: (length + 2) * 4 bytes.
        51 => (usize::from(length(at)?) + 2) * 4,
        _ => return Ok(None),
    }))
}

/// Where the first fragment header of an IPv6 packet starts, and where the Next Header field that
/// names it is: byte 6 of the IPv6 header, or the first byte of the extension header before it.
/// `None` when the packet has none before its upper-layer header, or its headers do not fit.
pub(crate) fn ipv6_fragment_header(packet: &[u8]) -> Option<(usize, usize)> {
    let (mut named, mut at) = (6, 40);
    let mut next = *packet.get(named)?;
    for _ in 0..MAX_EXTENSIONS {
        if next == FRAGMENT_HEADER {
            return Some((named, at));
        }
        let length = extension_length(packet, next, at).ok()??;
        named = at;
        next = *packet.get(at)?;
        at += length;
        if at > packet.len() {
            return None;
        }
    }
    None
}

/// The checksum of an IPv4 header whose checksum field is zero (RFC 791).
pub(crate) fn header_checksum(header: &[u8]) -> u16 {
    !fold(sum_words(header))
}

/// The TCP flags of a parsed TCP packet.
#[must_use]
pub fn tcp_flags(packet: &[u8], parsed: &Packet) -> u8 {
    packet.get(parsed.transport + 13).copied().unwrap_or(0)
}

/// The sequence number of a parsed TCP packet.
#[must_use]
pub fn tcp_sequence(packet: &[u8], parsed: &Packet) -> u32 {
    u32_at(packet, parsed.transport + 4).unwrap_or(0)
}

/// The acknowledgement number of a parsed TCP packet.
#[must_use]
pub fn tcp_acknowledgement(packet: &[u8], parsed: &Packet) -> u32 {
    u32_at(packet, parsed.transport + 8).unwrap_or(0)
}

/// The UDP payload of a parsed UDP packet, by the UDP header's own length.
#[must_use]
pub fn udp_payload<'a>(packet: &'a [u8], parsed: &Packet) -> Option<&'a [u8]> {
    let length = usize::from(u16_at(packet, parsed.transport + 4)?);
    let end = parsed.transport.checked_add(length)?;
    if length < 8 || end > parsed.length {
        return None;
    }
    packet.get(parsed.transport + 8..end)
}

/// Writes an address into `slot`, which has its length.
fn write_ip(slot: &mut [u8], address: IpAddr) {
    match address {
        IpAddr::V4(a) => slot.copy_from_slice(&a.octets()),
        IpAddr::V6(a) => slot.copy_from_slice(&a.octets()),
    }
}

fn octets(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// RFC 1624: the one's-complement checksum after the 16-bit words `old` became `new`.
pub(crate) fn adjust(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (o, n) in old.as_chunks::<2>().0.iter().zip(new.as_chunks::<2>().0) {
        sum += u32::from(!u16::from_be_bytes([o[0], o[1]]));
        sum += u32::from(u16::from_be_bytes([n[0], n[1]]));
    }
    !fold(sum)
}

pub(crate) fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(sum).unwrap_or(u16::MAX)
}

/// Gives a parsed TCP or UDP packet new ends, of the same IP version, and fixes its checksums.
/// Returns `None`, changing nothing, when the versions differ.
pub fn set_ends(
    packet: &mut [u8],
    parsed: &Packet,
    source: SocketAddr,
    destination: SocketAddr,
) -> Option<()> {
    let v4 = parsed.source.is_ipv4();
    if source.is_ipv4() != v4 || destination.is_ipv4() != v4 {
        return None;
    }
    let (source_at, destination_at, size) = if v4 { (12, 16, 4) } else { (8, 24, 16) };
    let ports = parsed.transport;
    // On the stack, not the heap: this runs for every packet of every connection.
    let mut old = [0u8; 36];
    let mut new = [0u8; 36];
    let used = 2 * size + 4;
    old[..size].copy_from_slice(packet.get(source_at..source_at + size)?);
    old[size..2 * size].copy_from_slice(packet.get(destination_at..destination_at + size)?);
    old[2 * size..used].copy_from_slice(packet.get(ports..ports + 4)?);
    write_ip(&mut new[..size], source.ip());
    write_ip(&mut new[size..2 * size], destination.ip());
    new[2 * size..2 * size + 2].copy_from_slice(&source.port().to_be_bytes());
    new[2 * size + 2..used].copy_from_slice(&destination.port().to_be_bytes());
    let (old, new) = (&old[..used], &new[..used]);
    let checksum_at = ports + if parsed.protocol == TCP { 16 } else { 6 };
    let checksum = u16_at(packet, checksum_at)?;
    // An IPv4 UDP checksum of 0 means "none" and stays so.
    let skip = parsed.protocol == UDP && v4 && checksum == 0;
    packet
        .get_mut(source_at..source_at + size)?
        .copy_from_slice(&new[..size]);
    packet
        .get_mut(destination_at..destination_at + size)?
        .copy_from_slice(&new[size..2 * size]);
    packet
        .get_mut(ports..ports + 4)?
        .copy_from_slice(&new[2 * size..]);
    if !skip {
        let mut adjusted = adjust(checksum, old, new);
        if parsed.protocol == UDP && adjusted == 0 {
            adjusted = 0xffff;
        }
        packet
            .get_mut(checksum_at..checksum_at + 2)?
            .copy_from_slice(&adjusted.to_be_bytes());
    }
    if v4 {
        let header = u16_at(packet, 10)?;
        packet
            .get_mut(10..12)?
            .copy_from_slice(&adjust(header, &old[..8], &new[..8]).to_be_bytes());
    }
    Some(())
}

/// The sum over the pseudo-header of TCP, UDP or `ICMPv6` (RFC 9293, RFC 8200).
pub(crate) fn pseudo_sum(from: IpAddr, to: IpAddr, protocol: u8, length: usize) -> u32 {
    let mut sum = sum_words(&octets(from)) + sum_words(&octets(to));
    sum += u32::from(protocol);
    let length = u32::try_from(length).unwrap_or(u32::MAX);
    sum += (length >> 16) + (length & 0xffff);
    sum
}

pub(crate) fn sum_words(bytes: &[u8]) -> u32 {
    let (words, rest) = bytes.as_chunks::<2>();
    let mut sum = 0u32;
    for word in words {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*word)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    // Folded here so that sums of large packets never wrap.
    u32::from(fold(sum))
}

/// An IP header from `from` to `to` for a payload of `length` bytes, or `None` when the versions
/// differ or the payload is too long.
fn ip_header(from: IpAddr, to: IpAddr, protocol: u8, length: usize) -> Option<Vec<u8>> {
    match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let total = u16::try_from(length.checked_add(20)?).ok()?;
            let mut header = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, HOPS, protocol, 0, 0];
            header[2..4].copy_from_slice(&total.to_be_bytes());
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
            let checksum = !fold(sum_words(&header));
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            Some(header)
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let payload = u16::try_from(length).ok()?;
            let mut header = vec![0x60, 0, 0, 0];
            header.extend_from_slice(&payload.to_be_bytes());
            header.extend_from_slice(&[protocol, HOPS]);
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
            Some(header)
        }
        _ => None,
    }
}

/// Puts an IP header before `transport`, after writing the transport checksum at `checksum_at`.
fn assemble(
    from: IpAddr,
    to: IpAddr,
    protocol: u8,
    mut transport: Vec<u8>,
    checksum_at: usize,
) -> Option<Vec<u8>> {
    let mut header = ip_header(from, to, protocol, transport.len())?;
    let pseudo = if protocol == ICMP {
        0
    } else {
        pseudo_sum(from, to, protocol, transport.len())
    };
    let mut checksum = !fold(pseudo + sum_words(&transport));
    if protocol == UDP && checksum == 0 {
        checksum = 0xffff;
    }
    transport
        .get_mut(checksum_at..checksum_at + 2)?
        .copy_from_slice(&checksum.to_be_bytes());
    header.append(&mut transport);
    Some(header)
}

/// A TCP reset from `from` to `to`: numbered `sequence`, and acknowledging `acknowledgement` when it
/// is given (RFC 9293 3.10.7.1: a reset answering a SYN acknowledges it; one answering a segment of
/// an unknown connection takes that segment's acknowledgement number as its sequence number).
#[must_use]
pub fn tcp_reset(
    from: SocketAddr,
    to: SocketAddr,
    sequence: u32,
    acknowledgement: Option<u32>,
) -> Option<Vec<u8>> {
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&from.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&to.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.unwrap_or(0).to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = RST | if acknowledgement.is_some() { ACK } else { 0 };
    assemble(from.ip(), to.ip(), TCP, tcp, 16)
}

/// A UDP datagram from `from` to `to`.
#[must_use]
pub fn udp(from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let length = u16::try_from(payload.len().checked_add(8)?).ok()?;
    let mut datagram = Vec::with_capacity(usize::from(length));
    datagram.extend_from_slice(&from.port().to_be_bytes());
    datagram.extend_from_slice(&to.port().to_be_bytes());
    datagram.extend_from_slice(&length.to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    assemble(from.ip(), to.ip(), UDP, datagram, 6)
}

/// Why a destination cannot be reached, for the ICMP error the app gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreachable {
    /// No route to the host, or it did not answer.
    Host,
    /// The host answered that no one listens on the port (UDP).
    Port,
    /// The network part refuses it: "communication administratively prohibited" (RFC 1812 5.2.7.1), `ICMPv6`'s
    /// "communication with destination administratively prohibited".
    Prohibited,
}

/// An ICMP (IPv4) or `ICMPv6` "destination unreachable" for the app's packet `original`, sent as if
/// by its destination, quoting as much of the original as the minimum MTU allows (RFC 1812 4.3.2.3,
/// RFC 4443 2.4).
#[must_use]
pub fn unreachable(original: &[u8], parsed: &Packet, reason: Unreachable) -> Option<Vec<u8>> {
    let quoted = original.get(..parsed.length)?;
    icmp_error(quoted, parsed.destination.ip(), parsed.source.ip(), reason)
}

/// The "administratively prohibited" that refuses the app's echo request `original`, sent as if by
/// the address it pinged and quoting the request, as [`unreachable`] quotes a datagram. An app's
/// ping socket hands it to the app as "host unreachable" (IPv4) or "permission denied" (IPv6).
/// `None` for a request to a multicast, broadcast or unspecified address, which no ICMP error may
/// answer (RFC 1812 4.3.2.7, RFC 4443 2.4 (e)), and which has no one sender to answer as.
#[must_use]
pub fn echo_refused(original: &[u8], echo: &Echo) -> Option<Vec<u8>> {
    if !unicast(echo.destination) {
        return None;
    }
    let quoted = original.get(..echo.length)?;
    icmp_error(
        quoted,
        echo.destination,
        echo.source,
        Unreachable::Prohibited,
    )
}

/// Whether `address` is one an ICMP error may come from: not multicast, broadcast or unspecified,
/// whose packets no error answers (RFC 1812 4.3.2.7, RFC 4443 2.4 (e)), and which no one host could
/// answer as.
pub(crate) fn unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(to) => !(to.is_multicast() || to.is_broadcast() || to.is_unspecified()),
        IpAddr::V6(to) => !(to.is_multicast() || to.is_unspecified()),
    }
}

/// A "destination unreachable" from `from` to `to`, quoting `quoted`.
fn icmp_error(quoted: &[u8], from: IpAddr, to: IpAddr, reason: Unreachable) -> Option<Vec<u8>> {
    let (kind, code) = if from.is_ipv4() {
        let code = match reason {
            Unreachable::Host => 1,
            Unreachable::Port => 3,
            Unreachable::Prohibited => 13,
        };
        (3, code)
    } else {
        let code = match reason {
            Unreachable::Host => 3,
            Unreachable::Port => 4,
            Unreachable::Prohibited => 1,
        };
        (1, code)
    };
    icmp_message(quoted, (from, to), (kind, code), [0; 4])
}

/// An ICMP error message of `kind` and `code` from `from` to `to`, with `rest` as the four bytes of
/// its header after the checksum, quoting as much of `quoted` as the least MTU allows: 576 bytes in
/// all for IPv4 (RFC 1812 4.3.2.3), 1,280 for IPv6 (RFC 4443 2.4 (c)).
fn icmp_message(
    quoted: &[u8],
    (from, to): (IpAddr, IpAddr),
    (kind, code): (u8, u8),
    rest: [u8; 4],
) -> Option<Vec<u8>> {
    let (protocol, room) = if from.is_ipv4() {
        (ICMP, LEAST_MTU_V4 - 20 - 8)
    } else {
        (ICMPV6, LEAST_MTU_V6 - 40 - 8)
    };
    let mut icmp = vec![kind, code, 0, 0];
    icmp.extend_from_slice(&rest);
    icmp.extend_from_slice(&quoted[..quoted.len().min(room)]);
    assemble(from, to, protocol, icmp, 2)
}

/// The least MTU of IPv4 that every host must take: 576 bytes (RFC 791, RFC 1122 3.3.3).
pub const LEAST_MTU_V4: usize = 576;
/// The least MTU of IPv6, which every link carries: 1,280 bytes (RFC 8200 5).
pub const LEAST_MTU_V6: usize = 1_280;

/// An ICMP "fragmentation needed and DF set" (type 3 code 4, RFC 1191) in IPv4, or an `ICMPv6`
/// "packet too big" (type 2, RFC 8201) in IPv6, from `from` to `to`, saying that packets of at most
/// `mtu` bytes pass, and quoting `quoted` as [`unreachable()`] quotes the app's packet. IPv4's next-hop
/// MTU has 16 bits, and a larger `mtu` gives its largest. `None` when `from` is a multicast,
/// broadcast or unspecified address, which no ICMP error may answer for, or the versions differ.
#[must_use]
pub fn too_big(quoted: &[u8], from: IpAddr, to: IpAddr, mtu: u32) -> Option<Vec<u8>> {
    if from.is_ipv4() {
        let [high, low] = u16::try_from(mtu).unwrap_or(u16::MAX).to_be_bytes();
        path_error(quoted, (from, to), (3, 4), [0, 0, high, low])
    } else {
        path_error(quoted, (from, to), (2, 0), mtu.to_be_bytes())
    }
}

/// An ICMP (IPv4) or `ICMPv6` error of `kind` and `code` from `from` to `to`, with `rest` as the four
/// bytes of its header after the checksum, quoting `quoted` as [`unreachable()`] quotes the app's
/// packet: what a router or host on the path sent the engine, as the engine passes it on to the app
/// ("time exceeded", "destination unreachable" with its code; ADR 0044, unit 11b). `None` when `from`
/// is a multicast, broadcast or unspecified address, which no ICMP error may come from, or the versions
/// differ.
#[must_use]
pub fn path_error(
    quoted: &[u8],
    (from, to): (IpAddr, IpAddr),
    (kind, code): (u8, u8),
    rest: [u8; 4],
) -> Option<Vec<u8>> {
    if !unicast(from) || from.is_ipv4() != to.is_ipv4() {
        return None;
    }
    icmp_message(quoted, (from, to), (kind, code), rest)
}

/// An ICMP echo reply in IPv4, or an `ICMPv6` one in IPv6, from `from` to the app at `to`, with the
/// app's echo identifier `id` and the `sequence` and `data` of the request it answers. Its checksum is
/// made anew, over the `ICMPv6` pseudo-header too, and its hop limit is the engine's own.
#[must_use]
pub fn echo_reply(
    from: IpAddr,
    to: IpAddr,
    id: u16,
    sequence: u16,
    data: &[u8],
) -> Option<Vec<u8>> {
    let kind = if from.is_ipv4() {
        ECHO_REPLY
    } else {
        ECHO_REPLY_V6
    };
    echo(kind, (from, to), (id, sequence), data)
}

/// What a router quotes back of a packet an app sent, beside its addresses (ADR 0044, unit 11b): the
/// first eight bytes of its IP header, IPv4's type of service, total length, identification, flags and
/// fragment offset, or IPv6's traffic class, flow label and payload length; the hop limit it was sent
/// with; and the first eight bytes of its transport header, UDP's whole, or an echo request's type,
/// code, checksum, identifier and sequence number. Tools that match an error to their probe by these,
/// as Paris traceroute and mtr do, find them as the app sent them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sent {
    ip: [u8; 8],
    hops: u8,
    transport: [u8; 8],
}

impl Sent {
    /// What a router would quote of `packet`, an IPv4 or IPv6 packet whose transport header starts at
    /// `transport`; `None` when it is shorter than that.
    #[must_use]
    pub fn of(packet: &[u8], transport: usize) -> Option<Self> {
        let ip: [u8; 8] = packet.get(..8)?.try_into().ok()?;
        let hops = *packet.get(if ip[0] >> 4 == 4 { 8 } else { 7 })?;
        let transport = packet
            .get(transport..transport.checked_add(8)?)?
            .try_into()
            .ok()?;
        Some(Self {
            ip,
            hops,
            transport,
        })
    }

    /// The hop limit it was sent with.
    #[must_use]
    pub fn hops(&self) -> u8 {
        self.hops
    }
}

/// The packet an app sent, `sent`, as a router on its path quotes it in an error (RFC 792, RFC 4443
/// 2.4): an IP header from `from` to `to` for `protocol`, of the app's own fields but with no IPv4
/// options or IPv6 extension headers, and the hop limit the router found, 1 for one that found it spent
/// (`expired`), else the one the app sent it with, which a router further on finds lower; then the
/// transport header as the app sent it, and `rest`, what the router quoted after it. `None` when the
/// versions of the addresses differ.
#[must_use]
pub fn quoted(
    sent: &Sent,
    (from, to): (IpAddr, IpAddr),
    protocol: u8,
    expired: bool,
    rest: &[u8],
) -> Option<Vec<u8>> {
    let hops = if expired { 1 } else { sent.hops };
    let ip = sent.ip;
    let mut quote = match (from, to) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let mut header = vec![0x45, ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]];
            header.extend_from_slice(&[hops, protocol, 0, 0]);
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
            let checksum = header_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            header
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let mut header = vec![0x60 | (ip[0] & 0x0f), ip[1], ip[2], ip[3], ip[4], ip[5]];
            header.extend_from_slice(&[protocol, hops]);
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
            header
        }
        _ => return None,
    };
    quote.extend_from_slice(&sent.transport);
    quote.extend_from_slice(rest);
    Some(quote)
}

/// The echo request an app sent, ICMP's in IPv4 or `ICMPv6`'s in IPv6, from the app at `from` to `to`,
/// with its own identifier `id`, its `sequence` and `data`: rebuilt for the quote of an error from the
/// path that answers it, by whose identifier the app's kernel finds its ping socket (ADR 0044, unit
/// 11b). Its checksum is made over what it holds.
#[must_use]
pub fn echo_request_of(
    from: IpAddr,
    to: IpAddr,
    id: u16,
    sequence: u16,
    data: &[u8],
) -> Option<Vec<u8>> {
    let kind = if from.is_ipv4() {
        ECHO_REQUEST
    } else {
        ECHO_REQUEST_V6
    };
    echo(kind, (from, to), (id, sequence), data)
}

/// An echo message of `kind`, a request or a reply, from `from` to `to`.
fn echo(
    kind: u8,
    (from, to): (IpAddr, IpAddr),
    (id, sequence): (u16, u16),
    data: &[u8],
) -> Option<Vec<u8>> {
    let protocol = if from.is_ipv4() { ICMP } else { ICMPV6 };
    let mut icmp = Vec::with_capacity(data.len().checked_add(8)?);
    icmp.extend_from_slice(&[kind, 0, 0, 0]);
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(data);
    assemble(from, to, protocol, icmp, 2)
}

/// Gives `packet`, an IPv4 or IPv6 packet the engine built, the hop limit `hops`: the one its answer
/// arrived with, which reaches the app as it would without the network part (ADR 0044, unit 11b). IPv4's header
/// checksum is made anew. A packet too short for its header is left as it is.
pub fn set_hops(packet: &mut [u8], hops: u8) {
    match packet.first().map(|first| first >> 4) {
        Some(4) => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || packet.len() < header {
                return;
            }
            packet[8] = hops;
            packet[10..12].fill(0);
            let checksum = header_checksum(&packet[..header]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(6) if packet.len() >= 40 => packet[7] = hops,
        _ => {}
    }
}

/// The unspecified address of the same version as `address`.
#[must_use]
pub fn unspecified_like(address: &SocketAddr) -> SocketAddr {
    if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};

    const APP4: [u8; 4] = [10, 215, 173, 1];
    const SERVER4: [u8; 4] = [93, 184, 216, 34];
    const APP6: [u16; 8] = [0xfd7a, 0x6470, 0x7761, 0, 0, 0, 0, 1];
    const SERVER6: [u16; 8] = [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x34];

    fn v6(words: [u16; 8]) -> [u8; 16] {
        Ipv6Addr::from(words).octets()
    }

    fn syn4() -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .tcp(40_000, 443, 1, 65_535)
            .syn()
            .write(&mut packet, &[])
            .unwrap_or_default();
        packet
    }

    /// Whether every checksum of `packet` is right, by etherparse's own computation.
    fn checksums_valid(packet: &[u8]) -> bool {
        let Ok(sliced) = SlicedPacket::from_ip(packet) else {
            return false;
        };
        match (sliced.net, sliced.transport) {
            (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Tcp(tcp))) => {
                let header = ip.header().to_header();
                header.calc_header_checksum() == header.header_checksum
                    && tcp
                        .to_header()
                        .calc_checksum_ipv4(&header, tcp.payload())
                        .ok()
                        == Some(tcp.checksum())
            }
            (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Tcp(tcp))) => {
                tcp.to_header()
                    .calc_checksum_ipv6(&ip.header().to_header(), tcp.payload())
                    .ok()
                    == Some(tcp.checksum())
            }
            (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp))) => {
                let header = ip.header().to_header();
                header.calc_header_checksum() == header.header_checksum
                    && udp
                        .to_header()
                        .calc_checksum_ipv4(&header, udp.payload())
                        .ok()
                        == Some(udp.checksum())
            }
            (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Udp(udp))) => {
                udp.to_header()
                    .calc_checksum_ipv6(&ip.header().to_header(), udp.payload())
                    .ok()
                    == Some(udp.checksum())
            }
            (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Icmpv4(icmp))) => {
                let header = ip.header().to_header();
                header.calc_header_checksum() == header.header_checksum
                    && icmp.header().icmp_type.calc_checksum(icmp.payload()) == icmp.checksum()
            }
            (Some(NetSlice::Ipv6(ip)), Some(TransportSlice::Icmpv6(icmp))) => {
                let header = ip.header().to_header();
                icmp.header()
                    .icmp_type
                    .calc_checksum(header.source, header.destination, icmp.payload())
                    .ok()
                    == Some(icmp.checksum())
            }
            _ => false,
        }
    }

    #[test]
    fn reads_tcp_and_udp_of_both_versions() {
        let parsed = parse(&syn4());
        assert_eq!(
            parsed.map(|p| (p.protocol, p.transport, p.source, p.destination)),
            Ok((
                TCP,
                20,
                SocketAddr::from((APP4, 40_000)),
                SocketAddr::from((SERVER4, 443))
            ))
        );

        let mut packet = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6(SERVER6), 64)
            .udp(5353, 53)
            .write(&mut packet, b"query")
            .unwrap_or_default();
        let parsed = parse(&packet);
        assert_eq!(parsed.map(|p| (p.protocol, p.transport)), Ok((UDP, 40)));
        assert_eq!(
            parsed.ok().and_then(|p| udp_payload(&packet, &p)),
            Some(&b"query"[..])
        );
    }

    #[test]
    fn follows_ipv6_extension_headers_and_skips_fragments() {
        // A destination-options header (8 bytes) between the IPv6 header and TCP.
        let mut packet = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6(SERVER6), 64)
            .tcp(40_000, 443, 1, 100)
            .syn()
            .write(&mut packet, &[])
            .unwrap_or_default();
        let tcp = packet.split_off(40);
        packet[6] = 60;
        packet[4..6].copy_from_slice(&u16::try_from(tcp.len() + 8).unwrap_or(0).to_be_bytes());
        packet.extend_from_slice(&[TCP, 0, 1, 4, 0, 0, 0, 0]);
        packet.extend_from_slice(&tcp);
        assert_eq!(parse(&packet).map(|p| p.transport), Ok(48));

        // The same with a fragment header that says more fragments follow.
        packet[40..48].copy_from_slice(&[TCP, 0, 0, 1, 0, 0, 0, 7]);
        packet[6] = 44;
        assert_eq!(parse(&packet), Err(Skip::Fragment));

        let mut fragment = syn4();
        fragment[6] = 0x20;
        assert_eq!(parse(&fragment), Err(Skip::Fragment));
    }

    #[test]
    fn refuses_what_does_not_fit() {
        let packet = syn4();
        for cut in 0..packet.len() {
            assert!(parse(&packet[..cut]).is_err(), "cut at {cut}");
        }
        let mut bad = packet.clone();
        bad[0] = 0x44;
        assert_eq!(parse(&bad), Err(Skip::Malformed));
        let mut icmp = packet;
        icmp[9] = ICMP;
        assert_eq!(parse(&icmp), Err(Skip::Other(ICMP)));
    }

    #[test]
    fn rewrites_ends_with_valid_checksums() {
        let mut packet = syn4();
        let Ok(parsed) = parse(&packet) else {
            unreachable!("not parsed")
        };
        let fake = SocketAddr::from(([10, 215, 173, 2], 10_000));
        let listener = SocketAddr::from((APP4, 5555));
        assert!(set_ends(&mut packet, &parsed, fake, listener).is_some());
        assert_eq!(
            parse(&packet).map(|p| (p.source, p.destination)),
            Ok((fake, listener))
        );
        assert!(checksums_valid(&packet));
        assert!(
            set_ends(
                &mut packet,
                &parsed,
                fake,
                SocketAddr::from((Ipv6Addr::LOCALHOST, 1))
            )
            .is_none()
        );

        let mut datagram = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6(SERVER6), 64)
            .udp(5353, 443)
            .write(&mut datagram, b"quic")
            .unwrap_or_default();
        let Ok(parsed) = parse(&datagram) else {
            unreachable!("not parsed")
        };
        let to = SocketAddr::from((v6(SERVER6), 8443));
        assert!(
            set_ends(
                &mut datagram,
                &parsed,
                SocketAddr::from((v6(APP6), 6000)),
                to
            )
            .is_some()
        );
        assert!(checksums_valid(&datagram));
    }

    #[test]
    fn builds_resets_datagrams_and_icmp_errors_that_check_out() {
        let app = SocketAddr::from((APP4, 40_000));
        let server = SocketAddr::from((SERVER4, 443));
        let reset = tcp_reset(server, app, 0, Some(2)).unwrap_or_default();
        assert!(checksums_valid(&reset));
        let Ok(parsed) = parse(&reset) else {
            unreachable!("not parsed")
        };
        assert_eq!(
            (
                parsed.source,
                parsed.destination,
                tcp_flags(&reset, &parsed)
            ),
            (server, app, RST | ACK)
        );
        assert_eq!(tcp_acknowledgement(&reset, &parsed), 2);

        let app6 = SocketAddr::from((v6(APP6), 5353));
        let server6 = SocketAddr::from((v6(SERVER6), 53));
        let answer = udp(server6, app6, b"answer").unwrap_or_default();
        assert!(checksums_valid(&answer));
        assert!(udp(server, app, &vec![0; 70_000]).is_none());

        let mut query = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .udp(5353, 53)
            .write(&mut query, b"query")
            .unwrap_or_default();
        let Ok(parsed) = parse(&query) else {
            unreachable!("not parsed")
        };
        let error = unreachable(&query, &parsed, Unreachable::Port).unwrap_or_default();
        assert!(checksums_valid(&error));
        assert_eq!(&error[20..22], &[3, 3]);
        assert_eq!(&error[28..], &query[..]);

        let mut query6 = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6(SERVER6), 64)
            .udp(5353, 53)
            .write(&mut query6, b"query")
            .unwrap_or_default();
        let Ok(parsed) = parse(&query6) else {
            unreachable!("not parsed")
        };
        let error6 = unreachable(&query6, &parsed, Unreachable::Host).unwrap_or_default();
        assert!(checksums_valid(&error6));
        assert_eq!(&error6[40..42], &[1, 3]);
    }

    /// A router's "time exceeded" and an unreachable with its code, in IPv4 and IPv6, from the router,
    /// check out, quote what they were given, and come from no address an error may not come from; the
    /// app's echo request rebuilt for such a quote reads back as the request it was (ADR 0044, unit
    /// 11b).
    #[test]
    fn errors_from_the_path_and_the_requests_they_quote_check_out() {
        let router4 = IpAddr::from([192, 0, 2, 1]);
        let router6 = IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        let (app4, app6) = (IpAddr::from(APP4), IpAddr::from(v6(APP6)));
        for (router, app, server, header, exceeded) in [
            (router4, app4, IpAddr::from(SERVER4), 20, (11, 0)),
            (router6, app6, IpAddr::from(v6(SERVER6)), 40, (3, 0)),
        ] {
            let request = echo_request_of(app, server, 0x4242, 9, b"echoed").unwrap_or_default();
            assert!(checksums_valid(&request));
            assert_eq!(
                echo_request(&request).map(|r| (r.source, r.destination, r.id, r.sequence)),
                Ok((app, server, 0x4242, 9))
            );
            let error = path_error(&request, (router, app), exceeded, [0; 4]).unwrap_or_default();
            assert!(checksums_valid(&error));
            assert_eq!((error[header], error[header + 1]), exceeded);
            assert_eq!(&error[header + 8..], &request[..]);
            let unreachable =
                path_error(&request, (router, app), (exceeded.0, 0), [0; 4]).unwrap_or_default();
            assert!(checksums_valid(&unreachable));
            let multicast = if app.is_ipv4() {
                IpAddr::from([224, 0, 0, 1])
            } else {
                IpAddr::from([0xff02, 0, 0, 0, 0, 0, 0, 1])
            };
            assert_eq!(
                path_error(&request, (multicast, app), exceeded, [0; 4]),
                None
            );
        }
        assert_eq!(path_error(&[], (router4, app6), (3, 0), [0; 4]), None);
    }

    /// An app's echo request, as its ping socket's kernel sends it into the tunnel.
    fn ping4(id: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv4(APP4, SERVER4, 64)
            .icmpv4_echo_request(id, sequence)
            .write(&mut packet, data)
            .unwrap_or_default();
        packet
    }

    fn ping6(id: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6(SERVER6), 64)
            .icmpv6_echo_request(id, sequence)
            .write(&mut packet, data)
            .unwrap_or_default();
        packet
    }

    /// A packet the engine built takes the hop limit its answer arrived with, IPv4's with its header
    /// checksum made anew, as an independent reader checks; one too short is left as it is.
    #[test]
    fn a_built_packet_takes_the_hop_limit_its_answer_came_with() {
        for (from, to) in [
            (
                SocketAddr::from((SERVER4, 53)),
                SocketAddr::from((APP4, 40_000)),
            ),
            (
                SocketAddr::from((v6(SERVER6), 53)),
                SocketAddr::from((v6(APP6), 40_000)),
            ),
        ] {
            let mut answer = udp(from, to, b"an answer").unwrap_or_default();
            set_hops(&mut answer, 7);
            let Ok(sliced) = SlicedPacket::from_ip(&answer) else {
                unreachable!("not read back")
            };
            match sliced.net {
                Some(NetSlice::Ipv4(ip)) => {
                    assert_eq!(ip.header().ttl(), 7);
                    let header = ip.header().to_header();
                    assert_eq!(header.header_checksum, header.calc_header_checksum());
                }
                Some(NetSlice::Ipv6(ip)) => assert_eq!(ip.header().hop_limit(), 7),
                _ => unreachable!("no IP header"),
            }
            assert_eq!(parse(&answer).map(|p| p.hops), Ok(7));
        }
        let mut short = vec![0x45, 0, 0, 20];
        set_hops(&mut short, 7);
        assert_eq!(short, [0x45, 0, 0, 20]);
    }

    #[test]
    fn reads_echo_requests_of_both_versions() {
        let request = ping4(0x1234, 7, b"ping data");
        assert_eq!(
            echo_request(&request),
            Ok(Echo {
                icmp: 20,
                length: request.len(),
                source: IpAddr::from(APP4),
                destination: IpAddr::from(SERVER4),
                id: 0x1234,
                sequence: 7,
                hops: 64,
            })
        );
        // A TCP or UDP reader gives it up as ICMP, as before.
        assert_eq!(parse(&request), Err(Skip::Other(ICMP)));

        let mut request6 = ping6(0xbeef, 65_535, b"ping data");
        assert_eq!(
            echo_request(&request6),
            Ok(Echo {
                icmp: 40,
                length: request6.len(),
                source: IpAddr::from(v6(APP6)),
                destination: IpAddr::from(v6(SERVER6)),
                id: 0xbeef,
                sequence: 65_535,
                hops: 64,
            })
        );
        // Padding after the IP packet's own length is not part of it.
        request6.extend_from_slice(&[0; 6]);
        assert_eq!(
            echo_request(&request6).map(|e| e.length),
            Ok(request6.len() - 6)
        );
    }

    #[test]
    fn refuses_an_echo_request_whose_checksum_is_wrong() {
        let mut request = ping4(1, 1, b"data");
        let last = request.len() - 1;
        request[last] ^= 0x01;
        assert_eq!(echo_request(&request), Err(Skip::Malformed));

        // ICMPv6's checksum covers the addresses too: the same message to another address fails.
        let mut request6 = ping6(1, 1, b"data");
        assert!(echo_request(&request6).is_ok());
        request6[39] ^= 0x01;
        assert_eq!(echo_request(&request6), Err(Skip::Malformed));

        for cut in 0..ping4(1, 1, b"").len() {
            let mut short = ping4(1, 1, b"");
            short.truncate(cut);
            if let Some(length) = short.get_mut(2..4) {
                length.copy_from_slice(&u16::try_from(cut).unwrap_or(0).to_be_bytes());
            }
            assert!(echo_request(&short).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn other_icmp_from_apps_is_still_skipped() {
        let app = SocketAddr::from((APP4, 40_000));
        let server = SocketAddr::from((SERVER4, 53));
        let datagram = udp(app, server, b"query").unwrap_or_default();
        let Ok(parsed) = parse(&datagram) else {
            unreachable!("not parsed")
        };
        // An app's kernel saying a port is closed, and an echo reply, which no app sends to be carried.
        let error = unreachable(&datagram, &parsed, Unreachable::Port).unwrap_or_default();
        assert_eq!(echo_request(&error), Err(Skip::Other(ICMP)));
        let reply =
            echo_reply(IpAddr::from(APP4), IpAddr::from(SERVER4), 1, 1, b"").unwrap_or_default();
        assert_eq!(echo_request(&reply), Err(Skip::Other(ICMP)));
        // An echo request with a code other than 0.
        let mut coded = ping4(1, 1, b"");
        coded[21] = 1;
        assert_eq!(echo_request(&coded), Err(Skip::Other(ICMP)));
        // A neighbour solicitation, and ICMP's echo request inside IPv6 rather than ICMPv6's.
        let mut solicitation = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6(SERVER6), 255)
            .icmpv6_raw(135, 0, [0; 4])
            .write(&mut solicitation, &[0; 16])
            .unwrap_or_default();
        assert_eq!(echo_request(&solicitation), Err(Skip::Other(ICMPV6)));
        let mut wrong_version = ping6(1, 1, b"");
        wrong_version[6] = ICMP;
        assert_eq!(echo_request(&wrong_version), Err(Skip::Other(ICMP)));
        // UDP and TCP are no echo.
        assert_eq!(echo_request(&datagram), Err(Skip::Other(UDP)));
        assert_eq!(echo_request(&syn4()), Err(Skip::Other(TCP)));
    }

    #[test]
    fn a_rebuilt_reply_bears_the_apps_id_and_checks_out() {
        use etherparse::{IcmpEchoHeader, Icmpv4Type, Icmpv6Type};
        let data = b"the request's own data, a time stamp among it";
        let reply = echo_reply(IpAddr::from(SERVER4), IpAddr::from(APP4), 0x1234, 7, data)
            .unwrap_or_default();
        assert!(checksums_valid(&reply));
        let Ok(SlicedPacket {
            net: Some(NetSlice::Ipv4(ip)),
            transport: Some(TransportSlice::Icmpv4(icmp)),
            ..
        }) = SlicedPacket::from_ip(&reply)
        else {
            unreachable!("not an ICMP packet: {reply:?}")
        };
        assert_eq!(
            (
                ip.header().source(),
                ip.header().destination(),
                ip.header().ttl()
            ),
            (SERVER4, APP4, 64)
        );
        assert_eq!(
            icmp.icmp_type(),
            Icmpv4Type::EchoReply(IcmpEchoHeader { id: 0x1234, seq: 7 })
        );
        assert_eq!(icmp.payload(), data);

        let reply6 = echo_reply(
            IpAddr::from(v6(SERVER6)),
            IpAddr::from(v6(APP6)),
            0xbeef,
            9,
            data,
        )
        .unwrap_or_default();
        assert!(checksums_valid(&reply6));
        let Ok(SlicedPacket {
            net: Some(NetSlice::Ipv6(ip)),
            transport: Some(TransportSlice::Icmpv6(icmp)),
            ..
        }) = SlicedPacket::from_ip(&reply6)
        else {
            unreachable!("not an ICMPv6 packet: {reply6:?}")
        };
        assert_eq!(
            (
                ip.header().source(),
                ip.header().destination(),
                ip.header().hop_limit()
            ),
            (v6(SERVER6), v6(APP6), 64)
        );
        assert_eq!(
            icmp.icmp_type(),
            Icmpv6Type::EchoReply(IcmpEchoHeader { id: 0xbeef, seq: 9 })
        );
        assert_eq!(icmp.payload(), data);
        assert!(echo_reply(IpAddr::from(SERVER4), IpAddr::from(v6(APP6)), 1, 1, data).is_none());
    }

    #[test]
    fn a_refused_echo_is_answered_administratively_prohibited() {
        let request = ping4(0x1234, 7, b"ping data");
        let Ok(echo) = echo_request(&request) else {
            unreachable!("not read")
        };
        let error = echo_refused(&request, &echo).unwrap_or_default();
        assert!(checksums_valid(&error));
        // From the address pinged to the app, type 3 code 13, quoting the whole request.
        assert_eq!((&error[12..16], &error[16..20]), (&SERVER4[..], &APP4[..]));
        assert_eq!(&error[20..22], &[3, 13]);
        assert_eq!(&error[28..], &request[..]);

        let request6 = ping6(0xbeef, 9, b"ping data");
        let Ok(echo6) = echo_request(&request6) else {
            unreachable!("not read")
        };
        let error6 = echo_refused(&request6, &echo6).unwrap_or_default();
        assert!(checksums_valid(&error6));
        assert_eq!(
            (&error6[8..24], &error6[24..40]),
            (&v6(SERVER6)[..], &v6(APP6)[..])
        );
        assert_eq!(&error6[40..42], &[1, 1]);
        assert_eq!(&error6[48..], &request6[..]);
        // No error answers a request to a multicast or broadcast address.
        for to in [[224, 0, 0, 1], [255, 255, 255, 255], [0, 0, 0, 0]] {
            let mut request = Vec::new();
            PacketBuilder::ipv4(APP4, to, 64)
                .icmpv4_echo_request(1, 1)
                .write(&mut request, b"")
                .unwrap_or_default();
            let Ok(echo) = echo_request(&request) else {
                unreachable!("not read: {to:?}")
            };
            assert_eq!(echo_refused(&request, &echo), None, "to {to:?}");
        }
        let mut all_nodes = Vec::new();
        PacketBuilder::ipv6(v6(APP6), v6([0xff02, 0, 0, 0, 0, 0, 0, 1]), 64)
            .icmpv6_echo_request(1, 1)
            .write(&mut all_nodes, b"")
            .unwrap_or_default();
        let Ok(echo) = echo_request(&all_nodes) else {
            unreachable!("not read")
        };
        assert_eq!(echo_refused(&all_nodes, &echo), None);
    }
}
