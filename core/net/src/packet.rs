//! IP packets as they come from and go to the tunnel: the parts the engine reads, the rewriting of
//! addresses and ports with incremental checksums (RFC 1624), and the few packets the engine builds
//! itself: TCP resets, UDP datagrams, and ICMP and `ICMPv6` errors.
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

/// The hop limit of packets the engine builds.
const HOPS: u8 = 64;
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
}

/// Why a packet is not one the engine forwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// Too short, a wrong version, or lengths that do not fit.
    Malformed,
    /// A fragment. Apps' traffic through a tunnel with a 1500-byte MTU is rarely fragmented.
    Fragment,
    /// Another protocol, by its number: ICMP, for example.
    Other(u8),
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(at)?,
        *bytes.get(at.checked_add(1)?)?,
    ]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Reads a TCP or UDP packet from the tunnel.
///
/// # Errors
/// [`Skip`] says why the packet is not one the engine forwards.
pub fn parse(packet: &[u8]) -> Result<Packet, Skip> {
    let first = *packet.first().ok_or(Skip::Malformed)?;
    let (protocol, transport, length, source, destination) = match first >> 4 {
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
            )
        }
        _ => return Err(Skip::Malformed),
    };
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
    })
}

/// Follows IPv6 extension headers to the upper-layer protocol and where its header starts.
fn ipv6_transport(packet: &[u8]) -> Result<(u8, usize), Skip> {
    let mut next = packet[6];
    let mut at = 40;
    for _ in 0..MAX_EXTENSIONS {
        let length = match next {
            // Hop-by-hop options, routing, destination options: (length + 1) * 8 bytes.
            0 | 43 | 60 => (usize::from(*packet.get(at + 1).ok_or(Skip::Malformed)?) + 1) * 8,
            // Fragment: 8 bytes, with the offset and the "more" flag.
            44 => {
                let field = u16_at(packet, at + 2).ok_or(Skip::Malformed)?;
                if field & 0xfff9 != 0 {
                    return Err(Skip::Fragment);
                }
                8
            }
            // Authentication header: (length + 2) * 4 bytes.
            51 => (usize::from(*packet.get(at + 1).ok_or(Skip::Malformed)?) + 2) * 4,
            protocol => return Ok((protocol, at)),
        };
        next = *packet.get(at).ok_or(Skip::Malformed)?;
        at += length;
        if at > packet.len() {
            return Err(Skip::Malformed);
        }
    }
    Err(Skip::Malformed)
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

fn octets(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// RFC 1624: the one's-complement checksum after the 16-bit words `old` became `new`.
fn adjust(checksum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!checksum);
    for (o, n) in old.as_chunks::<2>().0.iter().zip(new.as_chunks::<2>().0) {
        sum += u32::from(!u16::from_be_bytes([o[0], o[1]]));
        sum += u32::from(u16::from_be_bytes([n[0], n[1]]));
    }
    !fold(sum)
}

fn fold(mut sum: u32) -> u16 {
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
    let old = [
        packet.get(source_at..source_at + size)?,
        packet.get(destination_at..destination_at + size)?,
        packet.get(ports..ports + 4)?,
    ]
    .concat();
    let new = [
        octets(source.ip()),
        octets(destination.ip()),
        source.port().to_be_bytes().to_vec(),
        destination.port().to_be_bytes().to_vec(),
    ]
    .concat();
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
        let mut adjusted = adjust(checksum, &old, &new);
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
fn pseudo_sum(from: IpAddr, to: IpAddr, protocol: u8, length: usize) -> u32 {
    let mut sum = sum_words(&octets(from)) + sum_words(&octets(to));
    sum += u32::from(protocol);
    let length = u32::try_from(length).unwrap_or(u32::MAX);
    sum += (length >> 16) + (length & 0xffff);
    sum
}

fn sum_words(bytes: &[u8]) -> u32 {
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
}

/// An ICMP (IPv4) or `ICMPv6` "destination unreachable" for the app's packet `original`, sent as if
/// by its destination, quoting as much of the original as the minimum MTU allows (RFC 1812 4.3.2.3,
/// RFC 4443 2.4).
#[must_use]
pub fn unreachable(original: &[u8], parsed: &Packet, reason: Unreachable) -> Option<Vec<u8>> {
    let quoted = original.get(..parsed.length)?;
    let (from, to) = (parsed.destination.ip(), parsed.source.ip());
    if from.is_ipv4() {
        let code = match reason {
            Unreachable::Host => 1,
            Unreachable::Port => 3,
        };
        let mut icmp = vec![3, code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quoted[..quoted.len().min(576 - 20 - 8)]);
        assemble(from, to, ICMP, icmp, 2)
    } else {
        let code = match reason {
            Unreachable::Host => 3,
            Unreachable::Port => 4,
        };
        let mut icmp = vec![1, code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&quoted[..quoted.len().min(1280 - 40 - 8)]);
        assemble(from, to, ICMPV6, icmp, 2)
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
}
