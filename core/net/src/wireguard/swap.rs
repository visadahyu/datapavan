//! The address swap of ADR 0035's option 3: a chosen app's packet leaves with the configuration's
//! address as its source, and what comes back gets the tunnel's address again, each checksum updated
//! incrementally (RFC 1624), as a basic NAT does (RFC 3022); an ICMP error has its quoted packet swapped
//! too (RFC 5508). Ports are never changed: each app socket on the tunnel's address has its own, and the
//! configuration's address is this phone's alone. A tunnelled SYN's MSS is clamped to the tunnel's MTU.
//!
//! TCP and UDP take [`crate::packet::set_ends`], the swap the system stack already makes; this module adds
//! what an echo, an error and the back path need. Every function reads bytes a peer chose, bounded by
//! what the packet holds, and changes nothing when it cannot read them.

use crate::packet::{
    self, Echo, ICMP, ICMPV6, Packet, Skip, TCP, UDP, adjust, fold, pseudo_sum, sum_words, u16_at,
};
use std::net::{IpAddr, SocketAddr};

/// ICMP's error types (RFC 792): destination unreachable, source quench, redirect, time exceeded,
/// parameter problem. A redirect is not passed on: no one routes the app by it.
const ERRORS_V4: [u8; 3] = [3, 11, 12];
/// `ICMPv6`'s (RFC 4443): destination unreachable, packet too big, time exceeded, parameter problem.
const ERRORS_V6: [u8; 4] = [1, 2, 3, 4];

/// An ICMP or `ICMPv6` error, as the back path reads it: who sent it, and the packet it quotes, which
/// went into the tunnel from the configuration's address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpError {
    /// Where the ICMP header starts.
    pub icmp: usize,
    /// The packet's length by its IP header.
    pub length: usize,
    /// Who sent the error: a router, or the server.
    pub source: IpAddr,
    /// To whom: the configuration's address.
    pub destination: IpAddr,
    /// Where the quoted IP header starts.
    pub inner: usize,
    /// Where the quoted transport header starts.
    pub inner_transport: usize,
    /// The quoted packet's protocol.
    pub protocol: u8,
    /// The quoted packet's source, and its port, or for an echo request its identifier.
    pub from: SocketAddr,
    /// The quoted packet's destination, and its port, or 0 for an echo request.
    pub to: SocketAddr,
}

/// A packet back from the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Back {
    /// TCP or UDP.
    Transport(Packet),
    /// An echo reply: its identifier is the app's, its source the address the app pinged.
    EchoReply(Echo),
    /// An error about a packet that went into the tunnel.
    Error(IcmpError),
    /// Anything else, which no app asked for: an echo request from outside among it.
    Other,
}

/// Reads a packet the tunnel decrypted.
#[must_use]
pub fn read(packet: &[u8]) -> Back {
    match packet::parse(packet) {
        Ok(parsed) => Back::Transport(parsed),
        Err(Skip::Other(ICMP | ICMPV6)) => icmp(packet).unwrap_or(Back::Other),
        Err(_) => Back::Other,
    }
}

/// An echo reply or an error, else `None`.
fn icmp(packet: &[u8]) -> Option<Back> {
    let ip = packet::ip(packet).ok()?;
    let message = packet.get(ip.transport..ip.length)?;
    let (&kind, id, sequence) = (message.first()?, u16_at(message, 4)?, u16_at(message, 6)?);
    let v4 = ip.source.is_ipv4();
    let reply = if v4 {
        packet::ECHO_REPLY
    } else {
        packet::ECHO_REPLY_V6
    };
    if kind == reply && message.get(1) == Some(&0) {
        return Some(Back::EchoReply(Echo {
            icmp: ip.transport,
            length: ip.length,
            source: ip.source,
            destination: ip.destination,
            id,
            sequence,
            hops: ip.hops,
        }));
    }
    let error = if v4 {
        ERRORS_V4.contains(&kind)
    } else {
        ERRORS_V6.contains(&kind)
    };
    if !error {
        return None;
    }
    let inner = ip.transport + 8;
    let quoted = packet.get(inner..ip.length)?;
    let (protocol, transport, from, to) = quoted_ends(quoted, v4)?;
    let inner_transport = inner + transport;
    // An echo request is matched by its identifier, which the quote holds where its port would be.
    let (from_port, to_port) = match protocol {
        TCP | UDP => (
            u16_at(packet, inner_transport)?,
            u16_at(packet, inner_transport + 2)?,
        ),
        ICMP | ICMPV6 => {
            let request = if v4 {
                packet::ECHO_REQUEST
            } else {
                packet::ECHO_REQUEST_V6
            };
            if packet.get(inner_transport) != Some(&request) {
                return None;
            }
            (u16_at(packet, inner_transport + 4)?, 0)
        }
        _ => return None,
    };
    Some(Back::Error(IcmpError {
        icmp: ip.transport,
        length: ip.length,
        source: ip.source,
        destination: ip.destination,
        inner,
        inner_transport,
        protocol,
        from: SocketAddr::new(from, from_port),
        to: SocketAddr::new(to, to_port),
    }))
}

/// The protocol, where the transport header starts, and the addresses of a quoted packet of the version
/// `v4`, which may be cut short after its first eight transport bytes (RFC 792).
fn quoted_ends(quoted: &[u8], v4: bool) -> Option<(u8, usize, IpAddr, IpAddr)> {
    let first = *quoted.first()?;
    if v4 {
        if first >> 4 != 4 {
            return None;
        }
        let header = usize::from(first & 0x0f) * 4;
        if header < 20 || quoted.len() < header + 8 {
            return None;
        }
        let from: [u8; 4] = quoted.get(12..16)?.try_into().ok()?;
        let to: [u8; 4] = quoted.get(16..20)?.try_into().ok()?;
        Some((quoted[9], header, IpAddr::from(from), IpAddr::from(to)))
    } else {
        if first >> 4 != 6 || quoted.len() < 48 {
            return None;
        }
        let from: [u8; 16] = quoted.get(8..24)?.try_into().ok()?;
        let to: [u8; 16] = quoted.get(24..40)?.try_into().ok()?;
        // No extension headers are followed in a quote: the network part's own packets into the tunnel carry none
        // but a fragment header, whose quote names no port to match by.
        Some((quoted[6], 40, IpAddr::from(from), IpAddr::from(to)))
    }
}

/// Where an address of the version `v4` starts in an IP header: the source's, the destination's, and
/// its length.
fn address_at(v4: bool) -> (usize, usize, usize) {
    if v4 { (12, 16, 4) } else { (8, 24, 16) }
}

fn octets(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// Writes `addresses` into the IP header at `at` in `packet`, and updates IPv4's header checksum and, for
/// each of `checksums` (offsets of transport checksums that cover a pseudo-header), the checksum there:
/// the old addresses' words out, the new ones' in (RFC 1624). An IPv4 UDP checksum of 0 stays 0. `None`,
/// changing nothing, when the packet is too short or a version differs.
fn rewrite(
    packet: &mut [u8],
    at: usize,
    (source, destination): (IpAddr, IpAddr),
    checksums: &[(usize, bool)],
) -> Option<()> {
    let v4 = packet.get(at)? >> 4 == 4;
    if source.is_ipv4() != v4 || destination.is_ipv4() != v4 {
        return None;
    }
    let (from_at, to_at, size) = address_at(v4);
    let old = packet.get(at + from_at..at + to_at + size)?.to_vec();
    let mut new = octets(source);
    new.extend_from_slice(&octets(destination));
    if checksums
        .iter()
        .any(|&(at, _)| u16_at(packet, at).is_none())
    {
        return None;
    }
    packet
        .get_mut(at + from_at..at + to_at + size)?
        .copy_from_slice(&new);
    if v4 {
        let header = u16_at(packet, at + 10)?;
        packet
            .get_mut(at + 10..at + 12)?
            .copy_from_slice(&adjust(header, &old, &new).to_be_bytes());
    }
    for &(checksum_at, udp) in checksums {
        let checksum = u16_at(packet, checksum_at)?;
        if udp && v4 && checksum == 0 {
            continue;
        }
        let mut adjusted = adjust(checksum, &old, &new);
        if udp && adjusted == 0 {
            adjusted = 0xffff;
        }
        packet
            .get_mut(checksum_at..checksum_at + 2)?
            .copy_from_slice(&adjusted.to_be_bytes());
    }
    Some(())
}

/// Gives a TCP or UDP packet the addresses `source` and `destination`, its ports kept.
pub fn swap(packet: &mut [u8], parsed: &Packet, source: IpAddr, destination: IpAddr) -> Option<()> {
    packet::set_ends(
        packet,
        parsed,
        SocketAddr::new(source, parsed.source.port()),
        SocketAddr::new(destination, parsed.destination.port()),
    )
}

/// Gives an echo request or reply the addresses `source` and `destination`. ICMP's checksum covers its
/// message alone, `ICMPv6`'s a pseudo-header too (RFC 4443 2.3), which is updated with it.
pub fn swap_echo(
    packet: &mut [u8],
    echo: &Echo,
    source: IpAddr,
    destination: IpAddr,
) -> Option<()> {
    let checksums: &[(usize, bool)] = if echo.source.is_ipv4() {
        &[]
    } else {
        &[(echo.icmp + 2, false)]
    };
    rewrite(packet, 0, (source, destination), checksums)
}

/// Swaps an error from the tunnel back to the app (RFC 5508): its destination becomes `destination`, and
/// the packet it quotes gets `quoted`, its source and destination as the app sent it. The quoted IPv4
/// header's checksum and the quoted transport checksum, where the quote holds it, are updated as a NAT
/// updates them; the error's own checksum is made anew over what it now holds. `None`, changing nothing,
/// when the packet does not hold what the error says.
pub fn swap_error(
    packet: &mut [u8],
    error: &IcmpError,
    destination: IpAddr,
    quoted: (IpAddr, IpAddr),
) -> Option<()> {
    let v4 = error.source.is_ipv4();
    if destination.is_ipv4() != v4 || quoted.0.is_ipv4() != v4 || quoted.1.is_ipv4() != v4 {
        return None;
    }
    if error.length > packet.len() || error.inner_transport > error.length {
        return None;
    }
    let end = error.length;
    let inner_checksum = match error.protocol {
        TCP => Some((error.inner_transport + 16, false)),
        UDP => Some((error.inner_transport + 6, true)),
        ICMPV6 => Some((error.inner_transport + 2, false)),
        _ => None,
    }
    .filter(|&(at, _)| at + 2 <= end);
    let inner: Vec<(usize, bool)> = inner_checksum.into_iter().collect();
    rewrite(&mut packet[..end], error.inner, quoted, &inner)?;
    rewrite(&mut packet[..end], 0, (error.source, destination), &[])?;
    // The error's own checksum, anew: what it quotes changed.
    let message = error.icmp;
    packet.get_mut(message + 2..message + 4)?.fill(0);
    let pseudo = if v4 {
        0
    } else {
        pseudo_sum(error.source, destination, ICMPV6, end - message)
    };
    let checksum = !fold(pseudo + sum_words(packet.get(message..end)?));
    packet
        .get_mut(message + 2..message + 4)?
        .copy_from_slice(&checksum.to_be_bytes());
    Some(())
}

/// The largest MSS a SYN into the tunnel may announce, for the tunnel's MTU `mtu`: the IP and TCP
/// headers off, 40 bytes in IPv4, 60 in IPv6 (RFC 879, RFC 8200).
#[must_use]
pub fn largest_mss(mtu: u16, v4: bool) -> u16 {
    mtu.saturating_sub(if v4 { 40 } else { 60 })
}

/// Lowers the MSS option of a TCP SYN to `largest` where it announces more, the checksum updated
/// incrementally: whether it changed it. A SYN without the option announces 536 or 1,220 bytes (RFC
/// 9293 3.7.1), below any tunnel's MTU here, and is left as it is.
pub fn clamp_mss(packet: &mut [u8], parsed: &Packet, largest: u16) -> bool {
    let Some(&offset) = packet.get(parsed.transport + 12) else {
        return false;
    };
    let end = (parsed.transport + usize::from(offset >> 4) * 4).min(parsed.length);
    let mut at = parsed.transport + 20;
    while at < end {
        match packet.get(at) {
            None | Some(0) => return false,
            Some(1) => at += 1,
            Some(&kind) => {
                let Some(&length) = packet.get(at + 1) else {
                    return false;
                };
                let length = usize::from(length);
                if length < 2 || at + length > end {
                    return false;
                }
                if kind == 2 && length == 4 {
                    let Some(mss) = u16_at(packet, at + 2) else {
                        return false;
                    };
                    if mss <= largest {
                        return false;
                    }
                    let checksum_at = parsed.transport + 16;
                    let Some(checksum) = u16_at(packet, checksum_at) else {
                        return false;
                    };
                    // The option's word is aligned in the header only when it starts at an even offset
                    // from the TCP header; the sum is over 16-bit words from there.
                    let word = at + 2 - parsed.transport;
                    let new = largest.to_be_bytes();
                    let adjusted = if word.is_multiple_of(2) {
                        adjust(checksum, &mss.to_be_bytes(), &new)
                    } else {
                        let old = [
                            packet[at + 1],
                            packet[at + 2],
                            packet[at + 3],
                            packet.get(at + 4).copied().unwrap_or(0),
                        ];
                        let changed = [packet[at + 1], new[0], new[1], old[3]];
                        adjust(checksum, &old, &changed)
                    };
                    packet[at + 2..at + 4].copy_from_slice(&new);
                    packet[checksum_at..checksum_at + 2].copy_from_slice(&adjusted.to_be_bytes());
                    return true;
                }
                at += length;
            }
        }
    }
    false
}

/// Whether a packet may not be fragmented on the way: IPv4's DF bit, and every IPv6 packet, which only
/// its sender fragments (RFC 8200 5).
#[must_use]
pub fn dont_fragment(packet: &[u8]) -> bool {
    match packet.first().map(|b| b >> 4) {
        Some(4) => packet.get(6).is_some_and(|flags| flags & 0x40 != 0),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{
        IcmpEchoHeader, Icmpv4Type, Icmpv6Type, PacketBuilder, SlicedPacket, TransportSlice,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    const TUN4: Ipv4Addr = Ipv4Addr::new(10, 1, 10, 1);
    const CONFIG4: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 2);
    const SERVER4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const ROUTER4: Ipv4Addr = Ipv4Addr::new(10, 2, 0, 1);
    const TUN6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 1);
    const CONFIG6: Ipv6Addr = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 2);
    const SERVER6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);

    fn builder(from: IpAddr, to: IpAddr) -> etherparse::PacketBuilderStep<etherparse::IpHeaders> {
        match (from, to) {
            (IpAddr::V4(f), IpAddr::V4(t)) => PacketBuilder::ipv4(f.octets(), t.octets(), 64),
            (IpAddr::V6(f), IpAddr::V6(t)) => PacketBuilder::ipv6(f.octets(), t.octets(), 64),
            _ => unreachable!("mixed versions"),
        }
    }

    fn tcp(from: IpAddr, to: IpAddr, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let built = builder(from, to)
            .tcp(40_000, 443, 7, 64_240)
            .syn()
            .options(&[etherparse::TcpOptionElement::MaximumSegmentSize(1460)]);
        let Ok(built) = built else {
            unreachable!("options")
        };
        let _ = built.write(&mut out, payload);
        out
    }

    fn udp(from: IpAddr, to: IpAddr, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = builder(from, to).udp(40_001, 53).write(&mut out, payload);
        out
    }

    fn echo(from: IpAddr, to: IpAddr, reply: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let header = IcmpEchoHeader { id: 0x1234, seq: 9 };
        let step = builder(from, to);
        let _ = match (from, reply) {
            (IpAddr::V4(_), false) => step
                .icmpv4(Icmpv4Type::EchoRequest(header))
                .write(&mut out, b"ping"),
            (IpAddr::V4(_), true) => step
                .icmpv4(Icmpv4Type::EchoReply(header))
                .write(&mut out, b"ping"),
            (IpAddr::V6(_), false) => step
                .icmpv6(Icmpv6Type::EchoRequest(header))
                .write(&mut out, b"ping"),
            (IpAddr::V6(_), true) => step
                .icmpv6(Icmpv6Type::EchoReply(header))
                .write(&mut out, b"ping"),
        };
        out
    }

    /// Whether every checksum of `packet` holds, by etherparse's own recomputation.
    fn checksums_hold(packet: &[u8]) -> bool {
        let Ok(sliced) = SlicedPacket::from_ip(packet) else {
            return false;
        };
        let header_ok = match &sliced.net {
            Some(etherparse::NetSlice::Ipv4(v4)) => {
                let header = v4.header().to_header();
                header.calc_header_checksum() == header.header_checksum
            }
            _ => true,
        };
        let (source, destination) = match &sliced.net {
            Some(etherparse::NetSlice::Ipv4(v4)) => (
                IpAddr::V4(v4.header().source_addr()),
                IpAddr::V4(v4.header().destination_addr()),
            ),
            Some(etherparse::NetSlice::Ipv6(v6)) => (
                IpAddr::V6(v6.header().source_addr()),
                IpAddr::V6(v6.header().destination_addr()),
            ),
            _ => return false,
        };
        let transport_ok = match &sliced.transport {
            Some(TransportSlice::Tcp(t)) => {
                let header = t.to_header();
                let sum = match (source, destination) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => {
                        header.calc_checksum_ipv4_raw(s.octets(), d.octets(), t.payload())
                    }
                    (IpAddr::V6(s), IpAddr::V6(d)) => {
                        header.calc_checksum_ipv6_raw(s.octets(), d.octets(), t.payload())
                    }
                    _ => return false,
                };
                sum.ok() == Some(header.checksum)
            }
            Some(TransportSlice::Udp(u)) => {
                let header = u.to_header();
                if header.checksum == 0 && source.is_ipv4() {
                    true
                } else {
                    let sum = match (source, destination) {
                        (IpAddr::V4(s), IpAddr::V4(d)) => {
                            header.calc_checksum_ipv4_raw(s.octets(), d.octets(), u.payload())
                        }
                        (IpAddr::V6(s), IpAddr::V6(d)) => {
                            header.calc_checksum_ipv6_raw(s.octets(), d.octets(), u.payload())
                        }
                        _ => return false,
                    };
                    sum.ok() == Some(header.checksum)
                }
            }
            Some(TransportSlice::Icmpv4(i)) => {
                let header = i.header();
                header.icmp_type.calc_checksum(i.payload()) == header.checksum
            }
            Some(TransportSlice::Icmpv6(i)) => {
                let header = i.header();
                let (IpAddr::V6(s), IpAddr::V6(d)) = (source, destination) else {
                    return false;
                };
                header
                    .icmp_type
                    .calc_checksum(s.octets(), d.octets(), i.payload())
                    .ok()
                    == Some(header.checksum)
            }
            _ => false,
        };
        header_ok && transport_ok
    }

    /// TCP and UDP of both versions swapped both ways keep checksums that a recomputation agrees with,
    /// and a zero IPv4 UDP checksum stays zero.
    #[test]
    fn a_swapped_packet_checks_out_against_a_recomputation() {
        let cases = [
            (IpAddr::V4(TUN4), IpAddr::V4(CONFIG4), IpAddr::V4(SERVER4)),
            (IpAddr::V6(TUN6), IpAddr::V6(CONFIG6), IpAddr::V6(SERVER6)),
        ];
        for (tun, config, server) in cases {
            for payload in [&b""[..], b"hello", b"an odd length payload!!"] {
                for mut original in [tcp(tun, server, payload), udp(tun, server, payload)] {
                    let Ok(parsed) = packet::parse(&original) else {
                        unreachable!("unparsed")
                    };
                    let kept = original.clone();
                    assert_eq!(swap(&mut original, &parsed, config, server), Some(()));
                    assert!(checksums_hold(&original), "up {tun}");
                    let Ok(parsed) = packet::parse(&original) else {
                        unreachable!("unparsed")
                    };
                    assert_eq!(parsed.source.ip(), config);
                    assert_eq!(swap(&mut original, &parsed, tun, server), Some(()));
                    assert_eq!(original, kept, "back to the same bytes");
                }
            }
        }
        let mut zero = udp(IpAddr::V4(TUN4), IpAddr::V4(SERVER4), b"x");
        let Ok(parsed) = packet::parse(&zero) else {
            unreachable!("unparsed")
        };
        zero[parsed.transport + 6..parsed.transport + 8].fill(0);
        assert_eq!(
            swap(&mut zero, &parsed, IpAddr::V4(CONFIG4), IpAddr::V4(SERVER4)),
            Some(())
        );
        assert_eq!(&zero[parsed.transport + 6..parsed.transport + 8], &[0, 0]);
        assert!(checksums_hold(&zero));
    }

    #[test]
    fn an_echo_swapped_checks_out_and_reads_back_as_a_reply() {
        for (tun, config, server) in [
            (IpAddr::V4(TUN4), IpAddr::V4(CONFIG4), IpAddr::V4(SERVER4)),
            (IpAddr::V6(TUN6), IpAddr::V6(CONFIG6), IpAddr::V6(SERVER6)),
        ] {
            let mut request = echo(tun, server, false);
            let Ok(read) = packet::echo_request(&request) else {
                unreachable!("unread")
            };
            assert_eq!(swap_echo(&mut request, &read, config, server), Some(()));
            assert!(checksums_hold(&request), "{tun}");
            assert!(packet::echo_request(&request).is_ok());
            let mut reply = echo(server, config, true);
            let Back::EchoReply(read) = super::read(&reply) else {
                unreachable!("not a reply")
            };
            assert_eq!((read.id, read.sequence, read.source), (0x1234, 9, server));
            assert_eq!(swap_echo(&mut reply, &read, server, tun), Some(()));
            assert!(checksums_hold(&reply));
            // An echo request from outside is no reply.
            assert_eq!(super::read(&echo(server, config, false)), Back::Other);
        }
    }

    /// An error about a packet that went in quotes it from the configuration's address: swapped, it
    /// quotes it as the app sent it, and every checksum holds, the quoted ones included.
    #[test]
    fn an_error_has_its_quote_swapped_as_a_nat_does() {
        for (tun, config, server, router) in [
            (
                IpAddr::V4(TUN4),
                IpAddr::V4(CONFIG4),
                IpAddr::V4(SERVER4),
                IpAddr::V4(ROUTER4),
            ),
            (
                IpAddr::V6(TUN6),
                IpAddr::V6(CONFIG6),
                IpAddr::V6(SERVER6),
                IpAddr::V6(SERVER6),
            ),
        ] {
            for sent in [
                tcp(config, server, b"data"),
                udp(config, server, b"query"),
                echo(config, server, false),
            ] {
                let kind = if tun.is_ipv4() { (3, 1) } else { (1, 3) };
                let Some(mut error) = packet::path_error(&sent, (router, config), kind, [0; 4])
                else {
                    unreachable!("no error")
                };
                let Back::Error(read) = super::read(&error) else {
                    unreachable!("not an error")
                };
                assert_eq!(read.from.ip(), config);
                assert_eq!(read.to.ip(), server);
                assert_eq!(swap_error(&mut error, &read, tun, (tun, server)), Some(()));
                let Back::Error(swapped) = super::read(&error) else {
                    unreachable!("not an error")
                };
                assert_eq!((swapped.destination, swapped.from.ip()), (tun, tun));
                assert_eq!(swapped.from.port(), read.from.port());
                assert!(checksums_hold(&error));
                // The quote's own checksums hold for what it now names.
                let quote = &error[swapped.inner..swapped.length];
                assert_eq!(quote.len(), sent.len());
                assert!(checksums_hold(quote), "{tun}");
            }
        }
    }

    /// A router's error quotes only the start of the packet: the transport checksum is updated when the
    /// quote holds it, and nothing is read past what came.
    #[test]
    fn a_short_quote_is_swapped_as_far_as_it_goes() {
        let sent = tcp(IpAddr::V4(CONFIG4), IpAddr::V4(SERVER4), &[7; 40]);
        // RFC 792's least quote: the IP header and eight bytes, which hold the ports but not the
        // checksum.
        let mut error = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
        error.extend_from_slice(&ROUTER4.octets());
        error.extend_from_slice(&CONFIG4.octets());
        error.extend_from_slice(&[11, 0, 0, 0, 0, 0, 0, 0]);
        error.extend_from_slice(&sent[..28]);
        let length = u16::try_from(error.len()).unwrap_or(0);
        error[2..4].copy_from_slice(&length.to_be_bytes());
        let Back::Error(read) = super::read(&error) else {
            unreachable!("not an error")
        };
        assert_eq!(read.from.port(), 40_000);
        assert_eq!(read.to.port(), 443);
        assert_eq!(
            swap_error(
                &mut error,
                &read,
                IpAddr::V4(TUN4),
                (IpAddr::V4(TUN4), IpAddr::V4(SERVER4))
            ),
            Some(())
        );
        assert_eq!(&error[20 + 8 + 12..20 + 8 + 16], &TUN4.octets());
        // The error's own checksum holds over what it holds.
        assert_eq!(fold(sum_words(&error[20..])), 0xffff);
        // Cut before the ports: not an error the back path can match.
        let cut = &error[..20 + 8 + 24];
        let mut cut = cut.to_vec();
        let length = u16::try_from(cut.len()).unwrap_or(0);
        cut[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(super::read(&cut), Back::Other);
    }

    /// A quoted IPv4 UDP datagram sent without a checksum keeps none once the quote is swapped: 0 means "none".
    #[test]
    fn a_quoted_udp_datagram_without_a_checksum_keeps_none() {
        let mut sent = udp(IpAddr::V4(CONFIG4), IpAddr::V4(SERVER4), b"query");
        sent[20 + 6..20 + 8].fill(0);
        let Some(mut error) = packet::path_error(
            &sent,
            (IpAddr::V4(ROUTER4), IpAddr::V4(CONFIG4)),
            (3, 3),
            [0; 4],
        ) else {
            unreachable!("no error")
        };
        let Back::Error(read) = super::read(&error) else {
            unreachable!("not an error")
        };
        let quoted_checksum = read.inner_transport + 6;
        assert_eq!(
            swap_error(
                &mut error,
                &read,
                IpAddr::V4(TUN4),
                (IpAddr::V4(TUN4), IpAddr::V4(SERVER4))
            ),
            Some(())
        );
        assert_eq!(&error[quoted_checksum..quoted_checksum + 2], &[0, 0]);
        assert_eq!(
            fold(sum_words(&error[20..])),
            0xffff,
            "the error's own checksum holds"
        );
    }

    #[test]
    fn a_redirect_and_an_echo_request_are_no_errors() {
        let sent = udp(IpAddr::V4(CONFIG4), IpAddr::V4(SERVER4), b"x");
        let Some(redirect) = packet::path_error(
            &sent,
            (IpAddr::V4(ROUTER4), IpAddr::V4(CONFIG4)),
            (5, 0),
            [0; 4],
        ) else {
            unreachable!("no redirect")
        };
        assert_eq!(super::read(&redirect), Back::Other);
    }

    #[test]
    fn a_syns_mss_is_clamped_to_the_tunnels_mtu() {
        for (from, to, largest) in [
            (
                IpAddr::V4(TUN4),
                IpAddr::V4(SERVER4),
                largest_mss(1_420, true),
            ),
            (
                IpAddr::V6(TUN6),
                IpAddr::V6(SERVER6),
                largest_mss(1_280, false),
            ),
        ] {
            let mut syn = tcp(from, to, b"");
            let Ok(parsed) = packet::parse(&syn) else {
                unreachable!("unparsed")
            };
            assert!(clamp_mss(&mut syn, &parsed, largest));
            assert!(checksums_hold(&syn));
            let Ok(SlicedPacket {
                transport: Some(TransportSlice::Tcp(t)),
                ..
            }) = SlicedPacket::from_ip(&syn)
            else {
                unreachable!("not tcp")
            };
            let mss = t.options_iterator().find_map(|o| match o {
                Ok(etherparse::TcpOptionElement::MaximumSegmentSize(mss)) => Some(mss),
                _ => None,
            });
            assert_eq!(mss, Some(largest));
            // Already small enough: left as it is.
            let before = syn.clone();
            assert!(!clamp_mss(&mut syn, &parsed, largest));
            assert_eq!(syn, before);
        }
        assert_eq!(largest_mss(1_420, true), 1_380);
        assert_eq!(largest_mss(1_280, false), 1_220);
    }

    /// The option's word falls on an odd offset after a single NOP: the checksum still holds.
    #[test]
    fn an_mss_after_one_nop_is_clamped_with_a_checksum_that_holds() {
        let mut out = Vec::new();
        let Ok(built) = builder(IpAddr::V4(TUN4), IpAddr::V4(SERVER4))
            .tcp(40_000, 443, 7, 64_240)
            .syn()
            .options(&[
                etherparse::TcpOptionElement::Noop,
                etherparse::TcpOptionElement::MaximumSegmentSize(1460),
                etherparse::TcpOptionElement::Noop,
                etherparse::TcpOptionElement::Noop,
                etherparse::TcpOptionElement::Noop,
            ])
        else {
            unreachable!("options")
        };
        let _ = built.write(&mut out, b"");
        let Ok(parsed) = packet::parse(&out) else {
            unreachable!("unparsed")
        };
        assert!(clamp_mss(&mut out, &parsed, 1_380));
        assert!(checksums_hold(&out));
    }

    #[test]
    fn only_ipv4_without_df_may_be_fragmented() {
        let mut packet = udp(IpAddr::V4(TUN4), IpAddr::V4(SERVER4), b"x");
        packet[6] |= 0x40;
        assert!(dont_fragment(&packet));
        packet[6] &= !0x40;
        assert!(!dont_fragment(&packet));
        assert!(dont_fragment(&udp(
            IpAddr::V6(TUN6),
            IpAddr::V6(SERVER6),
            b"x"
        )));
    }
}
