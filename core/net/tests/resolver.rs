//! Watch's encrypted resolver through the engine's tunnel (W8, part 1, ADR 0042): a direct app's lookup to Watch's
//! DNS address at port 53 is answered by the encrypted way the Kotlin side carries, never relayed to the network's
//! resolver; at port 853 (DNS over QUIC) it is refused; in the strict setting with every way down the app gets
//! "server failure" and nothing goes to the network's resolver; outside it, the network's resolver answers. The
//! Kotlin side is played by a fake that answers DoH with 10.53.3.3 and the network with 10.53.5.5.

use datapavan_net::catalogue::Catalogue;
use datapavan_net::engine::{Addresses, Limits};
use datapavan_net::ladder::Failure;
use datapavan_net::{
    Carry, Config, DnsConfig, Engine, Exchange, Exchanges, Platform, Reply, dns, packet,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::net::UnixDatagram;

type Outcome = Result<(), Box<dyn std::error::Error>>;

const APP: u16 = 40_001;

/// Watch's Kotlin side, played: every exchange is recorded; DoH answers 10.53.3.3, the network 10.53.5.5, unless
/// `failing` makes every encrypted exchange fail.
#[derive(Default)]
struct Kotlin {
    exchanges: OnceLock<Arc<Exchanges>>,
    seen: Mutex<Vec<Carry>>,
    failing: bool,
}

/// The answer to `query` with one A record of `address`.
fn answer_with(query: &[u8], address: [u8; 4]) -> Vec<u8> {
    let end = 12 + query[12..].iter().position(|&b| b == 0).unwrap_or(0) + 5;
    let mut out = query[..end].to_vec();
    out[2] = 0x81;
    out[3] = 0x80;
    out[6..12].copy_from_slice(&[0, 1, 0, 0, 0, 0]);
    out.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    out.extend_from_slice(&address);
    out
}

impl Platform for Kotlin {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        (local.port() == APP).then_some(10_400)
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}

    fn exchange(&self, ticket: u64, request: &Exchange) -> bool {
        self.seen.lock().map(|mut s| s.push(request.carry)).ok();
        let Some(exchanges) = self.exchanges.get() else {
            return false;
        };
        let reply = match request.carry {
            Carry::Network => Reply::Answer(answer_with(&request.body, [10, 53, 5, 5])),
            _ if self.failing => Reply::Failed(Failure::Tampered),
            Carry::Doh => Reply::Answer(answer_with(&request.body, [10, 53, 3, 3])),
            _ => Reply::Failed(Failure::Refused),
        };
        exchanges.complete(ticket, reply);
        true
    }
}

impl Kotlin {
    fn seen(&self, carry: Carry) -> usize {
        self.seen
            .lock()
            .map_or(0, |s| s.iter().filter(|c| **c == carry).count())
    }
}

/// One preset of DoH, the user's choice, and no pairs.
fn config(strict: bool) -> Arc<DnsConfig> {
    let presets = "p\tP\tP Co\tXA\tdoh\thttps://p.test/dns-query\t192.0.2.5\t-\tno logs\t-\tnone\thttps://p.test/\t-\t-\n";
    let catalogue = Catalogue::parse("", "", "", presets);
    let setting = format!("choice preset p\nstrict {}", u8::from(strict));
    Arc::new(DnsConfig::read(catalogue, &setting))
}

fn started(
    kotlin: &Arc<Kotlin>,
    strict: bool,
) -> Result<(Engine, UnixDatagram), Box<dyn std::error::Error>> {
    let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
    engine_end.set_nonblocking(true)?;
    app_end.set_nonblocking(true)?;
    let engine = Engine::start(
        OwnedFd::from(engine_end),
        Config {
            limits: Limits::default(),
            mtu: 1500,
            keep_flows: 64,
            addresses: Addresses::COMMON,
        },
        Arc::clone(kotlin) as Arc<dyn Platform>,
        None,
    )?;
    let _ = kotlin.exchanges.set(engine.exchanges());
    engine.dns(Some(config(strict)));
    // The network's resolver, which nothing may reach but through the Kotlin side's `Network` exchange.
    engine.network_changed(Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))), true);
    Ok((engine, UnixDatagram::from_std(app_end)?))
}

fn query(name: &[u8]) -> Vec<u8> {
    let mut q = vec![0x51, 0x52, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(name);
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

/// The next packet to the app: its UDP payload, or `None` for anything else (an ICMP error).
async fn next(tunnel: &UnixDatagram) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let n = tokio::time::timeout(Duration::from_secs(6), tunnel.recv(&mut buffer)).await??;
    let Ok(parsed) = packet::parse(&buffer[..n]) else {
        return Ok(None);
    };
    Ok(packet::udp_payload(&buffer[..n], &parsed).map(<[u8]>::to_vec))
}

fn app() -> SocketAddr {
    SocketAddr::from(([10, 111, 0, 1], APP))
}

#[tokio::test]
async fn a_direct_apps_lookup_goes_the_encrypted_way_and_never_to_the_network() -> Outcome {
    let kotlin = Arc::new(Kotlin::default());
    let (mut engine, tunnel) = started(&kotlin, false)?;
    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    tunnel
        .send(&packet::udp(app(), dns, &query(b"\x03www\x07example\x03com\x00")).ok_or("udp")?)
        .await?;
    let answer = next(&tunnel).await?.ok_or("an answer")?;
    let read = dns::response(&answer).ok_or("a response")?;
    assert_eq!(
        read.addresses,
        vec![(IpAddr::V4(Ipv4Addr::new(10, 53, 3, 3)), 60)]
    );
    assert_eq!(answer[..2], [0x51, 0x52]);
    assert_eq!(kotlin.seen(Carry::Doh), 1);
    assert_eq!(kotlin.seen(Carry::Network), 0);
    assert!(engine.dns_status().starts_with("way choice\n"));
    engine.stop();
    Ok(())
}

#[tokio::test]
async fn dns_over_quic_at_watchs_address_is_refused() -> Outcome {
    let kotlin = Arc::new(Kotlin::default());
    let (mut engine, tunnel) = started(&kotlin, false)?;
    let doq = SocketAddr::from((Addresses::COMMON.dns4, 853));
    tunnel
        .send(&packet::udp(app(), doq, b"a quic initial").ok_or("udp")?)
        .await?;
    assert_eq!(next(&tunnel).await?, None, "an ICMP error, not an answer");
    assert_eq!(
        kotlin.seen.lock().map_or(1, |s| s.len()),
        0,
        "nothing carried"
    );
    engine.stop();
    Ok(())
}

#[tokio::test]
async fn strict_with_every_way_down_answers_server_failure_and_asks_the_network_nothing() -> Outcome
{
    let kotlin = Arc::new(Kotlin {
        failing: true,
        ..Kotlin::default()
    });
    let (mut engine, tunnel) = started(&kotlin, true)?;
    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    tunnel
        .send(&packet::udp(app(), dns, &query(b"\x03www\x07example\x03com\x00")).ok_or("udp")?)
        .await?;
    let answer = next(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(answer[3] & 0x0f, 2, "server failure");
    assert_eq!(kotlin.seen(Carry::Network), 0);
    assert!(engine.dns_status().starts_with("way failing "));
    // A local name still goes to the network's resolver.
    tunnel
        .send(&packet::udp(app(), dns, &query(b"\x07printer\x04home\x04arpa\x00")).ok_or("udp")?)
        .await?;
    let local = next(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(
        dns::response(&local).map(|r| r.addresses),
        Some(vec![(IpAddr::V4(Ipv4Addr::new(10, 53, 5, 5)), 60)])
    );
    engine.stop();
    Ok(())
}

#[tokio::test]
async fn outside_strict_the_networks_resolver_answers_and_the_status_says_fallback() -> Outcome {
    let kotlin = Arc::new(Kotlin {
        failing: true,
        ..Kotlin::default()
    });
    let (mut engine, tunnel) = started(&kotlin, false)?;
    let dns = SocketAddr::from((Addresses::COMMON.dns4, 53));
    tunnel
        .send(&packet::udp(app(), dns, &query(b"\x03www\x07example\x03com\x00")).ok_or("udp")?)
        .await?;
    let answer = next(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(
        dns::response(&answer).map(|r| r.addresses),
        Some(vec![(IpAddr::V4(Ipv4Addr::new(10, 53, 5, 5)), 60)])
    );
    assert!(engine.dns_status().starts_with("way fallback "));
    engine.stop();
    Ok(())
}
