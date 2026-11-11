//! Chaining (W6) through the whole engine: a pair of datagram sockets stands in for the tunnel, the
//! small proxy of `common` for the user's tool. Chained apps' UDP goes through the tool's relay, the
//! other apps' directly; chained apps' lookups get stand-in addresses, and the name behind one goes to
//! the tool; other questions go to the resolver through the tool and come back with a time to live of
//! 0; a stopped tool gets the app an ICMP error and sends nothing directly.

mod common;

use common::{Settings, proxy, udp_echo};
use datapavan_net::engine::{DNS4, TUN4};
use datapavan_net::{Chain, Config, Engine, Platform, dns, packet};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixDatagram};

type Outcome = Result<(), Box<dyn std::error::Error>>;

const TOOL: u32 = 10_200;
const CHAINED: u32 = 10_300;
const DIRECT: u32 = 10_400;
/// The app's ports inside the tunnel: the chained app's, then the direct app's.
const CHAINED_PORT: u16 = 40_000;
const DIRECT_PORT: u16 = 40_001;

/// Android names the app by its port inside the tunnel.
struct ByPort;

impl Platform for ByPort {
    fn owner(&self, _: u8, local: SocketAddr, _: SocketAddr) -> Option<u32> {
        match local.port() {
            CHAINED_PORT => Some(CHAINED),
            DIRECT_PORT => Some(DIRECT),
            _ => None,
        }
    }

    fn protect(&self, _: RawFd) -> bool {
        true
    }

    fn log(&self, _: &[u8]) {}
}

/// The engine on a datagram pair, with `chain` on, and the app's end of the pair.
fn engine(chain: Chain) -> io::Result<(Engine, UnixDatagram)> {
    let (engine_end, app_end) = std::os::unix::net::UnixDatagram::pair()?;
    engine_end.set_nonblocking(true)?;
    app_end.set_nonblocking(true)?;
    let engine = Engine::start(
        OwnedFd::from(engine_end),
        Config {
            mtu: 1500,
            keep_flows: 64,
        },
        Arc::new(ByPort),
        None,
    )?;
    engine.chain(Some(chain));
    Ok((engine, UnixDatagram::from_std(app_end)?))
}

fn chain(proxy: SocketAddr) -> Chain {
    Chain {
        proxy,
        credentials: None,
        tool: TOOL,
        apps: Some(HashSet::from([CHAINED])),
        udp: true,
    }
}

fn app(port: u16) -> SocketAddr {
    SocketAddr::from((TUN4, port))
}

async fn send(tunnel: &UnixDatagram, from: SocketAddr, to: SocketAddr, payload: &[u8]) -> Outcome {
    let datagram = packet::udp(from, to, payload).ok_or("a datagram")?;
    tunnel.send(&datagram).await?;
    Ok(())
}

/// The next packet to the app: its source and payload, or `None` for anything but UDP (an ICMP error).
async fn receive(
    tunnel: &UnixDatagram,
) -> Result<Option<(SocketAddr, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut buffer = vec![0u8; 65_535];
    let n = tokio::time::timeout(Duration::from_secs(5), tunnel.recv(&mut buffer)).await??;
    let Ok(parsed) = packet::parse(&buffer[..n]) else {
        return Ok(None);
    };
    Ok(packet::udp_payload(&buffer[..n], &parsed).map(|p| (parsed.source, p.to_vec())))
}

fn query(name: &[u8], kind: u16) -> Vec<u8> {
    let mut q = vec![0x51, 0x52, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    q.extend_from_slice(name);
    q.extend_from_slice(&kind.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

#[tokio::test(flavor = "current_thread")]
async fn chained_udp_goes_through_the_tool_and_the_rest_directly() -> Outcome {
    let echo = udp_echo().await?;
    let tool = proxy(Settings::default()).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;

    send(&tunnel, app(CHAINED_PORT), echo, b"chained").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (echo, b"chained".to_vec()));
    assert_eq!(tool.commands(), [3], "one UDP ASSOCIATE");

    send(&tunnel, app(DIRECT_PORT), echo, b"direct").await?;
    let answer = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(answer, (echo, b"direct".to_vec()));
    assert_eq!(tool.commands(), [3], "the direct app did not use the tool");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_chained_lookup_gets_a_stand_in_whose_name_goes_to_the_tool() -> Outcome {
    let echo = udp_echo().await?;
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), echo.ip());
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;

    let dns = SocketAddr::from((DNS4, 53));
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x04echo\x04test\x00", 1),
    )
    .await?;
    let (from, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(from, dns);
    let read = dns::response(&answer).ok_or("a response")?;
    let [(IpAddr::V4(stand_in), 0)] = read.addresses[..] else {
        return Err(format!(
            "not one stand-in with a time to live of 0: {:?}",
            read.addresses
        )
        .into());
    };
    assert_eq!(stand_in, Ipv4Addr::new(198, 18, 0, 1));

    send(
        &tunnel,
        app(CHAINED_PORT),
        SocketAddr::from((stand_in, echo.port())),
        b"by name",
    )
    .await?;
    let (from, payload) = receive(&tunnel).await?.ok_or("a datagram")?;
    assert_eq!(
        (from, payload.as_slice()),
        (SocketAddr::from((stand_in, echo.port())), &b"by name"[..])
    );
    assert_eq!(tool.commands(), [3]);

    // The direct app cannot use a stand-in.
    send(
        &tunnel,
        app(DIRECT_PORT),
        SocketAddr::from((stand_in, echo.port())),
        b"no",
    )
    .await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn other_questions_go_to_the_resolver_through_the_tool() -> Outcome {
    // A resolver here, reached when the tool is asked for Quad9.
    let resolver = TcpListener::bind("127.0.0.1:0").await?;
    let resolver_address = resolver.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = resolver.accept().await {
            let mut length = [0u8; 2];
            if stream.read_exact(&mut length).await.is_err() {
                continue;
            }
            let mut question = vec![0u8; usize::from(u16::from_be_bytes(length))];
            if stream.read_exact(&mut question).await.is_err() {
                continue;
            }
            // The question's ID and question, one TXT record of 300 s.
            let mut answer = question[..2].to_vec();
            answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            answer.extend_from_slice(&question[12..]);
            answer.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 1, 44, 0, 6, 5]);
            answer.extend_from_slice(b"hello");
            let mut framed = u16::try_from(answer.len())
                .unwrap_or(0)
                .to_be_bytes()
                .to_vec();
            framed.extend_from_slice(&answer);
            let _ = stream.write_all(&framed).await;
        }
    });
    let mut settings = Settings::default();
    settings
        .remap
        .insert(SocketAddr::from(([9, 9, 9, 10], 53)), resolver_address);
    let tool = proxy(settings).await?;
    let (_engine, tunnel) = engine(chain(tool.address))?;

    let dns = SocketAddr::from((DNS4, 53));
    send(
        &tunnel,
        app(CHAINED_PORT),
        dns,
        &query(b"\x07example\x03com\x00", 16),
    )
    .await?;
    let (_, answer) = receive(&tunnel).await?.ok_or("an answer")?;
    assert_eq!(answer[..4], [0x51, 0x52, 0x81, 0x80]);
    assert_eq!(answer[6..8], [0, 1], "one record");
    assert!(answer.ends_with(&[
        0, 16, 0, 1, 0, 0, 0, 0, 0, 6, 5, b'h', b'e', b'l', b'l', b'o'
    ]));
    assert_eq!(tool.commands(), [1], "one CONNECT, to the resolver");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_stopped_tool_gets_the_app_an_error_and_sends_nothing_directly() -> Outcome {
    let echo = udp_echo().await?;
    // A port nobody listens on: the tool stopped.
    let stopped = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let (_engine, tunnel) = engine(chain(stopped))?;
    send(&tunnel, app(CHAINED_PORT), echo, b"waits").await?;
    assert_eq!(receive(&tunnel).await?, None, "an ICMP error, no echo");
    // Had the datagram gone directly, the echo would come now.
    let mut buffer = [0u8; 2048];
    let later = tokio::time::timeout(Duration::from_millis(500), tunnel.recv(&mut buffer)).await;
    assert!(later.is_err(), "nothing more reaches the app");
    Ok(())
}
