//! The SOCKS5 client of W6 (`datapavan_net::socks5`) against the small proxy of `common`, whose bytes
//! are written by hand from the RFCs.

mod common;

use common::{Settings, proxy, tcp_echo, udp_echo};
use datapavan_net::socks5::{self, Command, Credentials, Error, Target};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type Outcome = Result<(), Box<dyn std::error::Error>>;

const LIMIT: Duration = Duration::from_secs(5);

/// Connects to the proxy and runs the handshake, within [`LIMIT`].
async fn through(
    proxy: SocketAddr,
    credentials: Option<&Credentials>,
    command: Command,
    target: &Target,
) -> Result<(TcpStream, Target), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(proxy).await?;
    let bound = tokio::time::timeout(
        LIMIT,
        socks5::handshake(&mut stream, credentials, command, target),
    )
    .await??;
    Ok((stream, bound))
}

async fn echoes(stream: &mut TcpStream) -> Outcome {
    stream.write_all(b"hello through the tool").await?;
    let mut back = [0; 22];
    tokio::time::timeout(LIMIT, stream.read_exact(&mut back)).await??;
    assert_eq!(&back, b"hello through the tool");
    Ok(())
}

fn credentials(user: &[u8], password: &[u8]) -> Result<Credentials, Box<dyn std::error::Error>> {
    Credentials::new(user, password).ok_or_else(|| "invalid credentials".into())
}

#[tokio::test]
async fn connects_by_address_and_by_name() -> Outcome {
    let echo = tcp_echo().await?;
    let mut settings = Settings::default();
    settings.names.insert("echo.test".into(), echo.ip());
    let proxy = proxy(settings).await?;
    let (mut stream, bound) = through(
        proxy.address,
        None,
        Command::Connect,
        &Target::Address(echo),
    )
    .await?;
    assert!(matches!(bound, Target::Address(a) if a.ip().is_loopback()));
    echoes(&mut stream).await?;
    let name = Target::name("echo.test", echo.port()).ok_or("a valid name")?;
    let (mut stream, _) = through(proxy.address, None, Command::Connect, &name).await?;
    echoes(&mut stream).await?;
    // A name the proxy cannot resolve: host unreachable.
    let unknown = Target::name("nowhere.test", 1).ok_or("a valid name")?;
    let failed = through(proxy.address, None, Command::Connect, &unknown).await;
    assert_eq!(
        failed
            .err()
            .and_then(|e| e.downcast::<Error>().ok())
            .map(|e| *e),
        Some(Error::Reply(4))
    );
    assert_eq!(proxy.commands(), [1, 1, 1], "only CONNECT, never BIND");
    Ok(())
}

#[tokio::test]
async fn gives_the_password_only_when_the_proxy_asks() -> Outcome {
    let echo = tcp_echo().await?;
    let right = credentials(b"watch", b"generated")?;
    let wrong = credentials(b"watch", b"guessed")?;
    let guarded = proxy(Settings {
        password: Some((b"watch".to_vec(), b"generated".to_vec())),
        ..Settings::default()
    })
    .await?;
    let (mut stream, _) = through(
        guarded.address,
        Some(&right),
        Command::Connect,
        &Target::Address(echo),
    )
    .await?;
    echoes(&mut stream).await?;
    let error = |result: Result<_, Box<dyn std::error::Error>>| {
        result
            .err()
            .and_then(|e| e.downcast::<Error>().ok())
            .map(|e| *e)
    };
    let refused = through(
        guarded.address,
        Some(&wrong),
        Command::Connect,
        &Target::Address(echo),
    )
    .await;
    assert_eq!(error(refused), Some(Error::PasswordRefused));
    let without = through(
        guarded.address,
        None,
        Command::Connect,
        &Target::Address(echo),
    )
    .await;
    assert_eq!(error(without), Some(Error::NoAcceptableMethod));
    // A proxy without a password takes Watch's greeting with one too.
    let open = proxy(Settings::default()).await?;
    let (mut stream, _) = through(
        open.address,
        Some(&right),
        Command::Connect,
        &Target::Address(echo),
    )
    .await?;
    echoes(&mut stream).await?;
    Ok(())
}

#[tokio::test]
async fn reports_a_refusal_and_the_proxy_s_failures() -> Outcome {
    // A port nobody listens on.
    let closed = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let open = proxy(Settings::default()).await?;
    let error = |result: Result<_, Box<dyn std::error::Error>>| {
        result
            .err()
            .and_then(|e| e.downcast::<Error>().ok())
            .map(|e| *e)
    };
    let refused = error(
        through(
            open.address,
            None,
            Command::Connect,
            &Target::Address(closed),
        )
        .await,
    );
    assert!(refused.is_some_and(Error::is_refused), "{refused:?}");
    let barred = proxy(Settings {
        fail_with: Some(2),
        ..Settings::default()
    })
    .await?;
    let not_allowed = error(
        through(
            barred.address,
            None,
            Command::Connect,
            &Target::Address(closed),
        )
        .await,
    );
    assert_eq!(not_allowed, Some(Error::Reply(2)));
    let no_udp = proxy(Settings {
        fail_with: Some(7),
        ..Settings::default()
    })
    .await?;
    let unsupported = error(
        through(
            no_udp.address,
            None,
            Command::UdpAssociate,
            &Target::Address(closed),
        )
        .await,
    );
    assert!(
        unsupported.is_some_and(Error::is_unsupported),
        "{unsupported:?}"
    );
    Ok(())
}

#[tokio::test]
async fn refuses_what_is_not_a_socks5_proxy() -> Outcome {
    // An echo server sends the greeting back: version 5, then the method count 1 where a method should be.
    let echo = tcp_echo().await?;
    let mut stream = TcpStream::connect(echo).await?;
    let answer =
        socks5::handshake(&mut stream, None, Command::Connect, &Target::Address(echo)).await;
    assert_eq!(answer, Err(Error::Protocol));
    // A server that closes at once.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let mut stream = TcpStream::connect(address).await?;
    let answer =
        socks5::handshake(&mut stream, None, Command::Connect, &Target::Address(echo)).await;
    assert!(matches!(answer, Err(Error::Io(_))), "{answer:?}");
    Ok(())
}

#[tokio::test]
async fn relays_datagrams_while_the_association_lasts() -> Outcome {
    for unspecified_relay in [false, true] {
        let echo = udp_echo().await?;
        let proxy = proxy(Settings {
            unspecified_relay,
            ..Settings::default()
        })
        .await?;
        let any = Target::Address(SocketAddr::from(([0, 0, 0, 0], 0)));
        let (control, bound) = through(proxy.address, None, Command::UdpAssociate, &any).await?;
        let relay = socks5::relay_address(&bound, proxy.address).ok_or("a relay address")?;
        assert!(!relay.ip().is_unspecified());
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket
            .send_to(&socks5::datagram(&Target::Address(echo), b"query"), relay)
            .await?;
        let mut buffer = [0; 1500];
        let (n, _) = tokio::time::timeout(LIMIT, socket.recv_from(&mut buffer)).await??;
        let (from, payload) = socks5::parse_datagram(&buffer[..n]).ok_or("a datagram")?;
        assert_eq!((from, payload), (Target::Address(echo), &b"query"[..]));
        assert_eq!(proxy.commands(), [3], "only UDP ASSOCIATE, never BIND");
        drop(control);
    }
    Ok(())
}
