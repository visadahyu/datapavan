//! The SOCKS5 client of W6 (`datapavan_net::socks5`) against a small proxy in the same process. The
//! proxy reads and writes its bytes by hand, from RFC 1928 and RFC 1929, rather than with the
//! client's own encoders, so that a mistake shared by both sides cannot pass unseen.

use datapavan_net::socks5::{self, Command, Credentials, Error, Target};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type Outcome = Result<(), Box<dyn std::error::Error>>;

const LIMIT: Duration = Duration::from_secs(5);

/// How the test proxy behaves.
#[derive(Clone, Default)]
struct Settings {
    /// The username and password it requires; none when empty.
    password: Option<(Vec<u8>, Vec<u8>)>,
    /// A reply code it answers every request with instead of carrying it.
    fail_with: Option<u8>,
    /// Whether a UDP relay is announced as 0.0.0.0, as many proxies do.
    unspecified_relay: bool,
    /// The names it resolves, to an address on this computer.
    names: HashMap<String, IpAddr>,
}

struct Proxy {
    address: SocketAddr,
    /// The command byte of each request it received.
    commands: Arc<Mutex<Vec<u8>>>,
}

impl Proxy {
    fn commands(&self) -> Vec<u8> {
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn proxy(settings: Settings) -> std::io::Result<Proxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let commands = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&commands);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let settings = settings.clone();
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let _ = serve(client, settings, seen).await;
            });
        }
    });
    Ok(Proxy { address, commands })
}

async fn serve(
    mut client: TcpStream,
    settings: Settings,
    seen: Arc<Mutex<Vec<u8>>>,
) -> std::io::Result<()> {
    // The greeting: version, count, methods.
    let mut head = [0; 2];
    client.read_exact(&mut head).await?;
    let mut methods = vec![0; usize::from(head[1])];
    client.read_exact(&mut methods).await?;
    let wanted = if settings.password.is_some() { 2 } else { 0 };
    let choice = if methods.contains(&wanted) {
        wanted
    } else {
        0xff
    };
    client.write_all(&[5, choice]).await?;
    if choice == 0xff {
        return Ok(());
    }
    if let Some((user, password)) = &settings.password {
        let mut length = [0; 2];
        client.read_exact(&mut length).await?;
        let mut given_user = vec![0; usize::from(length[1])];
        client.read_exact(&mut given_user).await?;
        client.read_exact(&mut length[..1]).await?;
        let mut given_password = vec![0; usize::from(length[0])];
        client.read_exact(&mut given_password).await?;
        let right = &given_user == user && &given_password == password;
        client.write_all(&[1, u8::from(!right)]).await?;
        if !right {
            return Ok(());
        }
    }
    // The request: version, command, reserved, then the address.
    let mut request = [0; 4];
    client.read_exact(&mut request).await?;
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request[1]);
    let ip = match request[3] {
        1 => {
            let mut octets = [0; 4];
            client.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        4 => {
            let mut octets = [0; 16];
            client.read_exact(&mut octets).await?;
            Some(IpAddr::from(octets))
        }
        3 => {
            let mut length = [0; 1];
            client.read_exact(&mut length).await?;
            let mut name = vec![0; usize::from(length[0])];
            client.read_exact(&mut name).await?;
            settings
                .names
                .get(&String::from_utf8_lossy(&name).into_owned())
                .copied()
        }
        _ => return Ok(()),
    };
    let mut port = [0; 2];
    client.read_exact(&mut port).await?;
    let failure = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
    if let Some(code) = settings.fail_with {
        return client.write_all(&failure(code)).await;
    }
    match (request[1], ip) {
        (_, None) => client.write_all(&failure(4)).await,
        (1, Some(ip)) => {
            let target = SocketAddr::new(ip, u16::from_be_bytes(port));
            match TcpStream::connect(target).await {
                Ok(mut upstream) => {
                    client.write_all(&success(upstream.local_addr()?)).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok(())
                }
                Err(_) => client.write_all(&failure(5)).await,
            }
        }
        (3, Some(_)) => relay(client, &settings).await,
        _ => client.write_all(&failure(7)).await,
    }
}

/// A success reply naming `bound`.
fn success(bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![5, 0, 0];
    match bound {
        SocketAddr::V4(a) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    out
}

/// A UDP relay for as long as the client's connection stays open.
async fn relay(mut client: TcpStream, settings: &Settings) -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut bound = socket.local_addr()?;
    if settings.unspecified_relay {
        bound.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    client.write_all(&success(bound)).await?;
    let mut app = None;
    let mut buffer = vec![0; 65_535];
    let mut control = [0; 1];
    loop {
        tokio::select! {
            read = client.read(&mut control) => {
                if matches!(read, Ok(0) | Err(_)) {
                    return Ok(());
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (n, from) = received?;
                let datagram = &buffer[..n];
                if app.is_none_or(|a| a == from) && datagram.len() > 10 && datagram[..4] == [0, 0, 0, 1] {
                    // From the client: a header with an IPv4 address (the tests send no other).
                    app = Some(from);
                    let ip = IpAddr::from([datagram[4], datagram[5], datagram[6], datagram[7]]);
                    let port = u16::from_be_bytes([datagram[8], datagram[9]]);
                    socket.send_to(&datagram[10..], SocketAddr::new(ip, port)).await?;
                } else if let Some(app) = app {
                    // From a server: the header names it.
                    let mut out = success(from);
                    out[..3].copy_from_slice(&[0, 0, 0]);
                    out.extend_from_slice(datagram);
                    socket.send_to(&out, app).await?;
                }
            }
        }
    }
}

async fn tcp_echo() -> std::io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    Ok(address)
}

async fn udp_echo() -> std::io::Result<SocketAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], from).await;
        }
    });
    Ok(address)
}

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
