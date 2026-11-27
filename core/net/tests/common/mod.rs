//! A small SOCKS5 proxy for the tests, its bytes read and written by hand from RFC 1928 and RFC 1929
//! rather than with the client's own encoders, so that a mistake shared by both sides cannot pass
//! unseen; an HTTP `CONNECT` proxy beside it, read by hand from RFC 9110 in the same way, as a network's
//! own proxy answers (the proxy record's unit S2); and echo servers to reach through them.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

/// How the test proxy behaves.
#[derive(Clone, Default)]
pub struct Settings {
    /// The username and password it requires; none when empty.
    pub password: Option<(Vec<u8>, Vec<u8>)>,
    /// A reply code it answers every request with instead of carrying it.
    pub fail_with: Option<u8>,
    /// Whether a UDP relay is announced as 0.0.0.0, as many proxies do.
    pub unspecified_relay: bool,
    /// The names it resolves, to an address on this computer.
    pub names: HashMap<String, IpAddr>,
    /// Where a connection or a datagram to an address goes instead, as a resolver's address to a
    /// server here; the relay names an answer from the server here by the address it stands for.
    pub remap: HashMap<SocketAddr, SocketAddr>,
    /// An address a UDP relay is announced at instead of its own, as a relay on another host.
    pub relay_at: Option<IpAddr>,
    /// How the relay names the sender of each answer.
    pub headers: Headers,
    /// A name the relay gives every answer instead, as a tool might forge one.
    pub answer_name: Option<String>,
    /// Whether the relay sends a fragment and a header cut short before the first answer it carries.
    pub bad_headers_first: bool,
}

/// How a relay names the sender of an answer in its header.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Headers {
    /// By its address.
    #[default]
    Address,
    /// By the name the datagram it answers was sent to, where it was sent to one, as some tools do.
    Name,
    /// By its address, an IPv4 one as an IPv4-mapped IPv6 address.
    Mapped,
}

/// The test proxy. Dropping it ends its UDP relays, as [`Proxy::close_relays`] does.
pub struct Proxy {
    pub address: SocketAddr,
    seen: Arc<Seen>,
    /// Counts up to end every UDP relay open now.
    closing: watch::Sender<u64>,
}

/// What the proxy saw: the command byte of each request, and the address of each UDP relay it opened.
#[derive(Default)]
struct Seen {
    commands: Mutex<Vec<u8>>,
    relays: Mutex<Vec<SocketAddr>>,
    /// How many of its UDP relays are open now.
    open: std::sync::atomic::AtomicUsize,
}

/// A relay open, counted until it ends, however it ends.
struct Open<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for Open<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Proxy {
    pub fn commands(&self) -> Vec<u8> {
        self.seen
            .commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The address of each UDP relay it opened, as its servers see the relay.
    pub fn relays(&self) -> Vec<SocketAddr> {
        self.seen
            .relays
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many of its UDP relays are open now.
    pub fn open_relays(&self) -> usize {
        self.seen.open.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Ends every UDP relay open now, and its request's connection, as a tool may.
    pub fn close_relays(&self) {
        self.closing.send_modify(|count| *count += 1);
    }
}

pub async fn proxy(settings: Settings) -> std::io::Result<Proxy> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let seen = Arc::new(Seen::default());
    let (closing, close) = watch::channel(0);
    let noted = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let settings = settings.clone();
            let noted = Arc::clone(&noted);
            let close = close.clone();
            tokio::spawn(async move {
                let _ = serve(client, settings, noted, close).await;
            });
        }
    });
    Ok(Proxy {
        address,
        seen,
        closing,
    })
}

async fn serve(
    mut client: TcpStream,
    settings: Settings,
    seen: Arc<Seen>,
    close: watch::Receiver<u64>,
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
    seen.commands
        .lock()
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
            let target = settings.remap.get(&target).copied().unwrap_or(target);
            match TcpStream::connect(target).await {
                Ok(mut upstream) => {
                    client.write_all(&success(upstream.local_addr()?)).await?;
                    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
                    Ok(())
                }
                Err(_) => client.write_all(&failure(5)).await,
            }
        }
        (3, Some(_)) => relay(client, &settings, &seen, close).await,
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

/// A UDP relay for as long as the client's connection stays open, or until the proxy ends it.
async fn relay(
    mut client: TcpStream,
    settings: &Settings,
    seen: &Seen,
    mut close: watch::Receiver<u64>,
) -> std::io::Result<()> {
    seen.open.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let _open = Open(&seen.open);
    // At the address it is announced at, where this computer holds it; else on the loopback.
    let here = match settings.relay_at {
        Some(ip) => UdpSocket::bind((ip, 0)).await.ok(),
        None => None,
    };
    let socket = match here {
        Some(socket) => socket,
        None => UdpSocket::bind("127.0.0.1:0").await?,
    };
    let mut bound = socket.local_addr()?;
    seen.relays
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(bound);
    if let Some(ip) = settings.relay_at {
        bound.set_ip(ip);
    } else if settings.unspecified_relay {
        bound.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    client.write_all(&success(bound)).await?;
    close.borrow_and_update();
    let mut app = None;
    // The name each server was asked by, where it was.
    let mut asked: HashMap<SocketAddr, (String, u16)> = HashMap::new();
    let mut answered = false;
    let mut buffer = vec![0; 65_535];
    let mut control = [0; 1];
    loop {
        tokio::select! {
            read = client.read(&mut control) => {
                if matches!(read, Ok(0) | Err(_)) {
                    return Ok(());
                }
            }
            _ = close.changed() => return Ok(()),
            received = socket.recv_from(&mut buffer) => {
                let (n, from) = received?;
                let datagram = &buffer[..n];
                if app.is_none_or(|a| a == from) {
                    // From the client: a header naming the destination by address or by name.
                    app = Some(from);
                    if let Some((target, name, payload)) = client_datagram(datagram, &settings.names) {
                        let real = settings.remap.get(&target).copied().unwrap_or(target);
                        if let Some(name) = name {
                            asked.insert(real, (name, target.port()));
                        }
                        socket.send_to(payload, real).await?;
                    }
                } else if let Some(app) = app {
                    // From a server: the header names it, as the client knows it.
                    let shown = settings
                        .remap
                        .iter()
                        .find(|&(_, &real)| real == from)
                        .map_or(from, |(&shown, _)| shown);
                    let by_name = asked.get(&from).filter(|_| settings.headers == Headers::Name);
                    let mut out = match (&settings.answer_name, by_name) {
                        (Some(name), _) => name_header(name, shown.port()),
                        (None, Some((name, port))) => name_header(name, *port),
                        (None, None) => address_header(shown, settings.headers == Headers::Mapped),
                    };
                    if settings.bad_headers_first && !answered {
                        let mut fragment = out.clone();
                        fragment[2] = 1;
                        fragment.extend_from_slice(datagram);
                        socket.send_to(&fragment, app).await?;
                        socket.send_to(&out[..out.len() - 1], app).await?;
                    }
                    answered = true;
                    out.extend_from_slice(datagram);
                    socket.send_to(&out, app).await?;
                }
            }
        }
    }
}

/// A datagram's header naming `from`, an IPv4 address as IPv6 when `mapped`.
fn address_header(from: SocketAddr, mapped: bool) -> Vec<u8> {
    let from = match from {
        SocketAddr::V4(v4) if mapped => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        other => other,
    };
    let mut out = success(from);
    out[..3].copy_from_slice(&[0, 0, 0]);
    out
}

/// A datagram's header naming `name` and `port`.
fn name_header(name: &str, port: u16) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 3, u8::try_from(name.len()).unwrap_or(0)];
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

pub async fn tcp_echo() -> std::io::Result<SocketAddr> {
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

pub async fn udp_echo() -> std::io::Result<SocketAddr> {
    echo_on(UdpSocket::bind("127.0.0.1:0").await?)
}

/// An echo server on `socket`.
fn echo_on(socket: UdpSocket) -> std::io::Result<SocketAddr> {
    let address = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buffer = vec![0; 65_535];
        while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], from).await;
        }
    });
    Ok(address)
}

/// A socket on 127.0.0.1 and one on 127.0.0.2 with the same port number. Another socket may hold that
/// number on the second address, another test's or a mapping's of an engine, which binds every
/// address: a few tries find one free on both.
pub async fn same_port() -> std::io::Result<(UdpSocket, UdpSocket)> {
    for _ in 0..50 {
        let first = UdpSocket::bind("127.0.0.1:0").await?;
        if let Ok(second) = UdpSocket::bind(("127.0.0.2", first.local_addr()?.port())).await {
            return Ok((first, second));
        }
    }
    Err(std::io::ErrorKind::AddrInUse.into())
}

/// An echo server on 127.0.0.1, as [`udp_echo`], and a socket on 127.0.0.2 at the same port.
pub async fn udp_echo_beside() -> std::io::Result<(SocketAddr, UdpSocket)> {
    let (echo, beside) = same_port().await?;
    Ok((echo_on(echo)?, beside))
}

/// A datagram from the client: where it goes, the name it named that by if it did, and its payload,
/// the header read by hand.
fn client_datagram<'a>(
    datagram: &'a [u8],
    names: &HashMap<String, IpAddr>,
) -> Option<(SocketAddr, Option<String>, &'a [u8])> {
    if datagram.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (ip, name, at) = match *datagram.get(3)? {
        1 => (
            IpAddr::from(<[u8; 4]>::try_from(datagram.get(4..8)?).ok()?),
            None,
            8,
        ),
        4 => (
            IpAddr::from(<[u8; 16]>::try_from(datagram.get(4..20)?).ok()?),
            None,
            20,
        ),
        3 => {
            let length = usize::from(*datagram.get(4)?);
            let name = String::from_utf8_lossy(datagram.get(5..5 + length)?).into_owned();
            (*names.get(&name)?, Some(name), 5 + length)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(datagram.get(at..at + 2)?.try_into().ok()?);
    Some((SocketAddr::new(ip, port), name, datagram.get(at + 2..)?))
}

/// How the test's HTTP `CONNECT` proxy answers a request, as a network's own proxy may (the proxy record's unit S2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectMode {
    /// Every request it can carry opened: `200`, then the tunnel.
    #[default]
    Open,
    /// A request by address refused with `403`, as a proxy that filters by name; one by name opened.
    AddressesRefused,
    /// Every request answered `407`, as a proxy that wants a password.
    Password,
    /// A request to port 80 refused with `403`, as tinyproxy with `ConnectPort 443`; any other opened.
    Port80Refused,
    /// No answer at all, the connection held open until the client closes it.
    Silent,
}

/// How the test's HTTP `CONNECT` proxy behaves.
#[derive(Clone, Default)]
pub struct ConnectSettings {
    pub mode: ConnectMode,
    /// The names it resolves, to an address on this computer.
    pub names: HashMap<String, IpAddr>,
    /// Where a tunnel to an address goes instead, as a proxy reaches a server the client cannot.
    pub remap: HashMap<SocketAddr, SocketAddr>,
    /// Whether it waits a moment for the server's first bytes and writes them with its `200`, in one segment, as a
    /// proxy may for a server that speaks first.
    pub first_bytes_with_answer: bool,
}

/// The test's HTTP `CONNECT` proxy: it listens at an address of its own, connects onward from that same address, so
/// that a lab can let out only it, and records each request's line and headers.
pub struct ConnectProxy {
    pub address: SocketAddr,
    seen: Arc<ConnectSeen>,
}

/// What the `CONNECT` proxy saw.
#[derive(Default)]
struct ConnectSeen {
    /// How many connections it accepted, a request read or not.
    connections: std::sync::atomic::AtomicUsize,
    /// Each request's lines, the request line first, as they came, without their line ends.
    requests: Mutex<Vec<Vec<String>>>,
    /// What its tunnels carried from the client, past each request's head.
    carried: Mutex<Vec<u8>>,
}

impl ConnectProxy {
    /// How many connections it accepted.
    pub fn connections(&self) -> usize {
        self.seen
            .connections
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Each request it read: its request line, then its header lines.
    pub fn requests(&self) -> Vec<Vec<String>> {
        self.seen
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What its tunnels carried from the client.
    pub fn carried(&self) -> Vec<u8> {
        self.seen
            .carried
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// An HTTP `CONNECT` proxy listening at `at`, on a port of its own.
pub async fn connect_proxy(at: IpAddr, settings: ConnectSettings) -> std::io::Result<ConnectProxy> {
    let listener = TcpListener::bind((at, 0)).await?;
    let address = listener.local_addr()?;
    let seen = Arc::new(ConnectSeen::default());
    let noted = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            noted
                .connections
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let settings = settings.clone();
            let noted = Arc::clone(&noted);
            tokio::spawn(async move {
                let _ = serve_connect(client, at, settings, noted).await;
            });
        }
    });
    Ok(ConnectProxy { address, seen })
}

/// The most bytes of a request's head read.
const CONNECT_HEAD: usize = 8_192;

/// A request's head, read a byte at a time to its blank line, so that nothing after it is taken; `None` if the client
/// closed first or sent too much.
async fn connect_head(client: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && !head.ends_with(b"\n\n") {
        if head.len() == CONNECT_HEAD || client.read(&mut byte).await? == 0 {
            return Ok(None);
        }
        head.push(byte[0]);
    }
    Ok(Some(head))
}

/// The host and port of an authority, `host:port` or `[v6]:port`.
fn authority(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Some((host.to_owned(), port.parse().ok()?))
}

async fn serve_connect(
    mut client: TcpStream,
    at: IpAddr,
    settings: ConnectSettings,
    seen: Arc<ConnectSeen>,
) -> std::io::Result<()> {
    let Some(head) = connect_head(&mut client).await? else {
        return Ok(());
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let lines: Vec<String> = text
        .lines()
        .take_while(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    seen.requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(lines.clone());
    let answer = |status: &str| format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
    if settings.mode == ConnectMode::Silent {
        let mut rest = Vec::new();
        let _ = client.read_to_end(&mut rest).await;
        return Ok(());
    }
    if settings.mode == ConnectMode::Password {
        let refusal = "HTTP/1.1 407 Proxy Authentication Required\r\n\
             Proxy-Authenticate: Basic realm=\"lab\"\r\nContent-Length: 0\r\n\r\n";
        return client.write_all(refusal.as_bytes()).await;
    }
    let target = lines
        .first()
        .and_then(|line| line.strip_prefix("CONNECT "))
        .and_then(|rest| rest.strip_suffix(" HTTP/1.1"))
        .and_then(authority);
    let Some((host, port)) = target else {
        return client.write_all(answer("400 Bad Request").as_bytes()).await;
    };
    let by_address = host.parse::<IpAddr>().ok();
    if (settings.mode == ConnectMode::AddressesRefused && by_address.is_some())
        || (settings.mode == ConnectMode::Port80Refused && port == 80)
    {
        return client.write_all(answer("403 Forbidden").as_bytes()).await;
    }
    let Some(ip) = by_address.or_else(|| settings.names.get(&host).copied()) else {
        return client.write_all(answer("502 Bad Gateway").as_bytes()).await;
    };
    let destination = SocketAddr::new(ip, port);
    let destination = settings
        .remap
        .get(&destination)
        .copied()
        .unwrap_or(destination);
    let socket = if at.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.bind(SocketAddr::new(at, 0))?;
    let Ok(mut server) = socket.connect(destination).await else {
        return client.write_all(answer("502 Bad Gateway").as_bytes()).await;
    };
    let mut opened = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
    if settings.first_bytes_with_answer {
        let mut first = [0u8; 2_048];
        if let Ok(Ok(n)) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            server.read(&mut first),
        )
        .await
        {
            opened.extend_from_slice(&first[..n]);
        }
    }
    client.write_all(&opened).await?;
    let (mut from_client, mut to_client) = client.into_split();
    let (mut from_server, mut to_server) = server.into_split();
    let up = async move {
        let mut buffer = [0u8; 4_096];
        while let Ok(n) = from_client.read(&mut buffer).await {
            if n == 0 {
                break;
            }
            seen.carried
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(&buffer[..n]);
            if to_server.write_all(&buffer[..n]).await.is_err() {
                break;
            }
        }
        let _ = to_server.shutdown().await;
    };
    let down = async move {
        let _ = tokio::io::copy(&mut from_server, &mut to_client).await;
        let _ = to_client.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}
