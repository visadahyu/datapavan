//! A small SOCKS5 proxy for the tests, its bytes read and written by hand from RFC 1928 and RFC 1929
//! rather than with the client's own encoders, so that a mistake shared by both sides cannot pass
//! unseen; and echo servers to reach through it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
    /// Where a connection to an address goes instead, as a resolver's address to a server here.
    pub remap: HashMap<SocketAddr, SocketAddr>,
}

pub struct Proxy {
    pub address: SocketAddr,
    /// The command byte of each request it received.
    commands: Arc<Mutex<Vec<u8>>>,
}

impl Proxy {
    pub fn commands(&self) -> Vec<u8> {
        self.commands
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

pub async fn proxy(settings: Settings) -> std::io::Result<Proxy> {
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
                if app.is_none_or(|a| a == from) {
                    // From the client: a header naming the destination by address or by name.
                    app = Some(from);
                    if let Some((target, payload)) = client_datagram(datagram, &settings.names) {
                        socket.send_to(payload, target).await?;
                    }
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

/// A datagram from the client: where it goes and its payload, the header read by hand.
fn client_datagram<'a>(
    datagram: &'a [u8],
    names: &HashMap<String, IpAddr>,
) -> Option<(SocketAddr, &'a [u8])> {
    if datagram.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (ip, at) = match *datagram.get(3)? {
        1 => (
            IpAddr::from(<[u8; 4]>::try_from(datagram.get(4..8)?).ok()?),
            8,
        ),
        4 => (
            IpAddr::from(<[u8; 16]>::try_from(datagram.get(4..20)?).ok()?),
            20,
        ),
        3 => {
            let length = usize::from(*datagram.get(4)?);
            let name = String::from_utf8_lossy(datagram.get(5..5 + length)?).into_owned();
            (*names.get(&name)?, 5 + length)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(datagram.get(at..at + 2)?.try_into().ok()?);
    Some((SocketAddr::new(ip, port), datagram.get(at + 2..)?))
}
