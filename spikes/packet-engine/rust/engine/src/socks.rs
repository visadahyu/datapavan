//! Chaining (RESTRICTED-REGIONS.md): the engine's upstream connections can go through a local SOCKS5
//! proxy that a circumvention tool offers in proxy mode. CONNECT only, without authentication; UDP
//! ASSOCIATE is left for later.

use std::io;
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Asks the proxy on `stream` to connect to `destination`; afterwards the stream carries that
/// connection.
///
/// # Errors
/// When the proxy refuses or answers something else than SOCKS5.
pub async fn connect(stream: &mut TcpStream, destination: SocketAddr) -> io::Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice != [5, 0] {
        return Err(io::Error::other("the proxy wants authentication"));
    }
    let mut request = vec![5, 1, 0];
    match destination {
        SocketAddr::V4(a) => {
            request.push(1);
            request.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            request.push(4);
            request.extend_from_slice(&a.ip().octets());
        }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("the proxy answered {}", reply[1])));
    }
    let rest = match reply[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0]) + 2
        }
        _ => return Err(io::Error::other("bad address type")),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).await?;
    Ok(())
}
