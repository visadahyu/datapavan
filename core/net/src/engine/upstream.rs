//! The engine's own connections to where the apps' traffic goes: the target of a destination, the
//! owner lookup and the protection that keep them out of the tunnel. W6 and W7 extend this, to go
//! through a tool's proxy or a `WireGuard` upstream.

use super::{CONNECT_TIMEOUT, Shared, lock};
use crate::packet;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

impl Shared {
    /// Where a flow to `destination` really goes: the network's DNS server for the tunnel's own DNS
    /// address, else the destination itself.
    pub(super) fn target(&self, destination: SocketAddr) -> Option<SocketAddr> {
        if self.is_tunnel_dns(destination.ip()) {
            return lock(&self.upstream_dns).map(|dns| SocketAddr::new(dns, destination.port()));
        }
        Some(destination)
    }
}

/// Asks Android whose a flow is, off the event loop: the answer comes over Binder.
pub(super) async fn owner(
    shared: &Arc<Shared>,
    protocol: u8,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u32> {
    let platform = Arc::clone(&shared.platform);
    tokio::task::spawn_blocking(move || platform.owner(protocol, local, remote))
        .await
        .ok()
        .flatten()
}

/// Protects a socket of the engine's own, off the event loop: the answer comes over Binder. The
/// blocking task gets a duplicate of the descriptor, which it owns: a caller that gives up waiting (a
/// timeout around it) and drops its socket must not leave a bare number that the kernel could hand to
/// another socket before Kotlin protects it. Protecting the duplicate protects the socket itself.
pub(super) async fn protect(shared: &Arc<Shared>, fd: BorrowedFd<'_>) -> io::Result<()> {
    let platform = Arc::clone(&shared.platform);
    let owned = fd.try_clone_to_owned()?;
    if tokio::task::spawn_blocking(move || platform.protect(owned.as_raw_fd()))
        .await
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(io::Error::other("protect() refused"))
    }
}

pub(super) async fn connect_tcp(shared: &Arc<Shared>, target: SocketAddr) -> io::Result<TcpStream> {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    protect(shared, socket.as_fd()).await?;
    // Android's stack answers the app's own keepalives inside the phone, so through Watch an app cannot
    // tell that the server is gone: the kernel's keepalive on the upstream socket does (after about two
    // hours and eleven minutes by Linux's defaults, beyond RFC 5382's two hours and four), and the relay
    // ends both sides.
    socket.set_keepalive(true)?;
    match tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await {
        Ok(connected) => connected,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

pub(super) async fn connect_udp(shared: &Arc<Shared>, target: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(packet::unspecified_like(&target)).await?;
    protect(shared, socket.as_fd()).await?;
    socket.connect(target).await?;
    Ok(socket)
}
