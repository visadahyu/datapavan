//! Engine 1: `ipstack`, a userspace TCP/IP stack, terminates every connection from the tunnel, and
//! each one is relayed over an ordinary socket of the watch app's own, outside the tunnel.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;

use crate::OwnerLookup;
use crate::stats::Stats;
use crate::tun::Tun;

/// How long a UDP flow may stay silent before it is closed, as Android firewalls commonly do.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Runs until `stop` changes or the tunnel closes.
pub async fn run(tun: Tun, mtu: u16, stats: Arc<Stats>, owners: Arc<dyn OwnerLookup>, mut stop: watch::Receiver<bool>) {
    let mut config = IpStackConfig::default();
    if config.mtu(mtu).is_err() {
        config.mtu_unchecked(mtu);
    }
    config.udp_timeout(UDP_IDLE);
    let mut stack = IpStack::new(config, tun);
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            accepted = stack.accept() => {
                let Ok(stream) = accepted else { return };
                match stream {
                    IpStackStream::Tcp(tcp) => {
                        Stats::add(&stats.tcp_flows, 1);
                        tokio::spawn(relay_tcp(tcp, Arc::clone(&stats), Arc::clone(&owners)));
                    }
                    IpStackStream::Udp(udp) => {
                        Stats::add(&stats.udp_flows, 1);
                        tokio::spawn(relay_udp(udp, Arc::clone(&stats), Arc::clone(&owners)));
                    }
                    // ICMP and other protocols are dropped in the spike.
                    IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
                }
            }
        }
    }
}

/// Asks Android which app opened a flow, off the engine's thread, and counts the time it took.
pub(crate) async fn look_up(owners: &Arc<dyn OwnerLookup>, stats: &Arc<Stats>, protocol: i32, local: SocketAddr, remote: SocketAddr) -> i32 {
    let owners = Arc::clone(owners);
    let started = Instant::now();
    let uid = tokio::task::spawn_blocking(move || owners.owner(protocol, local, remote)).await.unwrap_or(-1);
    Stats::add(&stats.owner_lookups, 1);
    Stats::add(&stats.owner_nanos, u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    if uid < 0 {
        Stats::add(&stats.owner_unknown, 1);
    }
    uid
}

async fn relay_tcp(mut tcp: IpStackTcpStream, stats: Arc<Stats>, owners: Arc<dyn OwnerLookup>) {
    let (local, remote) = (tcp.local_addr(), tcp.peer_addr());
    let lookup = look_up(&owners, &stats, 6, local, remote);
    let connect = TcpStream::connect(remote);
    let (_uid, upstream) = tokio::join!(lookup, connect);
    let Ok(mut upstream) = upstream else {
        Stats::add(&stats.connect_errors, 1);
        return;
    };
    let _ = upstream.set_nodelay(true);
    if let Ok((up, down)) = tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await {
        Stats::add(&stats.bytes_up, up);
        Stats::add(&stats.bytes_down, down);
    }
    let _ = upstream.shutdown().await;
    let _ = tcp.shutdown().await;
}

async fn relay_udp(mut udp: IpStackUdpStream, stats: Arc<Stats>, owners: Arc<dyn OwnerLookup>) {
    let (local, remote) = (udp.local_addr(), udp.peer_addr());
    let _uid = look_up(&owners, &stats, 17, local, remote).await;
    let bind: SocketAddr = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap_or(remote);
    let Ok(socket) = UdpSocket::bind(bind).await else {
        Stats::add(&stats.connect_errors, 1);
        return;
    };
    if socket.connect(remote).await.is_err() {
        Stats::add(&stats.connect_errors, 1);
        return;
    }
    let mut from_app = vec![0u8; 65_535];
    let mut from_net = vec![0u8; 65_535];
    loop {
        tokio::select! {
            read = udp.read(&mut from_app) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if socket.send(&from_app[..n]).await.is_err() { break; }
                    Stats::add(&stats.bytes_up, n as u64);
                }
            },
            received = tokio::time::timeout(UDP_IDLE, socket.recv(&mut from_net)) => match received {
                Ok(Ok(n)) => {
                    if udp.write_all(&from_net[..n]).await.is_err() { break; }
                    Stats::add(&stats.bytes_down, n as u64);
                }
                _ => break,
            },
        }
    }
}
