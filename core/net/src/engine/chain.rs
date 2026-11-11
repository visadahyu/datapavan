//! Chaining (W6): the apps the user picks go through the local SOCKS5 proxy of the user's tool, and
//! nothing of theirs leaves directly (docs/VPN.md, "Coexistence with other VPNs"; ADR 0038).
//!
//! While a chain is on, a flow's route waits for Android to name its app: a chained app's connection
//! must not start on the network beneath and then be moved. The tool's own traffic goes directly, so
//! that it does not loop back into its proxy. A flow whose app Android cannot name goes nowhere while
//! a chain is on: directly it could be a chained app's, and through the tool it could be the tool's own.

use super::upstream::protect;
use super::{CONNECT_TIMEOUT, Shared, lock};
use crate::socks5::{self, Command, Credentials, Target};
use crate::standins::is_stand_in;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::net::{TcpSocket, TcpStream};

/// The user's tool and the apps sent through it.
#[derive(Clone, Debug)]
pub struct Chain {
    /// The address of the tool's local SOCKS5 proxy.
    pub proxy: SocketAddr,
    /// The username and password the tool asks for, if the user set one.
    pub credentials: Option<Credentials>,
    /// The tool's UID: its own traffic goes directly.
    pub tool: u32,
    /// The UIDs of the apps sent through the tool, or `None` for every app but the tool.
    pub apps: Option<HashSet<u32>>,
    /// Whether the tool carries UDP (`UDP ASSOCIATE`); without it, chained apps' UDP goes nowhere.
    pub udp: bool,
}

/// Where a new flow goes.
#[derive(Clone, Debug)]
pub(super) enum Route {
    /// Out on the network beneath, from a protected socket.
    Direct,
    /// Through the tool's proxy.
    Tool(Arc<Chain>),
    /// Nowhere: the app gets a reset or an ICMP error.
    Refused,
}

impl Shared {
    /// The chain, if one is on.
    pub(super) fn chain(&self) -> Option<Arc<Chain>> {
        lock(&self.chain).clone()
    }

    /// Where a flow of the app `uid` to `destination` goes. A stand-in address is reached only through
    /// the tool: from any other app, it can only be one left over from a chain that ended.
    pub(super) fn route(&self, uid: Option<u32>, destination: SocketAddr) -> Route {
        let stand_in = is_stand_in(destination.ip());
        let Some(chain) = self.chain() else {
            return if stand_in {
                Route::Refused
            } else {
                Route::Direct
            };
        };
        match uid {
            Some(uid) if uid == chain.tool => {
                if stand_in {
                    Route::Refused
                } else {
                    Route::Direct
                }
            }
            Some(uid) if chain.apps.as_ref().is_none_or(|apps| apps.contains(&uid)) => {
                Route::Tool(chain)
            }
            Some(_) if !stand_in => Route::Direct,
            _ => Route::Refused,
        }
    }

    /// What to ask the tool for: the name behind a stand-in address, or the address itself. `None` for
    /// a stand-in the map no longer holds.
    pub(super) fn tool_target(&self, destination: SocketAddr) -> Option<Target> {
        if !is_stand_in(destination.ip()) {
            return Some(Target::Address(destination));
        }
        let name = lock(&self.stand_ins).name(destination.ip())?;
        Target::name(&name, destination.port())
    }
}

/// A TCP connection to the tool's proxy. One on the phone's loopback, which Android never routes into
/// a VPN, needs no protection; one elsewhere (on the local network) does, or it would loop back into
/// the tunnel. A proxy that does not answer means the tool stopped: the app is told its destination
/// cannot be reached, not that it refused.
pub(super) async fn connect_proxy(
    shared: &Arc<Shared>,
    proxy: SocketAddr,
) -> io::Result<TcpStream> {
    let socket = if proxy.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if !proxy.ip().is_loopback() {
        protect(shared, socket.as_raw_fd()).await?;
    }
    socket
        .connect(proxy)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::HostUnreachable, e))
}

/// A TCP connection to `destination` through the tool.
pub(super) async fn connect_through(
    shared: &Arc<Shared>,
    chain: &Chain,
    destination: SocketAddr,
) -> io::Result<TcpStream> {
    let target = shared
        .tool_target(destination)
        .ok_or(io::ErrorKind::ConnectionRefused)?;
    let handshake = async {
        let mut stream = connect_proxy(shared, chain.proxy).await?;
        socks5::handshake(
            &mut stream,
            chain.credentials.as_ref(),
            Command::Connect,
            &target,
        )
        .await
        .map_err(io_error)?;
        Ok(stream)
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, handshake).await {
        Ok(connected) => connected,
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// What the app is told of a failure through the tool: a refusal as a refusal, an unreachable
/// destination as unreachable, anything else, the tool stopped among it, as unreachable too: the app
/// waits and tries again, and nothing leaves directly.
pub(super) fn io_error(error: socks5::Error) -> io::Error {
    if error.is_refused() {
        io::ErrorKind::ConnectionRefused.into()
    } else {
        io::Error::new(io::ErrorKind::HostUnreachable, error)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::shared;
    use super::*;
    use std::net::Ipv4Addr;

    const TOOL: u32 = 10_200;
    const CHAINED: u32 = 10_300;
    const DIRECT: u32 = 10_400;

    fn chain(apps: Option<&[u32]>) -> Chain {
        Chain {
            proxy: SocketAddr::from(([127, 0, 0, 1], 10_808)),
            credentials: None,
            tool: TOOL,
            apps: apps.map(|a| a.iter().copied().collect()),
            udp: true,
        }
    }

    fn is(route: &Route, tool: bool) -> bool {
        matches!(
            (route, tool),
            (Route::Tool(_), true) | (Route::Direct, false)
        )
    }

    #[test]
    fn routes_each_app_by_the_chain() {
        let shared = shared();
        let server = SocketAddr::from(([93, 184, 216, 34], 443));
        let stand_in = SocketAddr::from(([198, 18, 0, 1], 443));
        assert!(is(&shared.route(Some(CHAINED), server), false), "no chain");
        assert!(matches!(
            shared.route(Some(CHAINED), stand_in),
            Route::Refused
        ));

        *lock(&shared.chain) = Some(Arc::new(chain(Some(&[CHAINED]))));
        assert!(is(&shared.route(Some(CHAINED), server), true));
        assert!(is(&shared.route(Some(CHAINED), stand_in), true));
        assert!(is(&shared.route(Some(DIRECT), server), false));
        assert!(is(&shared.route(Some(TOOL), server), false));
        for uid in [Some(DIRECT), Some(TOOL)] {
            assert!(matches!(shared.route(uid, stand_in), Route::Refused));
        }
        assert!(matches!(shared.route(None, server), Route::Refused));

        *lock(&shared.chain) = Some(Arc::new(chain(None)));
        assert!(is(&shared.route(Some(DIRECT), server), true), "every app");
        assert!(is(&shared.route(Some(TOOL), server), false), "but the tool");
        assert!(matches!(shared.route(None, server), Route::Refused));
    }

    #[test]
    fn asks_the_tool_for_the_name_behind_a_stand_in() {
        let shared = shared();
        let address = lock(&shared.stand_ins).address("example.com");
        let stand_in = SocketAddr::from((address, 443));
        assert_eq!(
            shared.tool_target(stand_in),
            Target::name("example.com", 443)
        );
        let forgotten = SocketAddr::from((Ipv4Addr::new(198, 19, 0, 9), 443));
        assert_eq!(shared.tool_target(forgotten), None);
        let server = SocketAddr::from(([93, 184, 216, 34], 443));
        assert_eq!(shared.tool_target(server), Some(Target::Address(server)));
    }

    #[test]
    fn tells_the_app_a_refusal_or_an_unreachable_destination() {
        assert_eq!(
            io_error(socks5::Error::Reply(5)).kind(),
            io::ErrorKind::ConnectionRefused
        );
        for error in [
            socks5::Error::Reply(4),
            socks5::Error::Reply(2),
            socks5::Error::NoAcceptableMethod,
            socks5::Error::Io(io::ErrorKind::ConnectionRefused),
        ] {
            assert_eq!(io_error(error).kind(), io::ErrorKind::HostUnreachable);
        }
    }
}
