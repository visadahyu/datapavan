//! Packet-engine spike for Datapavan Watch (ADR 0012, docs/VPN.md "Spike plan").
//!
//! Throwaway code for measuring, not for shipping: each engine reads IP packets from the TUN file
//! descriptor that Android's `VpnService` gives, hands every TCP and UDP flow to a socket of its own
//! outside the tunnel, and counts what passes. The watch app is left out of its own tunnel, so those
//! sockets need no `protect()`. Both Rust engines sit behind the same JNI surface as the Go one.
//!
//! - [`userspace`]: a userspace TCP/IP stack (`ipstack`) terminates each connection.
//! - [`system`]: packets are rewritten so that Android's own TCP stack terminates them.

pub mod socks;
pub mod stats;
pub mod system;
pub mod tun;
pub mod userspace;

mod bridge;

use std::net::SocketAddr;

/// Which engine runs, as the Kotlin side numbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A userspace TCP/IP stack.
    Userspace,
    /// Android's own TCP stack, reached by rewriting addresses.
    System,
}

impl Kind {
    /// The engine for a number from Kotlin, if there is one.
    #[must_use]
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Userspace),
            1 => Some(Self::System),
            _ => None,
        }
    }
}

/// What the engines ask of Android, through the Kotlin side.
pub trait OwnerLookup: Send + Sync + 'static {
    /// The owner of a flow from `local` to `remote`, with `protocol` 6 for TCP or 17 for UDP:
    /// `ConnectivityManager.getConnectionOwnerUid`, or -1 when Android does not know.
    fn owner(&self, protocol: i32, local: SocketAddr, remote: SocketAddr) -> i32;

    /// `VpnService.protect`: keeps a socket of the engine's own out of the tunnel. Needed when the
    /// watch app is inside its own tunnel, as the system engine requires.
    fn protect(&self, fd: i32) -> bool;
}
