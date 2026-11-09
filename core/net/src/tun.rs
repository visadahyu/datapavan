//! The tunnel's file descriptor, which `VpnService.Builder.establish()` returns non-blocking: one read
//! is one IP packet from an app, one write gives one packet to an app.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;

use tokio::io::unix::AsyncFd;

/// The tunnel, registered with the engine's event loop.
pub struct Tun {
    fd: AsyncFd<File>,
}

impl Tun {
    /// Wraps the descriptor, which must be non-blocking. Needs a tokio runtime with IO enabled.
    ///
    /// # Errors
    /// When tokio cannot register the descriptor.
    // `AsyncFd::new` is deprecated for types that only borrow a descriptor; the `File` here owns it,
    // so the descriptor cannot close under tokio. Its successor, `register`, is unsafe (ADR 0006).
    #[allow(deprecated)]
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            fd: AsyncFd::new(File::from(fd))?,
        })
    }

    /// Reads one packet into `buffer`, waiting until one is there. Returns its length; 0 means the
    /// tunnel was closed.
    ///
    /// # Errors
    /// When the descriptor fails.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            if let Ok(result) = guard.try_io(|inner| inner.get_ref().read(buffer)) {
                return result;
            }
        }
    }

    /// Reads one more packet if one is there at once, without waiting: after a wake-up, the engine
    /// reads what has queued up before it waits again (docs/VPN.md, "batched reads").
    ///
    /// # Errors
    /// `WouldBlock` when no packet is there, or when the descriptor fails.
    pub fn try_recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.fd.get_ref().read(buffer)
    }

    /// Writes one packet, waiting until the descriptor takes it.
    ///
    /// # Errors
    /// When the descriptor fails.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            if let Ok(result) = guard.try_io(|inner| inner.get_ref().write(packet)) {
                return result;
            }
        }
    }
}
