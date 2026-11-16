//! The tunnel's file descriptor, which `VpnService.Builder.establish()` returns non-blocking: one read
//! is one IP packet from an app, one write gives one packet to an app.
//!
//! A tunnel set up again with the same addresses, on the VPN network Android kept, is handed to the
//! running engine (ADR 0044, unit 12b): its descriptor takes the old one's place for the engine's one
//! reader and for every writer, each of which takes the descriptor in place when it reads or writes.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::unix::AsyncFd;
use tokio::sync::Notify;

/// The tunnel, registered with the engine's event loop.
pub struct Tun {
    /// The descriptor in place. The engine's tasks share one thread, so the lock is never contended; it
    /// is held only to clone or replace what it holds.
    fd: Mutex<Arc<AsyncFd<File>>>,
    /// Woken when another descriptor takes the place of the one in place: a write waiting for the old
    /// one to take a packet goes to the new one instead.
    replaced: Notify,
}

/// Registers the descriptor with tokio. Needs a tokio runtime with IO enabled.
// `AsyncFd::new` is deprecated for types that only borrow a descriptor; the `File` here owns it, so the
// descriptor cannot close under tokio. Its successor, `register`, is unsafe (ADR 0006).
#[allow(deprecated)]
fn register(fd: OwnedFd) -> io::Result<AsyncFd<File>> {
    AsyncFd::new(File::from(fd))
}

impl Tun {
    /// Wraps the descriptor, which must be non-blocking. Needs a tokio runtime with IO enabled.
    ///
    /// # Errors
    /// When tokio cannot register the descriptor.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        Ok(Self {
            fd: Mutex::new(Arc::new(register(fd)?)),
            replaced: Notify::new(),
        })
    }

    fn current(&self) -> Arc<AsyncFd<File>> {
        Arc::clone(&self.fd.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Reads one packet into `buffer`, waiting until one is there. Returns its length; 0 means the
    /// tunnel was closed. The engine's event loop is the one reader, and it replaces the descriptor
    /// itself, after dropping this read: a read never waits on a descriptor replaced.
    ///
    /// # Errors
    /// When the descriptor fails.
    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let fd = self.current();
        loop {
            let mut guard = fd.readable().await?;
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
        self.current().get_ref().read(buffer)
    }

    /// Writes one packet, waiting until the descriptor takes it. A write waiting when the descriptor is
    /// replaced goes to the new one, and lets go of the old one, which can then close: the old
    /// interface is down by then (Android resets it), and would refuse it.
    ///
    /// # Errors
    /// When the descriptor fails.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            // Made before the descriptor is taken, so that any replacement from then on wakes it.
            let replaced = self.replaced.notified();
            let fd = self.current();
            tokio::select! {
                // A replacement first, when both have come.
                biased;
                () = replaced => {}
                guard = fd.writable() => {
                    if let Ok(result) = guard?.try_io(|inner| inner.get_ref().write(packet)) {
                        return result;
                    }
                }
            }
        }
    }

    /// Puts `fd`, which must be non-blocking, in the place of the descriptor, for the reader and every
    /// writer from now on, and gives back the one it replaced, still open, so that what was queued on
    /// it can be read before it closes. Needs a tokio runtime with IO enabled.
    ///
    /// # Errors
    /// When tokio cannot register `fd`, which is closed then; the descriptor in place stays.
    pub fn replace(&self, fd: OwnedFd) -> io::Result<Replaced> {
        let new = Arc::new(register(fd)?);
        let old = std::mem::replace(
            &mut *self.fd.lock().unwrap_or_else(PoisonError::into_inner),
            new,
        );
        self.replaced.notify_waiters();
        Ok(Replaced(old))
    }
}

/// A descriptor of the tunnel that another took the place of ([`Tun::replace`]). Dropping it closes
/// it, exactly once, since it owns the descriptor: then, or as soon as the last write that was waiting
/// on it, which the replacement woke, has gone to the new one.
pub struct Replaced(Arc<AsyncFd<File>>);

impl Replaced {
    /// Reads one packet still queued on it, without waiting.
    ///
    /// # Errors
    /// `WouldBlock` when none is left, or when the descriptor fails.
    pub fn try_recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.get_ref().read(buffer)
    }
}
