//! The TUN file descriptor as an async byte stream: one `read` is one IP packet, one `write` sends
//! one. `VpnService.Builder.establish()` returns it non-blocking, so tokio can poll it.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::stats::Stats;

/// The tunnel, counting packets each way.
pub struct Tun {
    fd: AsyncFd<File>,
    stats: Arc<Stats>,
}

impl Tun {
    /// Wraps the descriptor; it must be non-blocking. Needs a tokio runtime with IO enabled.
    ///
    /// # Errors
    /// When tokio cannot register the descriptor.
    #[allow(deprecated)] // `register` is the unsafe successor; the descriptor is owned here, so `new` is sound.
    pub fn new(fd: OwnedFd, stats: Arc<Stats>) -> io::Result<Self> {
        Ok(Self { fd: AsyncFd::new(File::from(fd))?, stats })
    }

    /// Reads one packet into `buf`, waiting until one is there.
    ///
    /// # Errors
    /// When the descriptor fails.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| (&*inner.get_ref()).read(buf)) {
                Ok(result) => {
                    if result.is_ok() {
                        Stats::add(&self.stats.packets_in, 1);
                    }
                    return result;
                }
                Err(_would_block) => {}
            }
        }
    }

    /// Writes one packet, waiting until the descriptor takes it.
    ///
    /// # Errors
    /// When the descriptor fails.
    pub async fn send(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| (&*inner.get_ref()).write(packet)) {
                Ok(result) => {
                    if result.is_ok() {
                        Stats::add(&self.stats.packets_out, 1);
                    }
                    return result;
                }
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncRead for Tun {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| (&*inner.get_ref()).read(unfilled)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    Stats::add(&self.stats.packets_in, 1);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for Tun {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|inner| (&*inner.get_ref()).write(packet)) {
                Ok(result) => {
                    if result.is_ok() {
                        Stats::add(&self.stats.packets_out, 1);
                    }
                    return Poll::Ready(result);
                }
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
