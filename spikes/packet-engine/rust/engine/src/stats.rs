//! Counters every engine keeps, read by Kotlin as a `long[]` in the order of [`Stats::snapshot`].

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What an engine counted since it started.
#[derive(Default)]
pub struct Stats {
    /// TCP flows accepted from the tunnel.
    pub tcp_flows: AtomicU64,
    /// UDP flows accepted from the tunnel.
    pub udp_flows: AtomicU64,
    /// Bytes from apps to the network, payload only.
    pub bytes_up: AtomicU64,
    /// Bytes from the network to apps, payload only.
    pub bytes_down: AtomicU64,
    /// Owner lookups made, one per new flow.
    pub owner_lookups: AtomicU64,
    /// Total time spent in owner lookups, in nanoseconds.
    pub owner_nanos: AtomicU64,
    /// Lookups that found no owner.
    pub owner_unknown: AtomicU64,
    /// Upstream connections that failed.
    pub connect_errors: AtomicU64,
    /// Packets read from the tunnel.
    pub packets_in: AtomicU64,
    /// Packets written to the tunnel.
    pub packets_out: AtomicU64,
}

impl Stats {
    /// Adds `n` to a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// The counters, in the order the Kotlin side reads them.
    #[must_use]
    pub fn snapshot(&self) -> [i64; 10] {
        let read = |c: &AtomicU64| i64::try_from(c.load(Ordering::Relaxed)).unwrap_or(i64::MAX);
        [
            read(&self.tcp_flows),
            read(&self.udp_flows),
            read(&self.bytes_up),
            read(&self.bytes_down),
            read(&self.owner_lookups),
            read(&self.owner_nanos),
            read(&self.owner_unknown),
            read(&self.connect_errors),
            read(&self.packets_in),
            read(&self.packets_out),
        ]
    }
}

/// An upstream socket that counts as it goes: what is read from it went down to an app, what is
/// written to it went up. Counting at the end of a relay would miss every connection that ends in
/// an error or is still open when the engine stops.
pub struct Counted<T> {
    inner: T,
    stats: Arc<Stats>,
}

impl<T> Counted<T> {
    /// Wraps `inner`.
    pub fn new(inner: T, stats: Arc<Stats>) -> Self {
        Self { inner, stats }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            Stats::add(&self.stats.bytes_down, (buf.filled().len() - before) as u64);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = result {
            Stats::add(&self.stats.bytes_up, n as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
