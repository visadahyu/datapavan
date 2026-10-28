# 0012. Packet engine for the local VPN

- Status: Proposed (spike pending)
- Date: 2026-10-28

## Context
The local VPN (v0.2) needs a userspace TCP/IP stack to terminate connections and relay them over
protected sockets. The candidates are a Rust stack (`smoltcp` or `ipstack`), which keeps everything in
the memory-safe engine, and Go's gVisor netstack, which is proven in existing Android firewalls.

## Decision
To be decided after a two-week spike, described in [VPN.md](../VPN.md). Both prototypes use the same
JNI surface and are measured on the Galaxy A40 for throughput, latency, battery drain over 8 hours,
memory, binary size, and robustness when the network changes.

## Consequences
To be filled in when this record is accepted.
