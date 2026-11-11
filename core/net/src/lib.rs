//! Datapavan Watch's packet engine (ADR 0012, docs/VPN.md): it reads every app's IP packets from the
//! tunnel, asks Android which app each flow belongs to, and passes the traffic on to its real
//! destination over sockets that stay outside the tunnel. Android's own TCP stack terminates the
//! apps' connections, reached by rewriting addresses; UDP is relayed in userspace.
//!
//! Like the rest of the engine, it holds no `unsafe` code (ADR 0006). The JNI bridge in
//! `datapavan-watch-jni` hands it the tunnel's descriptor and answers its questions to Android.

pub mod dns;
pub mod engine;
pub mod log;
pub mod names;
pub mod nat;
pub mod organisations;
pub mod owners;
pub mod packet;
pub mod quic;
pub mod resolvers;
pub mod socks5;
pub mod tls;
pub mod tun;

pub use engine::{Config, DnsUse, Ech, Engine, Flow, NamedBy, Network, Outcome, Platform};
pub use owners::NetworkKind;
