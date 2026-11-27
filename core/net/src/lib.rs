//! Datapavan Advanced's packet engine (ADR 0012, docs/VPN.md): it reads every app's IP packets from the
//! tunnel, asks Android which app each flow belongs to, and passes the traffic on to its real
//! destination over sockets that stay outside the tunnel. Android's own TCP stack terminates the
//! apps' connections, reached by rewriting addresses; UDP is relayed in userspace.
//!
//! Like the rest of the engine, it holds no `unsafe` code (ADR 0006). The JNI bridge in
//! `datapavan-network-jni` hands it the tunnel's descriptor and answers its questions to Android.

pub mod answers;
pub mod blocking;
pub mod catalogue;
pub mod connect;
pub mod dns;
pub mod dnscache;
pub mod engine;
pub mod fragments;
pub mod hpke;
pub mod hygiene;
pub mod identifiers;
pub mod ladder;
pub mod local;
pub mod log;
pub mod messengers;
pub mod names;
pub mod nat;
pub mod odoh;
pub mod organisations;
pub mod owners;
pub mod packet;
pub mod proxies;
pub mod quic;
pub mod resolvers;
pub mod snapshot;
pub mod socks5;
pub mod standins;
pub mod states;
pub mod tls;
pub mod trackers;
pub mod tun;
pub mod wireguard;

pub use engine::resolver::{Carry, Choice, DnsConfig, Exchange, Exchanges, Reply, Through};
pub use engine::{
    ASK_BOUND, Addresses, AppRoute, BlockSetting, BlockedBy, Chain, ChainSetting, Config, DnsUse,
    Ech, Engine, Flow, Handover, Limits, NamedBy, Network, Outcome, Platform, Proxied,
    ProxySetting, Resolution, Tally, TunnelSetting, TunnelState, Via,
};
pub use owners::NetworkKind;

/// A new map's hasher keys: `std`'s `RandomState::new`, out of line. Inlined, it took about 100 bytes of the native
/// library at each map made, 39 times in the engine's start alone (the cold paths' size pass, ADR 0053). Each map
/// still gets keys of its own, made in the same order as before. A query ID to an endpoint's resolver takes its
/// randomness from such keys too (`engine::tunnels`).
#[inline(never)]
#[must_use]
pub(crate) fn keys() -> std::hash::RandomState {
    std::hash::RandomState::new()
}

/// An empty map with keys of its own: `HashMap::new()`, its keys made out of line (`keys`). Public for the JNI bridge
/// (`network-jni`), whose maps take this maker too, not a second copy of it (the cold paths' second pass, ADR 0053).
#[must_use]
pub fn map<K, V>() -> std::collections::HashMap<K, V> {
    std::collections::HashMap::with_hasher(keys())
}

/// An empty set with keys of its own: `HashSet::new()`, its keys made out of line (`keys`), as [`map`]'s.
#[must_use]
pub fn set<T>() -> std::collections::HashSet<T> {
    std::collections::HashSet::with_hasher(keys())
}
