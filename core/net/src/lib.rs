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
pub mod forward;
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
    ASK_BOUND, Addresses, AppRoute, Beneath, BeneathState, BlockSetting, BlockedBy, Chain,
    ChainSetting, Config, DnsUse, Ech, Engine, Flow, Handover, Limits, NamedBy, Network, Outcome,
    Platform, Proxied, ProxySetting, Resolution, Tally, TunnelSetting, TunnelState, Via,
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

/// Sorts `items` by `cmp`, stably, through the one copy of `std`'s stable sort that every caller shares
/// (`sort_indices`): the indices `0..len` are sorted, comparing the items they name, and the items are then moved into
/// that order, each cycle of the permutation walked once. The result is `items.sort_by(cmp)`'s, and for a type whose
/// equal values cannot be told apart (integers, addresses) `sort_unstable`'s too. Each caller keeps only this small
/// generic part, where `std`'s sort was built again for every element type, 3 to 6 KB each (the cold paths' third
/// pass, ADR 0053). For cold paths only: it allocates `len` words, and each comparison is an indirect call.
pub(crate) fn sort_by<T>(items: &mut [T], mut cmp: impl FnMut(&T, &T) -> std::cmp::Ordering) {
    if items.len() < 2 {
        return;
    }
    let mut order: Vec<usize> = (0..items.len()).collect();
    {
        let items = &*items;
        sort_indices(&mut order, &mut |a, b| cmp(&items[a], &items[b]));
    }
    // The item at `order[i]` goes to `i`: each cycle walked from its first index, each index marked done.
    for start in 0..order.len() {
        let mut at = start;
        loop {
            let from = std::mem::replace(&mut order[at], usize::MAX);
            if from == start || from == usize::MAX {
                break;
            }
            items.swap(at, from);
            at = from;
        }
    }
}

/// [`sort_by`] in the items' own order.
pub(crate) fn sort<T: Ord>(items: &mut [T]) {
    sort_by(items, T::cmp);
}

/// `std`'s stable sort, built once, for [`sort_by`]'s indices.
#[inline(never)]
fn sort_indices(order: &mut [usize], cmp: &mut dyn FnMut(usize, usize) -> std::cmp::Ordering) {
    order.sort_by(|&a, &b| cmp(a, b));
}

#[cfg(test)]
mod tests {
    /// The shared sort gives `std`'s answers: `slice::sort_by`'s, ties in their first order, on lists of every
    /// length to 300 with 1 to 4 and 1 to 1,000 distinct keys, and `sort_unstable`'s on the keys alone; and on lists
    /// already in order, in reverse, and of one key.
    #[test]
    fn the_shared_sort_gives_std_s_order() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for len in 0..=300usize {
            for round in 0..40 {
                let keys = 1 + next() % if round % 2 == 0 { 4 } else { 1_000 };
                let list: Vec<(u64, usize)> = (0..len).map(|i| (next() % keys, i)).collect();
                let mut want = list.clone();
                want.sort_by_key(|p| p.0);
                let mut got = list.clone();
                super::sort_by(&mut got, |a, b| a.0.cmp(&b.0));
                assert_eq!(got, want, "length {len}, {keys} keys");
                let mut want: Vec<u64> = list.iter().map(|p| p.0).collect();
                let mut got = want.clone();
                want.sort_unstable();
                super::sort(&mut got);
                assert_eq!(got, want, "length {len}, {keys} keys");
            }
        }
        for len in [0, 1, 2, 3, 1_000] {
            let ordered: Vec<usize> = (0..len).collect();
            let mut got = ordered.clone();
            super::sort(&mut got);
            assert_eq!(got, ordered);
            let mut got: Vec<usize> = ordered.iter().rev().copied().collect();
            super::sort(&mut got);
            assert_eq!(got, ordered);
            let one: Vec<(u8, usize)> = (0..len).map(|i| (7, i)).collect();
            let mut got = one.clone();
            super::sort_by(&mut got, |a, b| a.0.cmp(&b.0));
            assert_eq!(got, one, "ties keep their order");
        }
    }
}
