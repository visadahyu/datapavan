//! Fuzzing of the `WireGuard` configuration's parser (`datapavan_net::wireguard::config`, W7): any bytes
//! a file the user imports can hold. An accepted configuration has what W7 needs (an address, a DNS server
//! it can reach, a peer with an endpoint and AllowedIPs of a version it has), within the bounds; a refusal
//! names a line inside the text and a key that is one of `wg-quick`'s or a plain word, never a value.
#![no_main]

use datapavan_net::wireguard::config::{self, Config, Endpoint, MTU_RANGE};
use libfuzzer_sys::fuzz_target;

const KEYS: [&str; 10] = [
    "PrivateKey",
    "Address",
    "DNS",
    "MTU",
    "PublicKey",
    "PresharedKey",
    "Endpoint",
    "AllowedIPs",
    "PersistentKeepalive",
    "",
];

fuzz_target!(|data: &[u8]| {
    match Config::parse(data) {
        Ok(config) => {
            assert!(config.addresses.v4.is_some() || config.addresses.v6.is_some());
            assert!(!config.dns.is_empty() && config.dns.len() <= config::MAX_DNS);
            for dns in &config.dns {
                assert!(config.dns_like(*dns).is_some());
            }
            assert!(config.peer.allowed_ips.len() <= config::MAX_ALLOWED);
            assert!(
                config
                    .peer
                    .allowed_ips
                    .iter()
                    .any(|n| config.addresses.like(n.address).is_some())
            );
            for network in &config.peer.allowed_ips {
                assert_eq!(network.masked(), *network);
            }
            if let Some(mtu) = config.mtu {
                assert!(MTU_RANGE.contains(&mtu));
            }
            match &config.peer.endpoint {
                Endpoint::Address(address) => assert_ne!(address.port(), 0),
                Endpoint::Name(name, port) => {
                    assert_ne!(*port, 0);
                    assert!(
                        !name.is_empty() && name.len() <= 253 && name == &name.to_ascii_lowercase()
                    );
                }
            }
            assert_ne!(config.private_key.bytes(), &[0; 32]);
            let shown = format!("{config:?}");
            assert!(!shown.contains("Secret("), "{shown}");
        }
        Err(refusal) => {
            if let Some(line) = refusal.line() {
                assert!(line >= 1 && line <= data.len().max(1));
            }
            if let Some(key) = refusal.key() {
                assert!(
                    KEYS.contains(&key)
                        || (key.len() <= 24 && key.bytes().all(|b| b.is_ascii_alphabetic())),
                    "{key}"
                );
            }
            let _ = refusal.to_string();
        }
    }
});
