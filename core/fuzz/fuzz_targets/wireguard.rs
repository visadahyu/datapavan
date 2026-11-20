//! Fuzzing of the `WireGuard` configuration's parser (`datapavan_net::wireguard::config`, W7): any bytes
//! a file the user imports can hold. An accepted configuration has what W7 needs (an address, a DNS server
//! it can reach, a peer with an endpoint and AllowedIPs of a version it has), within the bounds, and its `Debug`
//! shows neither key, as bytes, as a list of numbers or in base64; a refusal names a line inside the text and a
//! key that is one of `wg-quick`'s or a plain word, never a value: its text holds no run of base64 a key could
//! be. The import's description of an accepted configuration (W7, part 2) holds no key either, and its
//! `everything` holds: every destination of each version it has an address of is allowed.
#![no_main]

use datapavan_net::wireguard::config::{self, Config, Endpoint, MTU_RANGE};
use libfuzzer_sys::fuzz_target;

/// A key in the base64 that `wg-quick` writes, 44 characters with its padding.
fn base64(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
        }
    }
    while out.len() % 4 != 0 {
        out.push('=');
    }
    out
}

/// The longest run of characters of base64 in `text`.
fn longest_base64_run(text: &str) -> usize {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
        .map(str::len)
        .max()
        .unwrap_or(0)
}

const KEYS: [&str; 15] = [
    "PrivateKey",
    "Address",
    "DNS",
    "MTU",
    "PublicKey",
    "PresharedKey",
    "Endpoint",
    "AllowedIPs",
    "PersistentKeepalive",
    "ListenPort",
    "FwMark",
    "IncludedApplications",
    "ExcludedApplications",
    "Table",
    "",
];

/// The words that begin the description's lines (`Config::describe`).
const DESCRIBED: [&str; 11] = [
    "endpoint",
    "address",
    "dns",
    "allowed",
    "everything",
    "preshared",
    "mtu",
    "keepalive",
    "only",
    "except",
    "",
];

/// Destinations every configuration that carries everything must allow, of the versions it has.
const SAMPLES: [&str; 8] = [
    "0.0.0.0",
    "127.255.255.255",
    "128.0.0.0",
    "255.255.255.255",
    "93.184.216.34",
    "::",
    "8000::",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
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
            // The import's description (W7, part 2), which reaches the screen: what the configuration does, a line
            // each under a known word, and no key.
            let described = config.describe();
            for line in described.lines() {
                let word = line.split(' ').next().unwrap_or("");
                assert!(DESCRIBED.contains(&word), "{line}");
            }
            let keys = std::iter::once(config.private_key.bytes())
                .chain(config.peer.preshared_key.as_ref().map(|k| k.bytes()));
            for key in keys {
                for text in [&shown, &described] {
                    assert!(!text.contains(&base64(key)), "{text}");
                    assert!(!text.contains(&format!("{key:?}")[1..20]), "{text}");
                    assert!(!text.as_bytes().windows(32).any(|w| w == key), "{text}");
                }
            }
            // `everything` says that every destination of each version the configuration has goes through it.
            if config.carries_everything() {
                for sample in SAMPLES {
                    let address: std::net::IpAddr =
                        sample.parse().unwrap_or(std::net::IpAddr::from([0; 4]));
                    if config.addresses.like(address).is_some() {
                        assert!(config.peer.allows(address), "{sample} {described}");
                    }
                }
            }
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
            let said = refusal.to_string();
            assert!(longest_base64_run(&said) < 40, "{said}");
        }
    }
});
