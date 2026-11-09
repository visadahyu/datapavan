//! Fuzzing of Watch's reader of the IP-to-organisation table (`datapavan_net::organisations`): a
//! table comes in the APK or a data pack, but is read as untrusted. Opening it and looking up
//! addresses must never panic, and a name found must hold no control character.
#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use datapavan_net::organisations::Organisations;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(table) = Organisations::open(Box::new(data.to_vec())) else {
        return;
    };
    for address in [
        IpAddr::V4(Ipv4Addr::new(157, 240, 1, 35)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V6(Ipv6Addr::new(0x2a03, 0x2880, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::from(u128::MAX)),
    ] {
        if let Some(organisation) = table.lookup(address) {
            assert!(!organisation.name.chars().any(char::is_control));
        }
    }
});
