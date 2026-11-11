//! Fuzzing of the SOCKS5 client's parsers (`datapavan_net::socks5`, W6): any bytes a local proxy, or
//! whatever listens on a tool's port, can send. A datagram that is read must encode back to the same
//! bytes, and a name read anywhere must be one a request can carry.
#![no_main]

use datapavan_net::socks5::{self, Target};
use libfuzzer_sys::fuzz_target;

fn sendable(target: &Target) -> bool {
    match target {
        Target::Name(name, port) => Target::name(name, *port).as_ref() == Some(target),
        Target::Address(_) => true,
    }
}

fuzz_target!(|data: &[u8]| {
    if let Some((target, payload)) = socks5::parse_datagram(data) {
        assert_eq!(socks5::datagram(&target, payload), data);
        assert!(sendable(&target));
    }
    if let Ok(bound) = socks5::reply(data) {
        assert!(sendable(&bound));
    }
    if let Some(head) = data.get(..5).and_then(|h| <[u8; 5]>::try_from(h).ok())
        && let Ok(length) = socks5::reply_length(head)
    {
        assert!((7..=262).contains(&length));
    }
    if let Some(two) = data.get(..2).and_then(|h| <[u8; 2]>::try_from(h).ok()) {
        let _ = socks5::chosen_method(two, true);
        let _ = socks5::password_status(two);
    }
});
