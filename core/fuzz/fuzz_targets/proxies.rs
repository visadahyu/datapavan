//! Fuzzing of the network part's reader of the proxy requests an app's first bytes declare, and of the shapes of
//! messengers' proxies (`datapavan_net::proxies`, W8, part 2a): the first bytes of any app's connection. A
//! request found names a destination a flow can keep, its tunnel starts within the bytes, and reading a stream
//! that grows never finds a request the whole stream does not have. The seeds are synthetic: no capture of a
//! real app's traffic, and no real credential, is ever among them.
//!
//! The server's side too (the proxy record's unit U, audit m5): the same bytes read as a server's first bytes, for
//! each kind of request, by `confirmed` and by a `UDP ASSOCIATE`'s `bound`, whose invariants are:
//! - a relay is given only once `confirmed` says `Some(true)`;
//! - a reply cut at any byte gives no answer, or the whole reply's: neither ever changes as more bytes come;
//! - so nothing past the reply's own length is read: bytes after it change nothing.
#![no_main]

use datapavan_net::proxies::{self, Asked, Declared, Kind, MAX_REQUEST, Request};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let whole = proxies::declared(data);
    if let Declared::Request(request) = &whole {
        if let Asked::Name(name) = &request.asked {
            assert!(!name.is_empty() && name.len() <= 253);
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase())
            );
        }
        if let Some(inner) = request.inner {
            assert!(inner <= data.len().min(MAX_REQUEST));
        }
        if request.associate {
            assert_eq!(request.inner, None);
            assert_eq!((&request.asked, request.port), (&unasked(), 0));
        }
    }
    for cut in [data.len() / 2, data.len().saturating_sub(1)] {
        if let Declared::Request(request) = proxies::declared(&data[..cut]) {
            assert_eq!(whole, Declared::Request(request));
        }
    }
    if let Some(known) = proxies::obfuscated2(data) {
        assert_eq!(proxies::obfuscated2(&data[..64]), Some(known));
    }
    if let (Some(whole), Some(part)) = (
        proxies::whatsapp_header(data),
        proxies::whatsapp_header(&data[..data.len() / 2]),
    ) {
        assert_eq!(whole, part);
    }
    server_side(data);
});

fn unasked() -> Asked {
    Asked::Address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// `data` as a server's first bytes, for each request a reply can answer.
fn server_side(data: &[u8]) {
    let base = |kind, method, associate| Request {
        kind,
        asked: unasked(),
        port: 0,
        password: method == 2,
        inner: None,
        method,
        associate,
    };
    let requests = [
        base(Kind::Socks5, 0, false),
        base(Kind::Socks5, 2, false),
        base(Kind::Socks5, 0, true),
        base(Kind::Socks5, 2, true),
        base(Kind::Socks4, 0, false),
        base(Kind::Connect, 0, false),
        base(Kind::Forward, 0, false),
    ];
    let cuts = [
        data.len() / 3,
        data.len() / 2,
        data.len().saturating_sub(1),
        data.len().min(proxies::MAX_REPLY),
    ];
    for request in &requests {
        let confirmed = proxies::confirmed(request, data);
        let bound = proxies::bound(request, data);
        if matches!(bound, Some(Some(_))) {
            assert!(request.associate);
            assert_eq!(confirmed, Some(true));
        }
        for cut in cuts {
            if let Some(part) = proxies::confirmed(request, &data[..cut]) {
                assert_eq!(confirmed, Some(part), "confirmed at {cut}");
            }
            if let Some(part) = proxies::bound(request, &data[..cut]) {
                assert_eq!(bound, Some(part), "bound at {cut}");
            }
        }
    }
}
