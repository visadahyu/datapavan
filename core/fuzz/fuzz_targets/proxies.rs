//! Fuzzing of the network part's reader of the proxy requests an app's first bytes declare, and of the shapes of
//! messengers' proxies (`datapavan_net::proxies`, W8, part 2a): the first bytes of any app's connection. A
//! request found names a destination a flow can keep, its tunnel starts within the bytes, and reading a stream
//! that grows never finds a request the whole stream does not have. The seeds are synthetic: no capture of a
//! real app's traffic, and no real credential, is ever among them.
#![no_main]

use datapavan_net::proxies::{self, Asked, Declared, MAX_REQUEST};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let whole = proxies::declared(data);
    if let Declared::Request(request) = &whole {
        if let Asked::Name(name) = &request.asked {
            assert!(!name.is_empty() && name.len() <= 253);
            assert!(name.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
        }
        if let Some(inner) = request.inner {
            assert!(inner <= data.len().min(MAX_REQUEST));
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
});
