//! Fuzzing of Watch's reader of TLS server names (`datapavan_net::tls`): the first bytes of any app's
//! connection. A name found must be printable ASCII in lower case, and reading a stream that grows
//! byte by byte must never find a name or an ECH flag the whole stream does not have.
#![no_main]

use datapavan_net::tls::{self, ServerName};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let whole = tls::server_name(data);
    if let ServerName::Found(hello) = &whole {
        assert!(!hello.name.is_empty() && hello.name.len() <= 253);
        assert!(hello.name.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
    }
    for cut in [data.len() / 2, data.len().saturating_sub(1)] {
        if let ServerName::Found(hello) = tls::server_name(&data[..cut]) {
            assert_eq!(whole, ServerName::Found(hello));
        }
    }
});
