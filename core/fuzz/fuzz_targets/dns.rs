//! Fuzzing of Watch's reader of DNS answers (`datapavan_net::dns`): any bytes a resolver on the
//! network can send. A response that is read must have a question in lower case, of printable ASCII.
#![no_main]

use datapavan_net::dns;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(response) = dns::response(data) {
        assert!(!response.question.is_empty() && response.question.len() <= 253);
        assert!(response.question.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
        assert!(response.addresses.len() <= 64);
    }
});
