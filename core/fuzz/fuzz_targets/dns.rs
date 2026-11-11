//! Fuzzing of Watch's reader of DNS answers (`datapavan_net::dns`): any bytes a resolver on the
//! network can send. A response that is read must have a question in lower case, of printable ASCII,
//! and so must the public names of its ECH configurations. Setting its times to live to 0 must not
//! panic, and a message it refuses must stay as it was. The answers Watch gives chained apps (ADR 0038):
//! a resolver's answer rebuilt once is rebuilt to the same bytes again and has every time to live at 0,
//! and a query read as one gets an answer.
#![no_main]

use datapavan_net::{answers, dns};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(out) = answers::rebuilt(data) {
        assert_eq!(answers::rebuilt(&out).as_ref(), Some(&out));
        let mut uncached = out.clone();
        assert!(dns::uncache(&mut uncached));
        assert_eq!(uncached, out);
    }
    if let Some(question) = answers::question(data) {
        assert!(answers::no_data(data, &question).is_some());
        assert!(answers::failure(data).is_some());
    }
    let mut uncached = data.to_vec();
    if !dns::uncache(&mut uncached) {
        assert_eq!(uncached, data);
    }
    if let Some(response) = dns::response(data) {
        assert!(!response.question.is_empty() && response.question.len() <= 253);
        assert!(response.question.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
        assert!(response.addresses.len() <= 64);
        assert!(response.public_names.len() <= 8);
        for (name, _) in &response.public_names {
            assert!(!name.is_empty() && name.len() <= 253);
            assert!(name.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
        }
    }
});
