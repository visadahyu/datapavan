//! Arbitrary bytes as an attestation extension: the parser must return, never panic, overflow or
//! hang. Overflow checks are on in fuzz builds, as in release builds.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = datapavan_engine::attestation::parse_key_description(data);
});
