//! Arbitrary bytes as a DEX file from another app's package: the parser must return, never panic,
//! overflow or hang.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = datapavan_engine::dex::defined_classes(data);
});
