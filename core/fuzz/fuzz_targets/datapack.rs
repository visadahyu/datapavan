//! Fuzzing of the data pack reader. The input is read twice: as a signed pack, whose signature
//! check must refuse it without panicking (no input can carry a valid signature by the test key),
//! and as a bare payload, whose header, if it is accepted, must describe the input exactly: every
//! range inside it, the files in ascending order of their paths and filling the rest of it.
#![no_main]

use datapavan_engine::datapack::{Payload, PublicKey, verify};
use libfuzzer_sys::fuzz_target;

/// The test key from `scripts/testdata`.
const TEST_KEY: &[u8] = b"RWSaKiYnaFJUifZRfEPxHyXNGoBK8ZRt44B2pqafPP6DCPmmnxA7fyPR";

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = PublicKey::parse(TEST_KEY) {
        let _ = verify(data, &[key]);
    }
    let Ok(header) = Payload::parse(data) else {
        return;
    };
    let inside = |range: &core::ops::Range<usize>| range.start <= range.end && range.end <= data.len();
    assert!(inside(&header.date));
    assert!(header.keys.iter().chain(&header.revoked).all(inside));
    let mut end = header.files.first().map_or(data.len(), |file| file.data.start);
    for (index, file) in header.files.iter().enumerate() {
        assert!(inside(&file.path) && inside(&file.data));
        assert!(file.path.end < file.data.start);
        assert_eq!(file.data.start, end);
        end = file.data.end;
        if let Some(next) = header.files.get(index + 1) {
            assert!(data[file.path.clone()] < data[next.path.clone()]);
        }
    }
    assert_eq!(end, data.len());
});
