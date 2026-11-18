//! Fuzzing of the engine's reader of the apps' states that Watch's Kotlin side tells it
//! (`datapavan_net::states`, ADR 0046, decision 1). Any bytes: a message that is read must write back
//! to the same bytes, with its span forward, every interval inside it and of a state other than the
//! background, and none where nothing is known; anything else is refused without a panic.
#![no_main]

use datapavan_net::states::{self, Known, State};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(told) = states::read(data) {
        assert_eq!(states::write(&told), data);
        assert!(told.from <= told.until);
        assert!(told.known == Known::States || told.intervals.is_empty());
        for interval in &told.intervals {
            assert!(told.from <= interval.from && interval.from < interval.until);
            assert!(interval.until <= told.until);
            assert!(interval.state != State::Background);
        }
    }
});
