//! Fuzzing of what a direct app's query becomes on its way to an encrypted resolver, and the answer on its way back
//! (`datapavan_net::hygiene`, W8, part 1): any bytes an app or a resolver can send. A query read goes upstream with
//! ID 0, padded to 128-byte blocks, and is read back as the same question; an answer made the app's carries the
//! app's ID, fits the app's UDP size, and is read again as an answer to the same question.
#![no_main]

use datapavan_net::hygiene;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(asked) = hygiene::read(data) {
        let up = asked.upstream(true);
        assert_eq!(up.len() % hygiene::QUERY_BLOCK, 0);
        assert_eq!(up.get(..2), Some(&[0u8, 0][..]));
        let again = hygiene::read(&up).expect("the upstream query reads");
        assert_eq!((&again.name, again.kind, again.class), (&asked.name, asked.kind, asked.class));
        assert!(asked.failure().is_some());
    }
    // The bytes as a resolver's answer to a fixed question.
    let asked = hygiene::query_for("www.example.com", 1).expect("a query");
    for limit in [Some(asked.udp_limit()), None] {
        if let Some(mine) = asked.answer(data, limit) {
            assert_eq!(mine.get(..2), Some(&[0u8, 0][..]));
            if let Some(limit) = limit {
                assert!(mine.len() <= limit.max(512));
            }
            assert!(asked.answer(&mine, None).is_some(), "an answer stays one");
        }
    }
});
