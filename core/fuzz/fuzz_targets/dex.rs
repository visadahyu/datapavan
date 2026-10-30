//! Arbitrary bytes as a DEX file from another app's package: the parser must return, never panic,
//! overflow or hang, and the streaming visitor that the scanner uses must report exactly the
//! classes of the two lists.
#![no_main]

use datapavan_engine::dex::{defined_classes, referenced_classes, visit_classes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (mut defined, mut referenced) = (Vec::new(), Vec::new());
    let visited = visit_classes(data, |name, is_defined| {
        if is_defined {
            defined.push(name.to_owned());
        }
        referenced.push(name.to_owned());
    });
    match (defined_classes(data), referenced_classes(data), visited) {
        (Ok(mut listed_defined), Ok(listed_referenced), Ok(())) => {
            // Two type entries may carry the same name; the lists are compared as sets of names.
            listed_defined.sort();
            listed_defined.dedup();
            defined.sort();
            defined.dedup();
            assert_eq!(defined, listed_defined);
            assert_eq!(referenced, listed_referenced);
        }
        (listed_defined, listed_referenced, visited) => {
            assert!(visited.is_err() && (listed_defined.is_err() || listed_referenced.is_err()));
        }
    }
});
