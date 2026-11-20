//! Fuzzing of the reader of the ways' datasets (`datapavan_net::catalogue`, W8, part 1): any text a data pack may
//! carry, split in four tables at the first three form feeds. Every default pair read passes the pair rule, every
//! index is in range, and the user's setting read over it never names an entry the tables lack.
#![no_main]

use datapavan_net::catalogue::Catalogue;
use datapavan_net::{Choice, DnsConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.splitn(5, '\u{c}');
    let (relays, targets, pairs, presets, setting) = (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    );
    let catalogue = Catalogue::parse(relays, targets, pairs, presets);
    for &(r, t) in &catalogue.pairs {
        assert!(r < catalogue.relays.len() && t < catalogue.targets.len());
        assert_eq!(catalogue.relays[r].behind.clash(&catalogue.targets[t].behind), None);
    }
    let config = DnsConfig::read(catalogue, setting);
    for &(r, t) in &config.pairs {
        assert!(r < config.catalogue.relays.len() && t < config.catalogue.targets.len());
        assert_eq!(config.catalogue.relays[r].behind.clash(&config.catalogue.targets[t].behind), None);
    }
    if let Choice::Preset(i) = config.choice {
        assert!(i < config.catalogue.presets.len());
    }
});
