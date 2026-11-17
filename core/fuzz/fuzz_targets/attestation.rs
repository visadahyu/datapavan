//! Arbitrary bytes as an attestation extension: the parser must return, never panic, overflow or
//! hang. Overflow checks are on in fuzz builds, as in release builds.
//!
//! Random bytes seldom get past an extension's outer elements, so the same bytes are also put where
//! the parser's inner paths read them, inside a valid extension whose every enclosing length is
//! encoded again: as each authorization list, and as the content of a `rootOfTrust`. There these
//! properties of ADR 0040's decision 5 must hold, whatever the bytes: a trusted environment's values
//! come from its hardware-enforced list alone, a software attestation's from its software-enforced
//! list alone, and a malformed root of trust leaves the rest of the extension readable.
#![no_main]

use datapavan_engine::attestation::parse_key_description;
use libfuzzer_sys::fuzz_target;

/// One DER element, with its length in the shortest form.
fn der(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let length = content.len();
    if let Ok(short) = u8::try_from(length)
        && short < 0x80
    {
        out.push(short);
    } else {
        let digits: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | u8::try_from(digits.len()).unwrap_or_default());
        out.extend(digits);
    }
    out.extend_from_slice(content);
    out
}

/// An extension with attestation version 300 at `level` for both the attestation and the key,
/// whose lists hold the given entries.
fn extension(level: u8, software: &[u8], hardware: &[u8]) -> Vec<u8> {
    let fields = [
        der(&[0x02], &[0x01, 0x2c]),
        der(&[0x0a], &[level]),
        der(&[0x02], &[0x01, 0x2c]),
        der(&[0x0a], &[level]),
        der(&[0x04], b"challenge"),
        der(&[0x04], &[]),
        der(&[0x30], software),
        der(&[0x30], hardware),
    ]
    .concat();
    der(&[0x04], &der(&[0x30], &fields))
}

/// A `[704] rootOfTrust` entry whose SEQUENCE holds `content`.
fn root_of_trust(content: &[u8]) -> Vec<u8> {
    der(&[0xbf, 0x85, 0x40], &der(&[0x30], content))
}

/// The `rootOfTrust` and `osPatchLevel` entries of a list.
fn entries(locked: u8, boot: u8, patch: [u8; 3]) -> Vec<u8> {
    let root = [
        der(&[0x04], &[0xaa; 32]),
        der(&[0x01], &[locked]),
        der(&[0x0a], &[boot]),
    ]
    .concat();
    [
        root_of_trust(&root),
        der(&[0xbf, 0x85, 0x42], &der(&[0x02], &patch)),
    ]
    .concat()
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_key_description(data);

    // Locked and verified, patched 2025-07, in hardware; unlocked and unverified, patched 2026-08,
    // in software. Each list is also tried empty, so that a value the parser took from the wrong
    // list would show, not only one it preferred over the right list's.
    let hardware = entries(0xff, 0, [0x03, 0x17, 0x0b]);
    let software = entries(0x00, 2, [0x03, 0x17, 0x70]);
    // An extension at `level` whose authoritative list holds `read` and whose other list `other`.
    let build = |level: u8, read: &[u8], other: &[u8]| match level {
        0 => extension(0, read, other),
        _ => extension(level, other, read),
    };
    for (level, read) in [
        (1, &hardware[..]),
        (2, &hardware[..]),
        (1, &[][..]),
        (0, &software[..]),
        (0, &[][..]),
    ] {
        let expected = parse_key_description(&build(level, read, &[]));
        assert!(expected.is_ok());
        // Whatever the other list holds, the values are the authoritative list's.
        let parsed = parse_key_description(&build(level, read, data));
        assert!(parsed.is_err() || parsed == expected, "{parsed:?}");
    }

    // The bytes as the list the parser reads, and as a rootOfTrust: a malformed root of trust is
    // absent, and never makes the rest of the extension fail.
    let _ = parse_key_description(&extension(1, &[], data));
    let root = parse_key_description(&extension(1, &[], &root_of_trust(data)));
    assert!(root.is_ok(), "{root:?}");
});
