//! Fuzzing of the network part's side of Oblivious DoH (`datapavan_net::odoh`, W8, part 1): any bytes a target may
//! serve as its configurations or a relay may send back as an answer, and any HTTPS record a resolver may send. A key
//! read from them seals a query whose bytes start as an ODoH query does; an answer that is not the target's to that
//! very query never opens; the `odohconfig` parameter of a record is read without panicking. The engine's own HPKE (fix
//! round): any encapsulated key and ciphertext are refused, or opened, without panicking.
#![no_main]

use datapavan_net::{dns, hpke, odoh};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dns::svc_param(data, "odoh.example", odoh::KEY_ODOHCONFIG);
    let _ = odoh::configs_in_https(data, "target.example");
    if let Some(key) = odoh::TargetKey::parse(data) {
        assert_eq!(key.configs(), data);
        if let Some(sealed) = odoh::seal(&key, b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01", 0) {
            // Type 1 (a query), then the key's identifier of 32 bytes.
            assert_eq!(sealed.body.first(), Some(&1));
            assert_eq!(sealed.body.get(1..3), Some(&[0u8, 32][..]));
            // Bytes nobody sealed for this query never open.
            assert_eq!(odoh::open(&sealed, data), None);
        }
    }
    if let Some((enc, rest)) = data.split_first_chunk::<32>() {
        if let Some(mut context) = hpke::setup_receiver(enc, &[7; 32], b"odoh query") {
            let _ = context.open(b"", rest);
        }
        let _ = hpke::open_aead(&[7; 16], [9; 12], enc, rest);
    }
});
