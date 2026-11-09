//! Fuzzing of Watch's reader of QUIC Initial packets (`datapavan_net::quic`): any datagrams an app
//! sends. The input is a series of datagrams, each after its length in two bytes. The first byte
//! chooses how they are read: as datagrams, protection and all, or as the frames of Initial packets
//! whose protection is already removed, since random bytes almost never decrypt to frames and the
//! reassembly would stay out of reach. A name found must be printable ASCII in lower case.
#![no_main]

use datapavan_net::quic::Initial;
use datapavan_net::tls::ServerName;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, mut rest)) = data.split_first() else {
        return;
    };
    let mut initial = Initial::new();
    while rest.len() >= 2 {
        let length = usize::from(u16::from_be_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let (datagram, after) = rest[2..].split_at(length);
        rest = after;
        let read = if mode & 1 == 0 {
            initial.push(datagram)
        } else {
            initial.push_frames(datagram)
        };
        match read {
            ServerName::Found(hello) => {
                assert!(!hello.name.is_empty() && hello.name.len() <= 253);
                assert!(hello.name.bytes().all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase()));
                assert!(initial.is_quic());
                return;
            }
            ServerName::None => return,
            ServerName::Incomplete => {}
        }
    }
});
