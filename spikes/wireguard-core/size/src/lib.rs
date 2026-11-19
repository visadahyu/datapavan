//! core/watch-jni's library, its source file included unchanged, and, with the `ring` or `aws-lc` feature,
//! one more export that runs a WireGuard session between two of GotaTun's `Tunn`s: the handshake with a
//! preshared key, the queued first packet, a data packet each way, the timers and the counters. What W7's
//! engine calls is then in the library, and nothing of it can be dropped as dead code.

#[allow(missing_docs, clippy::all)]
#[path = "../../../../core/watch-jni/src/lib.rs"]
mod watch;

#[cfg(any(feature = "ring", feature = "aws-lc"))]
#[path = "../../common/pair.rs"]
mod pair;

/// Runs the session with keys and packets taken from `seed`, and returns a sum of what came out, so that
/// none of it is computed ahead.
#[cfg(any(feature = "ring", feature = "aws-lc"))]
#[unsafe(no_mangle)]
pub extern "C" fn datapavan_wg_probe(seed: u64) -> u64 {
    use gotatun::noise::TunnResult;
    use gotatun::tun::MtuWatcher;

    let mut mtu = MtuWatcher::new(1280);
    let psk = (seed & 1 == 1).then_some([seed as u8; 32]);
    let (mut phone, mut server) = pair::pair(seed as u8, psk, Some(25));
    let first = pair::ipv4_udp(seed, 40 + (seed % 200) as usize);
    let Some(first) = pair::connect(&mut phone, &mut server, &mut mtu, first) else { return 0 };
    let mut total = first.len() as u64;
    if let Some(answer) = server.tunn.handle_outgoing_packet(pair::ipv4_udp(seed ^ 1, 100), Some(&mut mtu)) {
        if let TunnResult::WriteToTunnel(packet) = pair::deliver(&mut phone, answer) {
            if let Ok(ip) = packet.try_into_ipvx() {
                total += ip.either(|v4| v4.into_bytes().len(), |v6| v6.into_bytes().len()) as u64;
            }
        }
    }
    for side in [&mut phone, &mut server] {
        if let Ok(Some(_)) = side.tunn.update_timers() {
            total += 1;
        }
    }
    let (_, sent, received, _, _) = phone.tunn.stats();
    total + sent as u64 + received as u64
}
