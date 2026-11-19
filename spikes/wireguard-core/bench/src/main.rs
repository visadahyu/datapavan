//! Tunn's encapsulation, then the peer's decapsulation, per packet, on one core (W7's spike, ADR 0035).
//!
//!   wg-bench [--cpu N] [--seconds S] [--sizes 1280,1420] [--mtu 1420]
//!
//! The thread is pinned to core N (default: the core it starts on) and, for each size, runs batches of
//! 256 packets through an established session: the phone's `handle_outgoing_packet` (with the TUN's MTU,
//! so data is padded as W7 sends it), then the server's `RateLimiter::verify_packet` and
//! `handle_incoming_packet`, as a datagram from the socket would go. Building the input packets is left
//! out of the time. It prints one tab-separated line per size: the backend, the architecture, the core,
//! the size, nanoseconds per packet to encapsulate, to decapsulate and both, milliseconds per megabyte
//! (10^6 bytes of IP packets) for both, the thread's CPU time over the wall time (1.00: the core was its
//! own), and the packets measured.

use std::time::{Duration, Instant};

use bytes::BytesMut;
use gotatun::noise::TunnResult;
use gotatun::packet::{Packet, WgKind};
use gotatun::tun::MtuWatcher;
use nix::sched::{CpuSet, sched_getcpu, sched_setaffinity};
use nix::time::{ClockId, clock_gettime};
use nix::unistd::Pid;

#[path = "../../common/pair.rs"]
mod pair;

const BATCH: usize = 256;
const BACKEND: &str = if cfg!(feature = "aws-lc") { "aws-lc-rs" } else { "ring" };

fn thread_cpu() -> Duration {
    clock_gettime(ClockId::CLOCK_THREAD_CPUTIME_ID)
        .map(Duration::from)
        .unwrap_or_default()
}

struct Run {
    encap: Duration,
    decap: Duration,
    packets: u64,
    cpu: Duration,
    wall: Duration,
}

/// Runs batches of `size`-byte packets for `seconds`.
fn run(size: usize, mtu: u16, seconds: f64) -> Run {
    let mut tun_mtu = MtuWatcher::new(mtu);
    let (mut phone, mut server) = pair::pair(7, Some([9; 32]), None);
    let first = pair::ipv4_udp(1, size);
    assert!(
        pair::connect(&mut phone, &mut server, &mut tun_mtu, first).is_some(),
        "the handshake failed"
    );
    let template: Vec<u8> = AsRef::<[u8]>::as_ref(&pair::ipv4_udp(2, size)).to_vec();
    let mut sink = 0usize;
    let mut batch = |phone: &mut pair::Side, server: &mut pair::Side, timed: &mut Run| {
        let inputs: Vec<Packet> = (0..BATCH)
            .map(|_| Packet::from_bytes(BytesMut::from(&template[..])))
            .collect();
        let mut datagrams: Vec<WgKind> = Vec::with_capacity(BATCH);
        let start = Instant::now();
        for packet in inputs {
            if let Some(datagram) = phone.tunn.handle_outgoing_packet(packet, Some(&mut tun_mtu)) {
                datagrams.push(datagram);
            }
        }
        let encapsulated = Instant::now();
        for datagram in datagrams {
            if let TunnResult::WriteToTunnel(packet) = pair::deliver(server, datagram) {
                sink += packet.len();
            }
        }
        let end = Instant::now();
        timed.encap += encapsulated - start;
        timed.decap += end - encapsulated;
        timed.packets += BATCH as u64;
    };
    let mut warm = Run {
        encap: Duration::ZERO,
        decap: Duration::ZERO,
        packets: 0,
        cpu: Duration::ZERO,
        wall: Duration::ZERO,
    };
    let warm_until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < warm_until {
        batch(&mut phone, &mut server, &mut warm);
    }
    let mut timed = Run { packets: 0, ..warm };
    timed.encap = Duration::ZERO;
    timed.decap = Duration::ZERO;
    let (wall_start, cpu_start) = (Instant::now(), thread_cpu());
    let until = wall_start + Duration::from_secs_f64(seconds);
    while Instant::now() < until {
        batch(&mut phone, &mut server, &mut timed);
    }
    timed.wall = wall_start.elapsed();
    timed.cpu = thread_cpu().saturating_sub(cpu_start);
    assert_eq!(
        sink as u64,
        (warm.packets + timed.packets) * size as u64,
        "a packet was lost"
    );
    timed
}

fn main() {
    let mut cpu: Option<usize> = None;
    let mut seconds = 3.0;
    let mut sizes = vec![1280usize, 1420];
    let mut mtu = 1420u16;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args.next().unwrap_or_default();
        match arg.as_str() {
            "--cpu" => cpu = value.parse().ok(),
            "--seconds" => seconds = value.parse().unwrap_or(seconds),
            "--sizes" => sizes = value.split(',').filter_map(|s| s.parse().ok()).collect(),
            "--mtu" => mtu = value.parse().unwrap_or(mtu),
            _ => {
                eprintln!("usage: wg-bench [--cpu N] [--seconds S] [--sizes 1280,1420] [--mtu 1420]");
                std::process::exit(2);
            }
        }
    }
    let core = cpu.unwrap_or_else(|| sched_getcpu().unwrap_or(0));
    let mut set = CpuSet::new();
    if set
        .set(core)
        .and_then(|()| sched_setaffinity(Pid::from_raw(0), &set))
        .is_err()
    {
        eprintln!("cannot pin to core {core}");
        std::process::exit(1);
    }
    println!("backend\tarch\tcore\tsize\tencap_ns\tdecap_ns\tboth_ns\tms_per_MB\tcpu_over_wall\tpackets");
    for size in sizes {
        let r = run(size, mtu, seconds);
        let per = |d: Duration| d.as_nanos() as f64 / r.packets as f64;
        let (encap, decap) = (per(r.encap), per(r.decap));
        let both = encap + decap;
        println!(
            "{BACKEND}\t{}\t{core}\t{size}\t{encap:.0}\t{decap:.0}\t{both:.0}\t{:.3}\t{:.2}\t{}",
            std::env::consts::ARCH,
            both / size as f64,
            r.cpu.as_secs_f64() / r.wall.as_secs_f64(),
            r.packets,
        );
    }
}
