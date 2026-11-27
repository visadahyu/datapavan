//! The forwarder's pure tests: the shared vectors, each fed whole, cut at every byte and byte by byte; the gate's bounds
//! (m2); a second reader's view of every rewritten head; and the growth of the buffers by replacement (m3).

use super::*;
use crate::proxies::{self, Asked, Declared, Kind};

/// How a flow went, as a vector's first column names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Way {
    Forward,
    Connect,
    Reset,
}

/// A vector's bytes, `\r`, `\n`, `\t`, `\\` and `\xNN` unescaped.
fn unescaped(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        match bytes[i + 1] {
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'\\' => out.push(b'\\'),
            b'x' => {
                let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("00");
                out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
                i += 2;
            }
            other => unreachable!("escape {other}"),
        }
        i += 2;
    }
    out
}

/// The app's bytes `app`, to `destination`, whose names Datapavan's own resolvers gave are `names`, fed in pieces cut
/// at `cuts`, as the engine's stage feeds them: the way, the reason and the bytes to the proxy.
fn run(
    app: &[u8],
    destination: SocketAddr,
    names: &[&str],
    cuts: &[usize],
) -> (Way, Option<Why>, Vec<u8>) {
    let mut pieces = Vec::new();
    let mut at = 0;
    for &cut in cuts.iter().chain([app.len()].iter()) {
        let cut = cut.clamp(at, app.len());
        pieces.push(&app[at..cut]);
        at = cut;
    }
    let mut held = Zeroizing::new(Vec::new());
    let mut out = Zeroizing::new(Vec::new());
    let mut forward: Option<Forward> = None;
    for piece in pieces {
        if let Some(f) = forward.as_mut() {
            if let Err(why) = f.feed(piece, &mut out) {
                return (Way::Reset, Some(why), out.to_vec());
            }
            continue;
        }
        let before = held.len();
        put(&mut held, piece);
        let end = match head_end(&held, before) {
            Ok(Some(end)) => end,
            Ok(None) => continue,
            Err(why) => return (Way::Connect, Some(why), Vec::new()),
        };
        let checked =
            first(&held[..end], destination, &mut out).and_then(|first| match &first.name {
                Some(name) if !names.contains(&name.as_str()) => Err(Why::Unbound),
                _ => Ok(first.forward),
            });
        match checked {
            Ok(mut f) => {
                if let Err(why) = f.feed(&held[end..], &mut out) {
                    return (Way::Reset, Some(why), out.to_vec());
                }
                forward = Some(f);
            }
            Err(why) => return (Way::Connect, Some(why), Vec::new()),
        }
    }
    (Way::Forward, None, out.to_vec())
}

/// A vector: its line number, the way, the reason, the destination, the names, the app's bytes and the proxy's.
type Vector = (
    usize,
    Way,
    Option<String>,
    SocketAddr,
    Vec<String>,
    Vec<u8>,
    Vec<u8>,
);

/// Each vector: its line number, the way, the reason, the destination, the names, the app's bytes and the proxy's.
fn vectors() -> Vec<Vector> {
    include_str!("../../testdata/forward-requests.tsv")
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            !line.starts_with('#') && !line.starts_with("way\t") && !line.is_empty()
        })
        .map(|(n, line)| {
            let c: Vec<&str> = line.split('\t').collect();
            assert!(c.len() >= 6, "line {}", n + 1);
            let way = match c[0] {
                "forward" => Way::Forward,
                "connect" => Way::Connect,
                "reset" => Way::Reset,
                other => unreachable!("way {other}"),
            };
            let why = (c[1] != "-").then(|| c[1].to_owned());
            let destination = c[2].parse().unwrap_or_else(|_| unreachable!("{}", c[2]));
            let names = c[3]
                .split(',')
                .filter(|n| !n.is_empty())
                .map(str::to_owned)
                .collect();
            (
                n + 1,
                way,
                why,
                destination,
                names,
                unescaped(c[4]),
                unescaped(c[5]),
            )
        })
        .collect()
}

#[test]
fn every_vector_goes_its_way_whole_cut_at_every_byte_and_byte_by_byte() {
    let all = vectors();
    assert!(all.len() > 100, "{} vectors", all.len());
    for (line, way, why, destination, names, app, proxy) in all {
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let whole = run(&app, destination, &names, &[]);
        assert_eq!(whole.0, way, "line {line}: {:?}", whole.1);
        assert_eq!(whole.1.map(|w| format!("{w:?}")), why, "line {line}");
        assert_eq!(
            whole.2,
            proxy,
            "line {line}: {}",
            String::from_utf8_lossy(&whole.2)
        );
        for cut in 0..=app.len() {
            assert_eq!(
                run(&app, destination, &names, &[cut]),
                whole,
                "line {line}, cut at {cut}"
            );
        }
        let bytes: Vec<usize> = (1..app.len()).collect();
        assert_eq!(
            run(&app, destination, &names, &bytes),
            whole,
            "line {line}, byte by byte"
        );
    }
}

#[test]
fn only_each_request_line_changes() {
    for (line, way, _, destination, _, app, proxy) in vectors() {
        if way != Way::Forward
            || app
                .windows(8)
                .filter(|w| w.starts_with(b" HTTP/1."))
                .count()
                > 1
        {
            continue;
        }
        let tail = |bytes: &[u8]| -> Vec<u8> {
            let mut kept = Vec::new();
            let mut rest = bytes;
            while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
                let (line, after) = rest.split_at(line_end + 2);
                if !line.starts_with(b"GET ")
                    && !line.starts_with(b"POST ")
                    && !line.starts_with(b"PUT ")
                    && !line.starts_with(b"HEAD ")
                    && !line.starts_with(b"PATCH ")
                    && !line.starts_with(b"DELETE ")
                    && !line.starts_with(b"OPTIONS ")
                {
                    kept.extend_from_slice(line);
                }
                rest = after;
            }
            kept.extend_from_slice(rest);
            kept
        };
        assert_eq!(tail(&app), tail(&proxy), "line {line}");
        // A second reader, written before this one, reads each rewritten head as a plain proxy request to the flow's
        // host and port.
        match proxies::declared(&proxy) {
            Declared::Request(request) => {
                assert_eq!(request.kind, Kind::Forward, "line {line}");
                assert_eq!(request.port, destination.port(), "line {line}");
                if let Asked::Address(address) = request.asked {
                    assert_eq!(
                        address.to_canonical(),
                        destination.ip().to_canonical(),
                        "line {line}"
                    );
                }
            }
            other => unreachable!("line {line}: {other:?}"),
        }
    }
}

/// A head whose `Host` line ends at byte `at` (its LF the `at`th byte), a field of padding before it.
fn host_at(at: usize, host: &str) -> Vec<u8> {
    let start = b"GET / HTTP/1.1\r\nX-Pad: ";
    let line = format!("\r\nHost: {host}\r\n");
    let pad = at - start.len() - line.len();
    let mut head = start.to_vec();
    head.extend(std::iter::repeat_n(b'a', pad));
    head.extend_from_slice(line.as_bytes());
    assert_eq!(head.len(), at);
    head.extend_from_slice(b"\r\n");
    head
}

#[test]
fn a_host_the_gate_cannot_read_is_never_forwarded() {
    let destination: SocketAddr = "198.51.100.9:80".parse().unwrap_or_else(|_| unreachable!());
    for at in [8_190, 8_191, 8_192, 8_193, 9_000] {
        let head = host_at(at, "example.test");
        let gate = http_host(&head);
        let forwarded = run(&head, destination, &["example.test"], &[]);
        assert_eq!(
            forwarded.0 == Way::Forward,
            gate == HttpHost::Found("example.test".into()),
            "LF at {at}: {gate:?}"
        );
        assert_eq!(forwarded.0 == Way::Forward, at <= 8_192, "LF at {at}");
    }
    let label = "a".repeat(63);
    let name = format!("{label}.{label}.{label}.{}", "b".repeat(61));
    assert_eq!(name.len(), 253);
    let head = format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n");
    assert_eq!(
        run(head.as_bytes(), destination, &[name.as_str()], &[]).0,
        Way::Forward
    );
    let dotted = format!("GET / HTTP/1.1\r\nHost: {name}.\r\n\r\n");
    assert_eq!(
        run(dotted.as_bytes(), destination, &[name.as_str()], &[]).1,
        Some(Why::Host)
    );
    let long = format!("GET / HTTP/1.1\r\nHost: {name}b\r\n\r\n");
    assert_eq!(
        run(long.as_bytes(), destination, &[], &[]).1,
        Some(Why::Host)
    );
}

#[test]
fn a_head_ends_within_its_bound_or_is_refused() {
    let destination: SocketAddr = "198.51.100.9:80".parse().unwrap_or_else(|_| unreachable!());
    let mut head = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Pad: ".to_vec();
    head.extend(std::iter::repeat_n(b'c', MAX_HEAD - head.len() - 4));
    head.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head.len(), MAX_HEAD);
    let mut out = Zeroizing::new(Vec::new());
    assert_eq!(first(&head, destination, &mut out).err(), None);
    head.insert(45, b'c');
    assert_eq!(
        first(&head, destination, &mut out).err(),
        Some(Why::TooLong)
    );
    // A later head past the bound resets the connection.
    let mut keep = Zeroizing::new(Vec::new());
    let mut f = first(
        b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
        destination,
        &mut keep,
    )
    .unwrap_or_else(|_| unreachable!())
    .forward;
    assert_eq!(f.feed(&head, &mut keep), Err(Why::TooLong));
}

#[test]
fn a_buffer_grows_only_by_replacement() {
    let mut buffer = Zeroizing::new(Vec::with_capacity(256));
    buffer.extend_from_slice(&[7u8; 256]);
    let before = buffer.as_ptr();
    reserve(&mut buffer, 1);
    assert_ne!(buffer.as_ptr(), before, "a new allocation");
    assert!(buffer.capacity() >= 512);
    assert_eq!(&buffer[..], &[7u8; 256][..]);
    let kept = buffer.as_ptr();
    put(&mut buffer, &[8u8; 100]);
    assert_eq!(buffer.as_ptr(), kept, "room enough: no move");
}
