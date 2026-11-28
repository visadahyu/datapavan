//! The forwarder's pure tests: the shared vectors, each fed whole, cut at every byte and byte by byte; the gate's bounds
//! (m2); a second reader's view of every rewritten head; and the growth of the buffers by replacement (m3).

use super::*;
use crate::blocking::http_host;
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
                match f.feed(&held[end..], &mut out) {
                    // The first request's trailer with its head: the stage sends the flow as a head it may not carry.
                    Err(Why::Trailers) if f.first_request() => {
                        return (Way::Connect, Some(Why::Trailers), Vec::new());
                    }
                    Err(why) => return (Way::Reset, Some(why), out.to_vec()),
                    Ok(()) => {}
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

/// Whether the proxy lab can carry a row of `way` to `destination` with `names`, as its `check.py` reads it
/// (`carried_by_the_lab`): a forward row, IPv4 to its table's address on port 80 or 8080, by that address or the name
/// `example.test`.
fn carried_by_the_lab(way: &str, destination: &str, names: &str) -> bool {
    let (address, port) = destination.rsplit_once(':').unwrap_or_default();
    way == "forward"
        && address == "198.51.100.9"
        && (port == "80" || port == "8080")
        && names
            .split(',')
            .all(|n| n.is_empty() || n == "example.test")
}

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
            // The proxy lab's two columns too, measured on every forward row it can carry (the other review's M2).
            assert_eq!(c.len(), 8, "line {}", n + 1);
            assert!(
                !carried_by_the_lab(c[0], c[2], c[3]) || (c[6] != "-" && c[7] != "-"),
                "line {}: a forward row the proxy lab carries, its squid and tinyproxy cells measured",
                n + 1
            );
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
        // A first request's trailer read after its head went resets the connection, the head and the chunks before
        // the last one written: the way of every cut that parts them, as of the bytes fed one by one.
        let bytes: Vec<usize> = (1..app.len()).collect();
        let one_by_one = run(&app, destination, &names, &bytes);
        if whole.0 == Way::Connect && whole.1 == Some(Why::Trailers) {
            assert_eq!(one_by_one.0, Way::Reset, "line {line}");
            assert_eq!(one_by_one.1, Some(Why::Trailers), "line {line}");
            assert!(!one_by_one.2.ends_with(b"0\r\n"), "line {line}");
        } else {
            assert_eq!(one_by_one, whole, "line {line}, byte by byte");
        }
        for cut in 0..=app.len() {
            let piece = run(&app, destination, &names, &[cut]);
            assert!(
                piece == whole || piece == one_by_one,
                "line {line}, cut at {cut}: {piece:?}"
            );
        }
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
                if line.len() > 18 && lower_eq(&line[..18], b"transfer-encoding:") {
                    kept.extend_from_slice(&line[..17]);
                    kept.extend_from_slice(b": chunked\r\n");
                } else if !line.starts_with(b"GET ")
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
fn a_head_with_no_host_names_the_flows_own_address_and_port() {
    for (destination, written) in [
        ("198.51.100.9:80", "198.51.100.9"),
        ("198.51.100.9:65535", "198.51.100.9:65535"),
        ("[2001:db8::9]:80", "[2001:db8::9]"),
        ("[2001:db8::9]:8080", "[2001:db8::9]:8080"),
        ("[::ffff:198.51.100.9]:80", "198.51.100.9"),
        ("[::ffff:198.51.100.9]:81", "198.51.100.9:81"),
        ("[::1]:1", "[::1]:1"),
    ] {
        let destination: SocketAddr = destination.parse().unwrap_or_else(|_| unreachable!());
        let mut out = Zeroizing::new(Vec::new());
        assert!(first(b"GET /a HTTP/1.0\r\n\r\n", destination, &mut out).is_ok());
        assert_eq!(
            &out[..],
            format!("GET http://{written}/a HTTP/1.0\r\n\r\n").as_bytes(),
            "{destination}"
        );
    }
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

/// A chunked body's trailer is never forwarded (the proxy lab: tinyproxy 1.11.2 knows none and reads it as the next
/// request): read after its head went, the connection is refused with the head and the chunks before the last one
/// written, and the last chunk's line held back, so that no proxy reads an end of the body; with its head, the first
/// feed refuses it before anything is written. The CRLF that ends a body with no trailer passes it whole.
#[test]
fn a_trailer_is_refused_and_the_last_chunk_held_back() {
    let to = SocketAddr::from(([198, 51, 100, 9], 80));
    let head = b"PUT /t HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
    let mut out = Zeroizing::new(Vec::new());
    let Ok(mut first) = first(head, to, &mut out) else {
        unreachable!("a head the reader takes");
    };
    let mut framer = first.forward;
    assert_eq!(framer.feed(b"3\r\nabc\r\n0\r", &mut out), Ok(()));
    assert!(
        out.ends_with(b"3\r\nabc\r\n"),
        "{:?}",
        String::from_utf8_lossy(&out)
    );
    let written = out.len();
    assert_eq!(
        framer.feed(b"\nX-Sum: 1\r\n\r\n", &mut out),
        Err(Why::Trailers)
    );
    assert_eq!(
        out.len(),
        written,
        "nothing of the last chunk or its trailer"
    );

    out.clear();
    first = match super::first(head, to, &mut out) {
        Ok(first) => first,
        Err(why) => unreachable!("{why:?}"),
    };
    framer = first.forward;
    let head_only = out.len();
    assert_eq!(framer.feed(b"0\r\n\r", &mut out), Ok(()));
    assert_eq!(out.len(), head_only, "the last chunk's line held");
    assert_eq!(
        framer.feed(b"\nGET / HTTP/1.1\r\nHost: example.test\r\n\r\n", &mut out),
        Ok(())
    );
    assert!(out[head_only..].starts_with(b"0\r\n\r\nGET http://example.test/ HTTP/1.1\r\n"));
}

/// The review's m3: a request line is refused at its first byte that no request line could hold, before its end and
/// before any blank line, so that a line protocol that speaks first is not awaited until the flow's time runs out;
/// a line that may still be one is awaited.
#[test]
fn a_request_line_is_refused_at_its_first_byte_none_could_hold() {
    for (bytes, why) in [
        (&b"NICK a"[..], Why::Target),
        (b"SET k", Why::Target),
        (b"USER a 0 * :b", Why::Target),
        (b"CONNECT a", Why::Target),
        (b"GET *", Why::Target),
        (b"OPTIONS *x", Why::Target),
        (b"GET /a#", Why::Target),
        (b"GET  ", Why::Target),
        (b"GET / H2", Why::Version),
        (b"GET / HTTP/1.2", Why::Version),
        (b"GET / HTTP/1.1x", Why::Version),
        (b"GET / HTTP/1.1 ", Why::Line),
        (b"GET / HTTP/1.\r", Why::Version),
        (b"GET /\r", Why::Line),
    ] {
        assert_eq!(
            head_end(bytes, 0),
            Err(why),
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    for bytes in [
        &b"GET"[..],
        b"GET ",
        b"GET /",
        b"GET /p?q ",
        b"OPTIONS * HTTP/1.",
        b"GET / HTTP/1.1\r\n",
    ] {
        assert_eq!(
            head_end(bytes, 0),
            Ok(None),
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    // A line past its bound is refused once it passed it, and a line within it read once whole.
    let mut long = b"GET /".to_vec();
    long.resize(MAX_LINE, b'a');
    assert_eq!(head_end(&long, 0), Ok(None));
    long.push(b'a');
    assert_eq!(head_end(&long, 0), Err(Why::TooLong));
    long.truncate(MAX_LINE - 9);
    long.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n");
    let read = long.len();
    long.extend(std::iter::repeat_n(b'b', 2 * MAX_LINE));
    long.extend_from_slice(b": c\r\n\r\n");
    assert_eq!(head_end(&long[..read], 0), Ok(None));
    assert_eq!(head_end(&long, read), Ok(Some(long.len())));
    assert_eq!(head_end(&long, 0), Ok(Some(long.len())));
}

/// The review's m2: no size or length this reader takes overflows a proxy's signed 64-bit integer once the CRLF's 2
/// is added (tinyproxy 1.11.2): a chunk size of 15 hex digits is taken, of 16 refused, leading zeros counted; a
/// length of 2^63 − 1 is taken, of 2^63 refused.
#[test]
fn sizes_and_lengths_stay_within_a_signed_64_bit_integer() {
    let to = SocketAddr::from(([198, 51, 100, 9], 80));
    let chunked = b"PUT /t HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
    for (size, taken) in [
        (&b"FFFFFFFFFFFFFFF"[..], true),
        (b"000000000000005", true),
        (b"FFFFFFFFFFFFFFFF", false),
        (b"7FFFFFFFFFFFFFFE", false),
        (b"0000000000000005", false),
    ] {
        let mut out = Zeroizing::new(Vec::new());
        let Ok(first) = first(chunked, to, &mut out) else {
            unreachable!("a head the reader takes");
        };
        let mut framer = first.forward;
        let mut line = size.to_vec();
        line.extend_from_slice(b"\r\nhello");
        let fed = framer.feed(&line, &mut out);
        assert_eq!(fed.is_ok(), taken, "{:?}", String::from_utf8_lossy(size));
        if taken {
            assert!(
                out.ends_with(&line),
                "the size line and the data as they came"
            );
        } else {
            assert_eq!(fed, Err(Why::Chunk));
        }
    }
    for (length, taken) in [
        ("9223372036854775807", true),
        ("9223372036854775808", false),
    ] {
        let head =
            format!("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: {length}\r\n\r\n");
        let mut out = Zeroizing::new(Vec::new());
        let read = first(head.as_bytes(), to, &mut out).map(|_| ());
        assert_eq!(
            read,
            if taken { Ok(()) } else { Err(Why::Framing) },
            "{length}"
        );
    }
}

/// The review's note 3: the stage's first head, read at most to its bound and one byte, grows to that and no further,
/// where [`reserve`]'s doubling would take twice it.
#[test]
fn a_bounded_buffer_grows_no_further_than_its_bound() {
    let mut held = Zeroizing::new(Vec::new());
    let mut doubled = Zeroizing::new(Vec::new());
    while held.len() <= MAX_HEAD {
        let room = (MAX_HEAD + 1 - held.len()).min(4_096);
        reserve_within(&mut held, room, MAX_HEAD + 1);
        held.extend(std::iter::repeat_n(b'a', room));
        reserve(&mut doubled, room);
        doubled.extend(std::iter::repeat_n(b'a', room));
    }
    assert_eq!(held.len(), MAX_HEAD + 1);
    assert_eq!(held.capacity(), MAX_HEAD + 1);
    assert_eq!(doubled.capacity(), 2 * MAX_HEAD);
}
