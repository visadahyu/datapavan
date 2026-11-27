//! Fuzzing of the forwarder's reader, rewrite and framer (`datapavan_net::forward`, the proxy record's forwarder): any
//! bytes an app can send through the network's own proxy where it refused a `CONNECT` to the flow's port. The
//! invariants:
//! - nothing panics or reads past the bytes;
//! - a head cut at any byte gives "more", or the whole head's own answer: a refusal seen early stays a refusal, and an
//!   end found stays that end;
//! - the bytes fed in two pieces, cut where the input says, give the same way and the same bytes to the proxy as one
//!   feed;
//! - an accepted first head is read back by the proxy reader (`proxies::declared`) as a plain proxy request to the
//!   flow's port;
//! - and by hyper's parser, `httparse`, as the same head (the audit's m7): the same end, method, target, version and
//!   field lines, so that a second, widely used reader finds the boundaries this one found.
//!
//! Each input's first byte picks the flow's port (80 when even, 8080 when odd). The seeds are synthetic: OkHttp's, curl's, Chromium's and Python's `requests` heads written by hand, and the
//! smuggling classics (CL.TE, TE.CL, `Transfer-Encoding` obfuscations, chunk lines with a bare LF or an extension, an
//! `Expect` body that holds a request), never captured.
#![no_main]

use datapavan_net::forward::{self, Forward, Why};
use datapavan_net::proxies::{self, Declared, Kind};
use libfuzzer_sys::fuzz_target;
use std::net::SocketAddr;
use zeroize::Zeroizing;

/// The stage's way through `data` to `to`, fed in two pieces cut at `cut`: the first head's end and its outcome, or the
/// later refusal, and the bytes to the proxy.
fn run(data: &[u8], to: SocketAddr, cut: usize) -> (Option<usize>, Result<(), Why>, Vec<u8>) {
    let cut = cut.min(data.len());
    let mut held = Zeroizing::new(Vec::new());
    let mut out = Zeroizing::new(Vec::new());
    let mut forward: Option<Forward> = None;
    let mut first_end = None;
    for piece in [&data[..cut], &data[cut..]] {
        if let Some(f) = forward.as_mut() {
            if let Err(why) = f.feed(piece, &mut out) {
                return (first_end, Err(why), out.to_vec());
            }
            continue;
        }
        let before = held.len();
        forward::reserve(&mut held, piece.len());
        held.extend_from_slice(piece);
        let end = match forward::head_end(&held, before) {
            Ok(Some(end)) => end,
            Ok(None) => continue,
            Err(why) => return (None, Err(why), Vec::new()),
        };
        first_end = Some(end);
        match forward::first(&held[..end], to, &mut out) {
            Ok(first) => {
                let mut f = first.forward;
                if let Err(why) = f.feed(&held[end..], &mut out) {
                    return (first_end, Err(why), out.to_vec());
                }
                forward = Some(f);
            }
            Err(why) => return (first_end, Err(why), Vec::new()),
        }
    }
    (first_end, Ok(()), out.to_vec())
}

/// `bytes` without spaces and tabs at either end.
fn trim(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// The head `head`, accepted, read by `httparse` as the same head.
fn same_for_httparse(head: &[u8]) {
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut fields);
    let parsed = match request.parse(head) {
        Ok(parsed) => parsed,
        // More fields than this reader takes: nothing to compare.
        Err(httparse::Error::TooManyHeaders) => return,
        Err(error) => panic!("httparse refused an accepted head: {error:?}"),
    };
    assert_eq!(
        parsed,
        httparse::Status::Complete(head.len()),
        "the head's end"
    );
    let line_end = head.iter().position(|&b| b == b'\r').unwrap_or(0);
    let mut parts = head[..line_end].split(|&b| b == b' ');
    assert_eq!(
        request.method.map(str::as_bytes),
        parts.next(),
        "the method"
    );
    assert_eq!(request.path.map(str::as_bytes), parts.next(), "the target");
    let minor = parts.next().and_then(|v| v.last()).map(|d| d - b'0');
    assert_eq!(request.version, minor, "the version");
    let lines: Vec<&[u8]> = head[line_end + 2..head.len() - 2]
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(request.headers.len(), lines.len(), "the field lines");
    for (field, line) in request.headers.iter().zip(lines) {
        let colon = line.iter().position(|&b| b == b':').unwrap_or(0);
        assert_eq!(field.name.as_bytes(), &line[..colon], "a field's name");
        assert_eq!(
            trim(field.value),
            trim(&line[colon + 1..]),
            "a field's value"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&seed, data)) = data.split_first() else {
        return;
    };
    let port = if seed & 1 == 0 { 80 } else { 8080 };
    let to = SocketAddr::from(([198, 51, 100, 9], port));
    let whole = forward::head_end(data, 0);
    for cut in [
        usize::from(seed) * 7,
        data.len() / 2,
        data.len().saturating_sub(1),
    ] {
        let cut = cut.min(data.len());
        match forward::head_end(&data[..cut], 0) {
            Ok(None) => {}
            Ok(Some(end)) => assert_eq!(whole, Ok(Some(end)), "an end found stays"),
            Err(_) => assert!(whole.is_err(), "a refusal stays"),
        }
        if let Ok(None) = forward::head_end(&data[..cut], 0) {
            assert_eq!(forward::head_end(data, cut), whole, "read on from a cut");
        }
    }
    let one = run(data, to, data.len());
    let cut = usize::from(seed) * 13 % (data.len() + 1);
    assert_eq!(run(data, to, cut), one, "two pieces, cut at {cut}");
    if let (Some(end), result, out) = &one
        && !matches!(result, Err(why) if *end == 0 || matches!(why, Why::NotHttp))
        && !out.is_empty()
    {
        match proxies::declared(out) {
            Declared::Request(request) => {
                assert_eq!(
                    request.kind,
                    Kind::Forward,
                    "read back as a plain proxy request"
                );
                assert_eq!(request.port, port, "the flow's port");
            }
            Declared::Incomplete if out.len() >= proxies::MAX_REQUEST => {}
            other => panic!("read back as {other:?}"),
        }
        same_for_httparse(&data[..*end]);
    }
});
