//! Tracker blocking's graded table (W8, part 3a; ADR 0053): Datapavan's own record of which hosts tracker SDKs
//! send to, each graded by what it does (`data/blocking/hosts.tsv`, CC0, in the signed data pack), and the plain
//! HTTP `Host` a connection's first bytes name.
//!
//! Each row is a host, the SDK's Maven coordinate, the SDK's package prefix (which the network part's Kotlin side joins
//! at run time to the εxodus tracker of the same SDK, to name it: ADR 0046's decision 4 as ADR 0053 amends it), a
//! grade, the condition of a grade that depends on the app's code, the host's function, the kind of evidence, the
//! source and the date. The engine reads the host and the grade; Kotlin reads the rest for the screens, and
//! decides each code-dependent grade from the audit's scan of the app, which it hands over by app.
//!
//! A row's host matches itself and every name under it, on label boundaries, never as a substring, unlike the
//! εxodus signatures' `re.search`: `app-measurement.com` matches `app-measurement.com` and
//! `x.app-measurement.com`, never `notapp-measurement.com`. Where rows nest, the narrowest row names the name, so
//! that a `keep` row under a `block` one keeps what it names. Names compare without regard to ASCII case
//! (RFC 4343), a trailing dot left out.
//!
//! The table comes from the data pack the audit verifies, but its reader is strict all the same and fuzzed
//! (`fuzz_targets/blocking.rs`): a line that is not nine columns, a host that is not a DNS name, a grade it does
//! not know, a condition on a grade that takes none, or a host twice, refuses the whole table, so that a
//! malformed pack never blocks half of what it says.

use std::collections::HashMap;
use std::fmt;

/// What a host does, as the table grades it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grade {
    /// It serves only tracking, analytics, attribution, advertising, or crash or performance reports: blocked in
    /// every app the user's blocking covers, the tracker's own company's apps included (ADR 0053, decision 2).
    Block,
    /// It also serves the app's own function (sign-in, a database, storage, push): blocked in none.
    Keep,
    /// It serves both, and the app's own code decides which (`graph.facebook.com`): the network part's Kotlin side
    /// tells the engine, by app, where it is [`Grade::Block`]; elsewhere it is kept.
    Code,
}

/// One row of the table, as the engine reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The host, in lower case, without a trailing dot.
    pub host: String,
    /// The SDK's Maven coordinate, `group:artifact`, or `-`.
    pub sdk: String,
    /// Its grade.
    pub grade: Grade,
}

/// Why the table could not be read; the value is the line's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not nine tab-separated columns.
    Columns(usize),
    /// A host that is not a DNS name of two labels or more.
    Host(usize),
    /// A grade other than `block`, `keep` and `code`, or a condition that does not go with it.
    Grade(usize),
    /// A host that an earlier line has already.
    Twice(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Columns(line) => write!(f, "line {line}: not nine columns"),
            Self::Host(line) => write!(f, "line {line}: not a host name"),
            Self::Grade(line) => write!(
                f,
                "line {line}: not a grade, or a condition that does not go with it"
            ),
            Self::Twice(line) => write!(f, "line {line}: a host given twice"),
        }
    }
}

impl std::error::Error for Error {}

/// The most rows a table may hold: far above any list of SDK hosts, and a bound on what a pack can make the
/// engine keep.
pub const MAX_ENTRIES: usize = 16_384;

/// The graded table, ready for matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    entries: Vec<Entry>,
    by_host: HashMap<String, usize>,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            by_host: crate::map(),
        }
    }
}

impl Table {
    /// Reads `hosts.tsv` as the data pack holds it: lines starting with `#` are comments, empty lines are
    /// skipped, and every other line is a row of nine tab-separated columns.
    ///
    /// # Errors
    ///
    /// The first line that cannot be read ([`Error`]), or a table longer than [`MAX_ENTRIES`] rows, which
    /// refuses at the first row past it ([`Error::Columns`]).
    pub fn parse(tsv: &str) -> Result<Self, Error> {
        let mut table = Self::default();
        for (number, line) in tsv.lines().enumerate().map(|(i, line)| (i + 1, line)) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let columns: Vec<&str> = line.split('\t').collect();
            let [
                host,
                sdk,
                _classes,
                grade,
                condition,
                _function,
                _evidence,
                _source,
                _checked,
            ] = columns[..]
            else {
                return Err(Error::Columns(number));
            };
            if table.entries.len() == MAX_ENTRIES {
                return Err(Error::Columns(number));
            }
            if !is_host(host) {
                return Err(Error::Host(number));
            }
            let grade = match (grade, condition == "-") {
                ("block", true) => Grade::Block,
                ("keep", true) => Grade::Keep,
                ("code", false) if is_condition(condition) => Grade::Code,
                _ => return Err(Error::Grade(number)),
            };
            if table.by_host.contains_key(host) {
                return Err(Error::Twice(number));
            }
            table.by_host.insert(host.to_owned(), table.entries.len());
            table.entries.push(Entry {
                host: host.to_owned(),
                sdk: sdk.to_owned(),
                grade,
            });
        }
        Ok(table)
    }

    /// The rows, in the table's order: an entry's index is its place here.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The row whose host is `host`, written as the table writes it.
    #[must_use]
    pub fn index_of(&self, host: &str) -> Option<usize> {
        self.by_host.get(host).copied()
    }

    /// The narrowest row that names `name`: the row of `name` itself, else of the name one label up, and so on.
    /// A name that is not a host name (an address as text, an empty name) is named by none.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<usize> {
        if self.entries.is_empty() {
            return None;
        }
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.is_empty() || name.len() > 253 || name.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }
        let lower;
        let name = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            lower = name.to_ascii_lowercase();
            lower.as_str()
        } else {
            name
        };
        let mut at = 0;
        loop {
            let suffix = &name[at..];
            if let Some(&index) = self.by_host.get(suffix) {
                return Some(index);
            }
            at += suffix.find('.')? + 1;
        }
    }

    /// Whether the table has no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Whether `host` is written as a row's host must be: two labels or more of lower-case letters, digits, `-` and
/// `_`, each 1 to 63 bytes and not starting or ending with `-`, at most 253 bytes in all, and no address.
fn is_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && host.parse::<std::net::IpAddr>().is_err()
        && labels.iter().all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

/// Whether a code-dependent row's condition is written `block-with P|P keep-with P|P`, each prefix a Java package
/// name ending in `.`. Kotlin reads it; the engine only checks its form.
fn is_condition(condition: &str) -> bool {
    let prefixes = |list: &str| {
        !list.is_empty()
            && list.split('|').all(|p| {
                p.len() >= 3
                    && p.ends_with('.')
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
            })
    };
    let mut words = condition.split(' ');
    matches!(
        (words.next(), words.next(), words.next(), words.next(), words.next()),
        (Some("block-with"), Some(block), Some("keep-with"), Some(keep), None)
            if prefixes(block) && prefixes(keep)
    )
}

/// The most bytes of a stream's start read for a plain HTTP request's `Host`: a request line and headers that
/// no client sends longer before the host.
pub const MAX_HTTP_HEAD: usize = 8 * 1024;

/// What the start of a stream says of a plain HTTP request's host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpHost {
    /// An HTTP/1 request whose `Host` header names this host, in lower case, without its port.
    Found(String),
    /// Not an HTTP/1 request in origin form, or one with no `Host` before its head ends or the bound.
    None,
    /// More bytes are needed to tell.
    Incomplete,
}

/// Reads the `Host` of a plain HTTP/1 request from the start of a stream (RFC 9112 3.2, RFC 9110 7.2): a method
/// of 1 to 20 upper-case letters, a space, a target in origin form (`/...`) or `*`, ` HTTP/1.`, then the headers
/// up to the empty line. Only that header's value is read, up to its port. A request in absolute form names its
/// host in its target, and is the proxy reader's (`crate::proxies`), not read here.
#[must_use]
pub fn http_host(start: &[u8]) -> HttpHost {
    read_host(start, |name| name.eq_ignore_ascii_case(b"host"))
}

/// [`http_host`] for the forwarder's check that this reader finds its own `Host` (`crate::forward`): the same reader,
/// its one comparison of a name with `host` written out rather than core's, so that the tracker gate's copy, inlined
/// into the relay's task on the packet path, keeps both its own call and core's inlined in it (the forwarder's size
/// pass).
#[must_use]
pub fn http_host_again(start: &[u8]) -> HttpHost {
    read_host(start, |name| {
        name.len() == 4
            && name
                .iter()
                .zip(b"host")
                .all(|(b, l)| b.to_ascii_lowercase() == *l)
    })
}

/// [`http_host`]'s reader, `is_host` telling a field name `host` in any case. Inlined into both: with a call
/// between, the gate's copy in the relay's task is no longer its machine code of before the forwarder (measured).
#[allow(clippy::inline_always)]
#[inline(always)]
fn read_host(start: &[u8], is_host: impl Fn(&[u8]) -> bool) -> HttpHost {
    let start = &start[..start.len().min(MAX_HTTP_HEAD)];
    let full = start.len() == MAX_HTTP_HEAD;
    let space = match start.iter().take(21).position(|&c| !c.is_ascii_uppercase()) {
        Some(space) if space > 0 && start[space] == b' ' => space,
        None if start.len() < 21 => return HttpHost::Incomplete,
        _ => return HttpHost::None,
    };
    match start.get(space + 1) {
        None => return HttpHost::Incomplete,
        Some(b'/' | b'*') => {}
        Some(_) => return HttpHost::None,
    }
    let Some(line_end) = find(start, b"\n") else {
        return if full {
            HttpHost::None
        } else {
            HttpHost::Incomplete
        };
    };
    if find(&start[..line_end], b" HTTP/1.").is_none() {
        return HttpHost::None;
    }
    let mut at = line_end + 1;
    loop {
        let Some(n) = find(&start[at..], b"\n") else {
            return if full {
                HttpHost::None
            } else {
                HttpHost::Incomplete
            };
        };
        let header = &start[at..at + n];
        let header = header.strip_suffix(b"\r").unwrap_or(header);
        at += n + 1;
        if header.is_empty() {
            return HttpHost::None;
        }
        let Some(colon) = header.iter().position(|&c| c == b':') else {
            continue;
        };
        if !is_host(&header[..colon]) {
            continue;
        }
        let value = std::str::from_utf8(&header[colon + 1..])
            .unwrap_or("")
            .trim();
        return host_of(value).map_or(HttpHost::None, HttpHost::Found);
    }
}

/// The host of a `Host` value, `host[:port]` or `[v6]:port`, in lower case; `None` for one that is empty or
/// holds what no host holds.
fn host_of(value: &str) -> Option<String> {
    let host = if let Some(rest) = value.strip_prefix('[') {
        &rest[..rest.find(']')?]
    } else {
        value.rsplit_once(':').map_or(value, |(host, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                host
            } else {
                value
            }
        })
    };
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
    ok.then(|| host.trim_end_matches('.').to_ascii_lowercase())
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A row of the table with `host` and `grade` (and the condition a code row needs).
    pub(crate) fn row(host: &str, grade: &str) -> String {
        let condition = if grade == "code" {
            "block-with com.facebook.appevents.|com.facebook.ads. keep-with com.facebook.login."
        } else {
            "-"
        };
        format!(
            "{host}\tcom.example:sdk\tcom.example.\t{grade}\t{condition}\tReceives events\tcode\thttps://example.com/x\t2026-11-21\n"
        )
    }

    pub(crate) fn table(rows: &[(&str, &str)]) -> Table {
        let tsv: String = rows.iter().map(|(h, g)| row(h, g)).collect();
        Table::parse(&tsv).unwrap_or_default()
    }

    #[test]
    fn matches_on_label_boundaries_and_the_narrowest_row_names() {
        let t = table(&[
            ("app-measurement.com", "block"),
            ("graph.facebook.com", "code"),
            ("facebook.example", "block"),
            ("keep.facebook.example", "keep"),
        ]);
        let host = |name: &str| t.find(name).map(|i| t.entries()[i].host.as_str());
        assert_eq!(host("app-measurement.com"), Some("app-measurement.com"));
        assert_eq!(host("X.App-Measurement.COM."), Some("app-measurement.com"));
        assert_eq!(host("notapp-measurement.com"), None);
        assert_eq!(host("app-measurement.com.evil.example"), None);
        assert_eq!(host("measurement.com"), None);
        assert_eq!(host("graph.facebook.com"), Some("graph.facebook.com"));
        assert_eq!(host("facebook.com"), None);
        assert_eq!(
            host("a.keep.facebook.example"),
            Some("keep.facebook.example")
        );
        assert_eq!(host("other.facebook.example"), Some("facebook.example"));
        assert_eq!(host("10.0.0.1"), None);
        assert_eq!(host("::1"), None);
        assert_eq!(host(""), None);
        assert_eq!(host("."), None);
        assert_eq!(
            t.entries()[t.find("graph.facebook.com").unwrap_or(0)].grade,
            Grade::Code
        );
    }

    #[test]
    fn reads_the_bundled_table() {
        let tsv = include_str!("../../../data/blocking/hosts.tsv");
        let read = Table::parse(tsv);
        assert!(read.is_ok(), "{read:?}");
        let t = read.unwrap_or_default();
        assert!(t.entries().len() >= 50);
        let grade = |name: &str| t.find(name).map(|i| t.entries()[i].grade);
        assert_eq!(grade("app-measurement.com"), Some(Grade::Block));
        assert_eq!(grade("graph.facebook.com"), Some(Grade::Code));
        assert_eq!(
            grade("firebaseinstallations.googleapis.com"),
            Some(Grade::Keep)
        );
        // Never a broad shared parent.
        for broad in [
            "googleapis.com",
            "google.com",
            "facebook.com",
            "amazonaws.com",
            "cloudfront.net",
        ] {
            assert_eq!(grade(broad), None, "{broad}");
            assert_eq!(grade(&format!("www.{broad}")), None, "{broad}");
        }
    }

    #[test]
    fn refuses_malformed_lines_whole() {
        let good = row("a.example", "block");
        for (bad, error) in [
            ("a.example\tx\n".to_owned(), Error::Columns(2)),
            (row("A.example", "block"), Error::Host(2)),
            (row("example", "block"), Error::Host(2)),
            (row("-a.example", "block"), Error::Host(2)),
            (row("10.0.0.1", "block"), Error::Host(2)),
            (row("a..example", "block"), Error::Host(2)),
            (row("b.example", "ban"), Error::Grade(2)),
            (row("a.example", "keep"), Error::Twice(2)),
            (
                "c.example\ts\tc.\tblock\tblock-with a.b.\tf\tcode\tu\td\n".to_owned(),
                Error::Grade(2),
            ),
            (
                "c.example\ts\tc.\tcode\t-\tf\tcode\tu\td\n".to_owned(),
                Error::Grade(2),
            ),
            (
                "c.example\ts\tc.\tcode\tblock-with com.x keep-with com.y.\tf\tcode\tu\td\n"
                    .to_owned(),
                Error::Grade(2),
            ),
        ] {
            assert_eq!(Table::parse(&(good.clone() + &bad)), Err(error), "{bad}");
        }
        assert!(Table::parse(&format!("# comment\n\n{good}")).is_ok());
    }

    #[test]
    fn reads_a_plain_requests_host_and_nothing_else() {
        let found = |s: &str| HttpHost::Found(s.to_owned());
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: Track.Example:8080\r\n\r\n"),
            found("track.example")
        );
        assert_eq!(
            http_host(b"POST /a?b HTTP/1.0\r\nUser-Agent: x\r\nhost:track.example\r\n\r\n"),
            found("track.example")
        );
        assert_eq!(
            http_host(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"),
            found("2001:db8::1")
        );
        assert_eq!(
            http_host(b"GET / HTTP/1.1\nHost: a.example.\n\n"),
            found("a.example")
        );
        for incomplete in [
            &b""[..],
            b"GE",
            b"GET ",
            b"GET / HTTP/1.1\r\n",
            b"GET / HTTP/1.1\r\nHost: a.exa",
        ] {
            assert_eq!(
                http_host(incomplete),
                HttpHost::Incomplete,
                "{incomplete:?}"
            );
        }
        for none in [
            &b"\x16\x03\x01"[..],
            b"get / HTTP/1.1\r\n",
            b"GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\nHost: late.example\r\n",
            b"GET / SPDY/3\r\nHost: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
        ] {
            assert_eq!(http_host(none), HttpHost::None, "{none:?}");
        }
        let mut long = b"GET / HTTP/1.1\r\nX: ".to_vec();
        long.resize(MAX_HTTP_HEAD + 10, b'a');
        assert_eq!(http_host(&long), HttpHost::None);
    }

    #[test]
    fn the_forwarders_copy_of_the_reader_reads_as_the_gates() {
        for start in [
            &b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHOST: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nhOsT: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHosts: a.example\r\nHost: b.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHos: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nH\xc3\xb6st: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nX-Host: a.example\r\n\r\n",
            b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a.exa",
        ] {
            assert_eq!(http_host_again(start), http_host(start), "{start:?}");
        }
    }
}
