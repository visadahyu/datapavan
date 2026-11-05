//! Signed data packs: how the datasets under `data/` reach the phone (ADR 0015, decision 11).
//!
//! A pack is a file in the embedded-signature format of OpenBSD's `signify`, so anyone can check one
//! with that tool (`signify -V -e`): a comment line, a line with the base64 signature, then the signed
//! payload. The signature is Ed25519 over the whole payload, and it is checked before any of the
//! payload is read. The payload starts with a text header that lists its files, followed by their
//! contents. The format is described in `docs/DATA-PACKS.md` and decided in ADR 0017.
//!
//! The app's own copy, inside the APK, is a bare payload: the APK's signature covers it.

use core::fmt;
use core::ops::Range;

/// The largest pack the app accepts. Today's packs hold some hundred kilobytes; the room is for
/// the domain lists of v0.2.
pub const MAX_PACK_BYTES: usize = 32 << 20;
/// The largest header, which lists the files.
pub const MAX_HEADER_BYTES: usize = 64 << 10;
/// The most files one pack may hold.
pub const MAX_FILES: usize = 256;
/// The most keys one pack may name, in `key` and in `revoked` lines each.
pub const MAX_KEYS: usize = 16;
/// The longest path of a file in a pack.
pub const MAX_PATH_BYTES: usize = 128;

/// The first line of every payload, with the format version this parser reads.
const FORMAT: &[u8] = b"datapavan-data-pack 1";
const FORMAT_NAME: &[u8] = b"datapavan-data-pack ";
/// How `signify` starts the comment line of a signature or key file.
const COMMENT: &[u8] = b"untrusted comment: ";
/// `signify` limits the comment to this many bytes.
const MAX_COMMENT_BYTES: usize = 1024;
/// `signify`'s only algorithm.
const ALGORITHM: &[u8] = b"Ed";
const KEY_NUMBER_BYTES: usize = 8;
/// A signature line: base64 of the algorithm, the key number and the 64-byte signature.
const SIGNATURE_LINE_BYTES: usize = 100;
/// A public key line: base64 of the algorithm, the key number and the 32-byte key.
const KEY_LINE_BYTES: usize = 56;

/// Why a pack was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The pack is larger than [`MAX_PACK_BYTES`].
    TooLarge,
    /// The file does not start with a `signify` signature.
    NotSigned,
    /// No trusted key has the signature's key number.
    UnknownKey,
    /// The signature does not match the payload: it was changed, damaged or forged.
    BadSignature,
    /// The payload is not a data pack.
    NotPack,
    /// The pack is in a newer format than this parser reads.
    UnsupportedVersion,
    /// A header line is malformed or out of order, or the file sizes do not add up.
    InvalidHeader,
    /// A public key is malformed or not a usable Ed25519 key.
    InvalidKey,
}

impl Error {
    /// A stable number for the error, which the JNI bridge passes to the app.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::TooLarge => 1,
            Self::NotSigned => 2,
            Self::UnknownKey => 3,
            Self::BadSignature => 4,
            Self::NotPack => 5,
            Self::UnsupportedVersion => 6,
            Self::InvalidHeader => 7,
            Self::InvalidKey => 8,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "data pack too large",
            Self::NotSigned => "data pack has no signature",
            Self::UnknownKey => "data pack signed by an unknown key",
            Self::BadSignature => "data pack signature does not match",
            Self::NotPack => "not a data pack",
            Self::UnsupportedVersion => "data pack in a newer format",
            Self::InvalidHeader => "invalid data pack header",
            Self::InvalidKey => "invalid data-signing key",
        })
    }
}

impl std::error::Error for Error {}

/// A data-signing public key, as the second line of a `signify` public key file holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    number: [u8; KEY_NUMBER_BYTES],
    key: ed25519_compact::PublicKey,
}

impl PublicKey {
    /// Reads the base64 line of a `signify` public key file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] unless the line is exactly such a key, and the key a canonical
    /// Ed25519 point that does not have a small order.
    pub fn parse(line: &[u8]) -> Result<Self, Error> {
        if line.len() != KEY_LINE_BYTES {
            return Err(Error::InvalidKey);
        }
        let raw = base64_decode(line).ok_or(Error::InvalidKey)?;
        let (algorithm, rest) = raw
            .split_at_checked(ALGORITHM.len())
            .ok_or(Error::InvalidKey)?;
        let (number, key) = rest
            .split_first_chunk::<KEY_NUMBER_BYTES>()
            .ok_or(Error::InvalidKey)?;
        if algorithm != ALGORITHM {
            return Err(Error::InvalidKey);
        }
        Self::from_raw(*number, key)
    }

    /// A key from its number and its 32 bytes, refused unless it is a canonical Ed25519 point that
    /// does not have a small order.
    fn from_raw(number: [u8; KEY_NUMBER_BYTES], key: &[u8]) -> Result<Self, Error> {
        let key = ed25519_compact::PublicKey::from_slice(key).map_err(|_| Error::InvalidKey)?;
        key.validate().map_err(|_| Error::InvalidKey)?;
        Ok(Self { number, key })
    }

    /// Whether this key made `signature` over `message`.
    fn signed(&self, message: &[u8], signature: &ed25519_compact::Signature) -> bool {
        self.key.verify(message, signature).is_ok()
    }
}

/// A pack whose signature matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Index of the key that signed it, in the list given to [`verify`].
    pub signer: usize,
    /// Where the signed payload starts in the pack.
    pub payload_start: usize,
}

/// Checks that `pack` carries a signature by one of the `trusted` keys over everything after it.
/// Nothing in the payload is read before the signature has matched.
///
/// # Errors
///
/// Returns [`Error::TooLarge`], [`Error::NotSigned`] for a file without a `signify` signature,
/// [`Error::UnknownKey`] when no trusted key has the signature's key number, and
/// [`Error::BadSignature`] when none of those keys made the signature.
pub fn verify(pack: &[u8], trusted: &[PublicKey]) -> Result<Verified, Error> {
    if pack.len() > MAX_PACK_BYTES {
        return Err(Error::TooLarge);
    }
    let (number, signature, payload_start) = signature_block(pack)?;
    let payload = pack.get(payload_start..).ok_or(Error::NotSigned)?;
    let mut candidates = trusted
        .iter()
        .enumerate()
        .filter(|(_, key)| key.number == number)
        .peekable();
    if candidates.peek().is_none() {
        return Err(Error::UnknownKey);
    }
    // Key numbers are random, not unique: try every key that has this one.
    candidates
        .find(|(_, key)| key.signed(payload, &signature))
        .map(|(signer, _)| Verified {
            signer,
            payload_start,
        })
        .ok_or(Error::BadSignature)
}

/// Reads the two lines `signify -S -e` puts before the message: the key number, the signature, and
/// where the message starts.
fn signature_block(
    pack: &[u8],
) -> Result<([u8; KEY_NUMBER_BYTES], ed25519_compact::Signature, usize), Error> {
    let first_line = pack
        .iter()
        .take(COMMENT.len() + MAX_COMMENT_BYTES + 1)
        .position(|&b| b == b'\n')
        .ok_or(Error::NotSigned)?;
    // Like `signify`, a comment must not be empty.
    if !pack.starts_with(COMMENT) || first_line <= COMMENT.len() {
        return Err(Error::NotSigned);
    }
    let line_start = first_line + 1;
    let line_end = line_start + SIGNATURE_LINE_BYTES;
    let line = pack.get(line_start..line_end).ok_or(Error::NotSigned)?;
    if pack.get(line_end) != Some(&b'\n') {
        return Err(Error::NotSigned);
    }
    let raw = base64_decode(line).ok_or(Error::NotSigned)?;
    let (algorithm, rest) = raw
        .split_at_checked(ALGORITHM.len())
        .ok_or(Error::NotSigned)?;
    let (number, signature) = rest
        .split_first_chunk::<KEY_NUMBER_BYTES>()
        .ok_or(Error::NotSigned)?;
    if algorithm != ALGORITHM {
        return Err(Error::NotSigned);
    }
    let signature =
        ed25519_compact::Signature::from_slice(signature).map_err(|_| Error::NotSigned)?;
    Ok((*number, signature, line_end + 1))
}

/// One file in a payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Its path, for example `exodus/trackers.tsv`.
    pub path: Range<usize>,
    /// Its contents.
    pub data: Range<usize>,
}

/// The header of a payload. Every range points into the payload it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// Raised by one for every published pack; the app refuses a pack that is not newer than the
    /// one it uses.
    pub sequence: u32,
    /// The day the pack was made, as `YYYY-MM-DD`.
    pub date: Range<usize>,
    /// The keys that may sign later packs, as `signify` public key lines.
    pub keys: Vec<Range<usize>>,
    /// Keys that must no longer be trusted.
    pub revoked: Vec<Range<usize>>,
    /// The files, in ascending order of their paths.
    pub files: Vec<Entry>,
}

impl Payload {
    /// Reads the header of a payload and checks that its files fill the rest exactly.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooLarge`], [`Error::NotPack`] for other data, [`Error::UnsupportedVersion`] for a newer
    /// format, [`Error::InvalidKey`] for a malformed key line, and [`Error::InvalidHeader`] for
    /// anything else that does not follow the format.
    pub fn parse(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() > MAX_PACK_BYTES {
            return Err(Error::TooLarge);
        }
        let mut lines = Lines {
            payload,
            position: 0,
        };
        let format = lines.next().map_err(|_| Error::NotPack)?;
        match payload.get(format.clone()) {
            Some(FORMAT) => {}
            Some(line) if line.starts_with(FORMAT_NAME) => return Err(Error::UnsupportedVersion),
            _ => return Err(Error::NotPack),
        }

        let sequence = lines.value(b"sequence ")?;
        let sequence = decimal(payload.get(sequence).unwrap_or_default())
            .and_then(|n| u32::try_from(n).ok())
            .filter(|&n| n > 0 && i32::try_from(n).is_ok())
            .ok_or(Error::InvalidHeader)?;
        let date = lines.value(b"date ")?;
        if !is_date(payload.get(date.clone()).unwrap_or_default()) {
            return Err(Error::InvalidHeader);
        }

        let mut line = lines.next()?;
        let mut keys = Vec::new();
        let mut revoked = Vec::new();
        for (keyword, list) in [(&b"key "[..], &mut keys), (&b"revoked "[..], &mut revoked)] {
            while let Some(value) = strip(payload, &line, keyword) {
                PublicKey::parse(payload.get(value.clone()).unwrap_or_default())?;
                if list.len() == MAX_KEYS {
                    return Err(Error::InvalidHeader);
                }
                list.push(value);
                line = lines.next()?;
            }
        }

        let mut listed = Vec::new();
        while let Some(value) = strip(payload, &line, b"file ") {
            let text = payload.get(value.clone()).unwrap_or_default();
            let space = text
                .iter()
                .rposition(|&b| b == b' ')
                .ok_or(Error::InvalidHeader)?;
            let path = value.start..value.start + space;
            let size = decimal(text.get(space + 1..).unwrap_or_default())
                .filter(|&n| n <= MAX_PACK_BYTES)
                .ok_or(Error::InvalidHeader)?;
            let name = payload.get(path.clone()).unwrap_or_default();
            // Strictly ascending paths: each appears once, and a pack has one canonical form.
            let ascending = listed
                .last()
                .is_none_or(|(last, _): &(Range<usize>, usize)| {
                    payload.get(last.clone()).unwrap_or_default() < name
                });
            if !is_path(name) || !ascending || listed.len() == MAX_FILES {
                return Err(Error::InvalidHeader);
            }
            listed.push((path, size));
            line = lines.next()?;
        }
        if payload.get(line) != Some(b"end") {
            return Err(Error::InvalidHeader);
        }

        let mut start = lines.position;
        let mut files = Vec::with_capacity(listed.len());
        for (path, size) in listed {
            let end = start.checked_add(size).ok_or(Error::InvalidHeader)?;
            files.push(Entry {
                path,
                data: start..end,
            });
            start = end;
        }
        if start != payload.len() {
            return Err(Error::InvalidHeader);
        }
        Ok(Self {
            sequence,
            date,
            keys,
            revoked,
            files,
        })
    }
}

/// The header's lines, each without its `\n`.
struct Lines<'a> {
    payload: &'a [u8],
    position: usize,
}

impl Lines<'_> {
    fn next(&mut self) -> Result<Range<usize>, Error> {
        let rest = self
            .payload
            .get(self.position..MAX_HEADER_BYTES.min(self.payload.len()))
            .ok_or(Error::InvalidHeader)?;
        let length = rest
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(Error::InvalidHeader)?;
        let line = self.position..self.position + length;
        self.position += length + 1;
        Ok(line)
    }

    /// The next line, which must start with `keyword`, without the keyword.
    fn value(&mut self, keyword: &[u8]) -> Result<Range<usize>, Error> {
        let line = self.next()?;
        strip(self.payload, &line, keyword).ok_or(Error::InvalidHeader)
    }
}

fn strip(payload: &[u8], line: &Range<usize>, keyword: &[u8]) -> Option<Range<usize>> {
    payload
        .get(line.clone())?
        .starts_with(keyword)
        .then_some(line.start + keyword.len()..line.end)
}

/// A decimal number without a sign or leading zeros.
fn decimal(text: &[u8]) -> Option<usize> {
    if text.is_empty() || (text.len() > 1 && text.first() == Some(&b'0')) {
        return None;
    }
    text.iter().try_fold(0usize, |n, &b| {
        b.is_ascii_digit()
            .then(|| n.checked_mul(10)?.checked_add(usize::from(b - b'0')))
            .flatten()
    })
}

/// `YYYY-MM-DD`, with a month and day in range.
fn is_date(text: &[u8]) -> bool {
    let [y1, y2, y3, y4, b'-', m1, m2, b'-', d1, d2] = *text else {
        return false;
    };
    let digits = [y1, y2, y3, y4, m1, m2, d1, d2];
    if !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let month = (m1 - b'0') * 10 + (m2 - b'0');
    let day = (d1 - b'0') * 10 + (d2 - b'0');
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

/// A relative path of plain names: letters, digits, `.`, `_` and `-`, separated by `/`. No name is
/// empty or starts with `.`, so `..` cannot climb out of a folder.
fn is_path(text: &[u8]) -> bool {
    !text.is_empty()
        && text.len() <= MAX_PATH_BYTES
        && text.split(|&b| b == b'/').all(|name| {
            name.first().is_some_and(|&b| b != b'.')
                && name
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// Standard base64 with padding, as `signify` writes it. Anything else is refused, including
/// unused bits that are not zero, so every value has a single encoding.
fn base64_decode(text: &[u8]) -> Option<Vec<u8>> {
    let (groups, rest) = text.as_chunks::<4>();
    if groups.is_empty() || !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(groups.len() * 3);
    for (index, group) in groups.iter().enumerate() {
        let padding = group.iter().rev().take_while(|&&b| b == b'=').count();
        if padding > 2 || (padding > 0 && index + 1 != groups.len()) {
            return None;
        }
        let mut bits = 0u32;
        for &b in group.get(..4 - padding)? {
            bits = bits << 6 | u32::from(sextet(b)?);
        }
        bits <<= 6 * padding;
        let bytes = bits.to_be_bytes();
        if bytes.get(4 - padding..)?.iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(bytes.get(1..4 - padding)?);
    }
    Some(out)
}

fn sextet(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Payload, PublicKey, base64_decode, verify};
    use ed25519_compact::Signature;

    /// A pack signed with `signify-openbsd -S -e` (version 33) and the test key in
    /// `scripts/testdata`, which only debug builds trust.
    const PACK: &[u8] = include_bytes!("../testdata/test.pack");
    const TEST_KEY: &[u8] = b"RWSaKiYnaFJUifZRfEPxHyXNGoBK8ZRt44B2pqafPP6DCPmmnxA7fyPR";
    /// Another key made by `signify -G`.
    const OTHER_KEY: &[u8] = b"RWQaxG+lnRo0U5zecWAJn5iuFLam7wYlhd+tNfEeUwu8QJs41rHBXTsv";

    fn key(line: &[u8]) -> PublicKey {
        PublicKey::parse(line).unwrap_or_else(|e| unreachable!("{e}"))
    }

    /// `data/PACK` pins this key: if this reader refused it, release builds would refuse every pack.
    #[test]
    fn the_published_data_key_is_a_valid_key() {
        let file = include_str!("../../../keys/datapavan-data-1.pub");
        let line = file.lines().nth(1).unwrap_or_default();
        assert_eq!(PublicKey::parse(line.as_bytes()).map(|_| ()), Ok(()));
    }

    fn text(payload: &[u8], range: &core::ops::Range<usize>) -> String {
        String::from_utf8_lossy(&payload[range.clone()]).into_owned()
    }

    /// Builds a payload in the format `BundledDataTask` writes.
    fn payload(header: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = header.as_bytes().to_vec();
        for (path, data) in files {
            out.extend_from_slice(format!("file {path} {}\n", data.len()).as_bytes());
        }
        out.extend_from_slice(b"end\n");
        for (_, data) in files {
            out.extend_from_slice(data);
        }
        out
    }

    const HEADER: &str = "datapavan-data-pack 1\nsequence 7\ndate 2026-10-30\n";

    #[test]
    fn verifies_and_reads_a_pack_signed_by_signify() {
        let trusted = [key(OTHER_KEY), key(TEST_KEY)];
        let verified = verify(PACK, &trusted).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(verified.signer, 1);
        let payload = &PACK[verified.payload_start..];
        let header = Payload::parse(payload).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(header.sequence, 2);
        assert_eq!(text(payload, &header.date), "2026-10-30");
        assert_eq!(header.keys.len(), 1);
        assert_eq!(text(payload, &header.keys[0]).as_bytes(), TEST_KEY);
        let paths: Vec<String> = header
            .files
            .iter()
            .map(|f| text(payload, &f.path))
            .collect();
        assert_eq!(paths, ["example/LICENSE", "example/list.txt"]);
        assert_eq!(text(payload, &header.files[1].data), "one\ntwo\n");
    }

    #[test]
    fn refuses_unknown_keys_and_changed_payloads() {
        assert_eq!(verify(PACK, &[key(OTHER_KEY)]), Err(Error::UnknownKey));
        assert_eq!(verify(PACK, &[]), Err(Error::UnknownKey));
        let mut changed = PACK.to_vec();
        if let Some(last) = changed.last_mut() {
            *last ^= 1;
        }
        assert_eq!(verify(&changed, &[key(TEST_KEY)]), Err(Error::BadSignature));
        let mut longer = PACK.to_vec();
        longer.push(b'\n');
        assert_eq!(verify(&longer, &[key(TEST_KEY)]), Err(Error::BadSignature));
    }

    #[test]
    fn a_different_key_with_the_same_number_does_not_verify() {
        // The other key's 32 key bytes under the test key's number.
        let mut raw = base64_decode(TEST_KEY).unwrap_or_default();
        let other = base64_decode(OTHER_KEY).unwrap_or_default();
        raw[10..].copy_from_slice(&other[10..]);
        let line = base64_encode(&raw);
        assert_eq!(
            verify(PACK, &[key(line.as_bytes())]),
            Err(Error::BadSignature)
        );
        assert!(verify(PACK, &[key(line.as_bytes()), key(TEST_KEY)]).is_ok());
    }

    #[test]
    fn refuses_files_without_a_signature_block() {
        let trusted = [key(TEST_KEY)];
        let payload_start = verify(PACK, &trusted).map_or(0, |v| v.payload_start);
        for broken in [
            &PACK[payload_start..],
            b"untrusted comment: x\n".as_slice(),
            b"untrusted comment: \nRWSa\n".as_slice(),
            b"",
        ] {
            assert_eq!(verify(broken, &trusted), Err(Error::NotSigned));
        }
        let mut no_newline = PACK.to_vec();
        no_newline[payload_start - 1] = b' ';
        assert_eq!(verify(&no_newline, &trusted), Err(Error::NotSigned));
    }

    #[test]
    fn reads_a_payload_and_its_files() {
        let bytes = payload(
            &format!(
                "{HEADER}key {}\n",
                std::str::from_utf8(TEST_KEY).unwrap_or_default()
            ),
            &[
                ("a/LICENSE", b"text"),
                ("a/b-c_d.tsv", b""),
                ("b/x", b"\x00\xff"),
            ],
        );
        let header = Payload::parse(&bytes).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(header.sequence, 7);
        assert_eq!(header.revoked, []);
        assert_eq!(header.files.len(), 3);
        assert_eq!(&bytes[header.files[0].data.clone()], b"text");
        assert!(header.files[1].data.is_empty());
        assert_eq!(&bytes[header.files[2].data.clone()], b"\x00\xff");
    }

    #[test]
    fn refuses_payloads_that_break_the_format() {
        let ok = payload(HEADER, &[("a/x", b"1")]);
        assert!(Payload::parse(&ok).is_ok());
        let cases: &[(&[u8], Error)] = &[
            (b"", Error::NotPack),
            (b"hello\n", Error::NotPack),
            (b"datapavan-data-pack 2\nsequence 1\n", Error::UnsupportedVersion),
            (b"datapavan-data-pack 1\nsequence 01\ndate 2026-10-30\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 0\ndate 2026-10-30\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 2147483648\ndate 2026-10-30\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-13-30\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\ndate 2026-10-30\nsequence 1\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nkey RWSa\nend\n", Error::InvalidKey),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nend", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nend\nextra", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nfile a 2\nend\nx", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nfile a 99999999999999999999999\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nfile b 0\nfile a 0\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nfile a 0\nfile a 0\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nfile a 0\nkey x\nend\n", Error::InvalidHeader),
            (b"datapavan-data-pack 1\nsequence 1\ndate 2026-10-30\nend\r\n", Error::InvalidHeader),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                Payload::parse(bytes),
                Err(*expected),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn refuses_paths_that_could_leave_their_folder() {
        for path in [
            "../x", "a/../x", "/x", "a//x", "a/", ".hidden", "a/.x", "a b", "a\\x", "ä",
        ] {
            let bytes = payload(HEADER, &[(path, b"")]);
            assert_eq!(Payload::parse(&bytes), Err(Error::InvalidHeader), "{path}");
        }
        let long = "a".repeat(129);
        assert_eq!(
            Payload::parse(&payload(HEADER, &[(&long, b"")])),
            Err(Error::InvalidHeader)
        );
    }

    #[test]
    fn reads_keys_exactly() {
        assert!(PublicKey::parse(TEST_KEY).is_ok());
        let mut changed = TEST_KEY.to_vec();
        changed[0] = b'X';
        assert_eq!(PublicKey::parse(&changed), Err(Error::InvalidKey));
        // A small-order point (the identity) under the right algorithm and key number.
        let mut raw = base64_decode(TEST_KEY).unwrap_or_default();
        let mut identity = [0u8; 32];
        identity[0] = 1;
        raw[10..].copy_from_slice(&identity);
        assert_eq!(
            PublicKey::parse(base64_encode(&raw).as_bytes()),
            Err(Error::InvalidKey)
        );
    }

    /// Project Wycheproof's Ed25519 vectors, converted by `testdata/wycheproof/convert.py`.
    const WYCHEPROOF: &str = include_str!("../testdata/wycheproof/ed25519.tsv");

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .filter_map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
            .collect()
    }

    /// Every vector goes through the same checks as a pack's signature: the key as
    /// [`PublicKey::parse`] accepts it, then the signature. Valid signatures must verify and invalid
    /// ones must not. Of the "acceptable" ones, keys of small order are refused by the key policy,
    /// and keys with a torsion component may go either way, as Wycheproof allows.
    #[test]
    fn wycheproof_vectors() {
        let mut counts = [0usize; 3];
        for line in WYCHEPROOF.lines().filter(|l| !l.starts_with('#')) {
            let [id, result, flags, key, message, signature] =
                line.split('\t').collect::<Vec<_>>()[..]
            else {
                unreachable!("malformed line: {line}");
            };
            let accepted = PublicKey::from_raw([0; 8], &hex(key)).is_ok_and(|key| {
                Signature::from_slice(&hex(signature))
                    .is_ok_and(|signature| key.signed(&hex(message), &signature))
            });
            match result {
                "valid" => assert!(accepted, "tcId {id} must verify"),
                "invalid" => assert!(!accepted, "tcId {id} must not verify"),
                _ if flags == "SmallOrderPublicKey" => {
                    assert!(!accepted, "tcId {id}: small-order key must be refused");
                }
                _ => assert_eq!(flags, "MixedOrderPublicKey", "tcId {id}"),
            }
            counts[usize::from(result != "valid") + usize::from(result == "acceptable")] += 1;
        }
        assert_eq!(counts, [117, 64, 29]);
    }

    #[test]
    fn base64_has_one_encoding_per_value() {
        assert_eq!(base64_decode(b"aGk="), Some(b"hi".to_vec()));
        assert_eq!(base64_decode(b"aGkh"), Some(b"hi!".to_vec()));
        assert_eq!(base64_decode(b"aA=="), Some(b"h".to_vec()));
        for bad in [
            &b""[..],
            b"aGk",
            b"aGl=",
            b"aB==",
            b"a===",
            b"aG=k",
            b"aA==aGkh",
            b"aG k",
            b"aGk\n",
        ] {
            assert_eq!(base64_decode(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut group = [0u8; 3];
            group[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from_be_bytes([0, group[0], group[1], group[2]]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(ALPHABET[((bits >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn base64_round_trips() {
        for length in 0..40u8 {
            let bytes: Vec<u8> = (0..length)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            let encoded = base64_encode(&bytes);
            if length > 0 {
                assert_eq!(base64_decode(encoded.as_bytes()), Some(bytes));
            }
        }
    }
}
