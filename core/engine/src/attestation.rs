//! Android key attestation: the `KeyDescription` extension of an attestation certificate.
//!
//! The extension (OID 1.3.6.1.4.1.11129.2.1.17) states, among other things, whether the bootloader
//! is locked and whether verified boot succeeded. The bytes come from the device's keystore, which
//! a compromised system can tamper with, so they are parsed as untrusted input: every length is
//! checked, and malformed input is an error, never a panic.
//!
//! Only the fields the audit needs are decoded. Schema:
//! <https://source.android.com/docs/security/features/keystore/attestation#schema>
//!
//! # Which list a value comes from
//!
//! A `KeyDescription` carries two authorization lists. The secure environment that signs the
//! attestation enforces the entries of `hardwareEnforced` itself; the entries of `softwareEnforced`
//! are what the operating system states, and a compromised system controls them. A sound trusted
//! environment or `StrongBox` always puts `rootOfTrust` and `osPatchLevel` in its hardware-enforced
//! list. So every value is read from one list only, the one the attestation's security level makes
//! authoritative: the hardware-enforced list for a trusted environment or `StrongBox`, the
//! software-enforced list for a software attestation, which is only as trustworthy as the system
//! anyway. A value missing from that list is reported as absent, never taken from the other list,
//! so that the system cannot fill in a bootloader state that the hardware left out. The security
//! level is the weaker of `attestationSecurityLevel` and `keyMintSecurityLevel`, as Google's
//! verifier takes it (`android/keyattestation`, `Verifier.kt`).
//!
//! # Encoding
//!
//! The schema requires DER. Where this parser and Google's reference verifier, which reads through
//! `BouncyCastle` (`android/keyattestation`, `Extension.kt`), could differ, one rule decides: the
//! parser must never present a phone as locked and verified when its hardware did not say so, and
//! must not fail on a sound phone. Once the chain check (`AttestationChain.kt` in the app) has
//! passed, these bytes were signed by the phone's attestation key in answer to the app's own
//! request, so a lenient reading cannot let anything unsigned through, while a strict one could only
//! turn a sound phone's answer into a failure that its owner would never think to report. So:
//!
//! - A length may take the long form where DER wants the short one, or carry leading zero bytes, as
//!   BER allows and `BouncyCastle` accepts: its meaning is not in doubt. Its value must fit in 32
//!   bits, as in `BouncyCastle` (31 there). The indefinite form is refused: an element of indefinite length
//!   that the parser skips could be measured only by descending into it, which would bring back
//!   nesting driven by the input, and no keystore is known to write it (the corpus of real chains
//!   holds none, and RFC 5280 wants certificates in DER).
//! - Tag numbers, INTEGER and ENUMERATED values must be in their shortest form, and INTEGER and
//!   ENUMERATED each where the schema puts it, as `BouncyCastle` requires.
//! - A BOOLEAN is false when 0x00 and true otherwise, as BER and `BouncyCastle` read it. A genuine
//!   chain in Google's test data (`invalid/malformed_rot_device_locked.pem`, whose signatures
//!   verify) writes `deviceLocked` as 0x01.
//! - An entry the audit reads that is malformed inside (a `rootOfTrust` that is not a SEQUENCE of
//!   three or four fields of the schema's types, an unknown verified boot state, a patch level that
//!   is not a non-negative INTEGER) is treated as absent, so that the rest of the attestation still
//!   counts. Google's verifier reads most such entries as null too, but fails the whole extension
//!   on a root of trust of another size or an unknown boot state; this parser treats them alike. An
//!   absent root of trust is reported as an incomplete check, never as locked.
//! - An entry the audit reads that appears twice is read when its copies are identical, and treated
//!   as absent when they differ. Google's verifier keeps the last copy; this parser does not choose
//!   between two statements of the bootloader's state.
//! - Entries may come in any order, and what the audit does not use is skipped unread: entries with
//!   other tags, elements of other classes, and the content of the entries it does not read.
//!   Google's verifier fails on a tag it does not know; this parser reads none of them, so it need
//!   not.
//! - The `KeyDescription` must have exactly its eight fields, of the schema's types, and the
//!   authorization lists must be well formed, as Google's verifier requires.
//!
//! # Depth
//!
//! The parser descends by the schema, never by the input, and without recursion: the deepest
//! element it reads is a field of `RootOfTrust`, five elements below the extension's OCTET STRING
//! (`KeyDescription`, an authorization list, the `[704]` wrapper, `RootOfTrust`, the field).
//! Nesting in the input cannot take it deeper, so it needs no depth limit.

use core::fmt;

/// Context-specific tags of the `AuthorizationList` entries the audit reads.
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_VERSION: u32 = 705;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_VENDOR_PATCH_LEVEL: u32 = 718;
const TAG_BOOT_PATCH_LEVEL: u32 = 719;

/// Where the attested key lives, and so how much the attestation can be trusted. Ordered from the
/// weakest to the strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Software only: the statement is as trustworthy as the operating system.
    Software,
    /// A trusted execution environment, isolated from Android.
    TrustedEnvironment,
    /// A separate secure chip.
    StrongBox,
}

/// Result of verified boot, as recorded by the bootloader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifiedBootState {
    /// The system was verified with the device maker's key.
    Verified,
    /// The system was verified with a key the user installed.
    SelfSigned,
    /// The system was not verified, typically because the bootloader is unlocked.
    Unverified,
    /// Verification failed.
    Failed,
}

/// The `RootOfTrust` sequence: the bootloader's state, and what it verified the system with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootOfTrust<'a> {
    /// A digest of the key that verified the system, usually SHA-256 of the verified boot key:
    /// the maker's key on a phone as sold, the owner's on one locked with a system of their own,
    /// and zeros or empty where verification did not run.
    pub verified_boot_key: &'a [u8],
    /// Whether the bootloader is locked.
    pub device_locked: bool,
    /// Result of verified boot.
    pub verified_boot: VerifiedBootState,
    /// A digest of the verified boot images, from attestation version 3 on.
    pub verified_boot_hash: Option<&'a [u8]>,
}

/// The fields of a `KeyDescription` that the audit uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDescription<'a> {
    /// Attestation format version, e.g. 3 for Keymaster 4 or 400 for `KeyMint` 4.
    pub attestation_version: u32,
    /// Where the attestation was produced: the weaker of the attestation's and the key's levels.
    pub security_level: SecurityLevel,
    /// The challenge the app passed when it generated the key, so that the app can tell this
    /// attestation answers its own request.
    pub attestation_challenge: &'a [u8],
    /// Bootloader state, from the hardware-enforced list unless [`Self::security_level`] is
    /// [`SecurityLevel::Software`], and then from the software-enforced list; never from the other
    /// list. Absent when that list lacks it, holds it malformed, or holds two copies that differ
    /// (see the module documentation). The values below come from the same list and are absent in
    /// the same cases.
    pub root_of_trust: Option<RootOfTrust<'a>>,
    /// Android's version as `MMmmpp`, for example 160000 for Android 16.
    pub os_version: Option<u32>,
    /// The system's security patch level as `YYYYMM`.
    pub os_patch_level: Option<u32>,
    /// The vendor image's security patch level as `YYYYMM`.
    pub vendor_patch_level: Option<u32>,
    /// The boot image's security patch level as `YYYYMM`.
    pub boot_patch_level: Option<u32>,
}

/// Why a `KeyDescription` could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended inside an element.
    Truncated,
    /// A field that the schema requires is absent.
    MissingField,
    /// Bytes or elements follow the last element that the schema allows there.
    ExtraData,
    /// An element had a tag other than the one the schema requires.
    UnexpectedTag,
    /// An encoding that the parser does not accept, though BER would (see the module
    /// documentation).
    NotDer,
    /// A value outside its range, such as an unknown enumeration value or a negative number.
    InvalidValue,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated attestation extension",
            Self::MissingField => "missing field in attestation extension",
            Self::ExtraData => "unexpected data after a field of attestation extension",
            Self::UnexpectedTag => "unexpected element in attestation extension",
            Self::NotDer => "attestation extension not in DER",
            Self::InvalidValue => "invalid value in attestation extension",
        })
    }
}

impl std::error::Error for Error {}

/// Parses the extension value exactly as `X509Certificate.getExtensionValue` returns it: an
/// OCTET STRING whose content is the DER-encoded `KeyDescription` sequence.
///
/// # Errors
///
/// Returns an [`Error`] when the input is not a well-formed `KeyDescription` in DER.
pub fn parse_key_description(extension: &[u8]) -> Result<KeyDescription<'_>, Error> {
    let wrapper = read_one(extension)?.expect(OCTET_STRING)?;
    let mut fields = read_one(wrapper)?.contents(SEQUENCE)?;

    let attestation_version = fields.required()?.integer()?;
    let attestation_level = security_level(fields.required()?.enumerated()?)?;
    // keyMintVersion: checked, but the audit does not use it.
    fields.required()?.integer()?;
    let keymint_level = security_level(fields.required()?.enumerated()?)?;
    let attestation_challenge = fields.required()?.expect(OCTET_STRING)?;
    // uniqueId: checked, but the audit does not use it.
    fields.required()?.expect(OCTET_STRING)?;
    let software = fields.required()?.contents(SEQUENCE)?;
    let hardware = fields.required()?.contents(SEQUENCE)?;
    fields.finish()?;

    // A key the attestation calls hardware-backed but whose own level is software (or the other
    // way round, as on early Pixels, where a software keystore attests keys of an older trusted
    // environment) is trusted only as far as the weaker of the two.
    let security_level = attestation_level.min(keymint_level);
    let (authoritative, other) = match security_level {
        SecurityLevel::Software => (software, hardware),
        SecurityLevel::TrustedEnvironment | SecurityLevel::StrongBox => (hardware, software),
    };
    // The other list is read only far enough to know that it is well formed.
    for entry in other {
        entry?;
    }
    let entries = entries(authoritative)?;

    // A malformed entry counts as absent: see the module documentation.
    let integer = |entry: Entry<'_>| {
        entry
            .value()
            .and_then(|entry| explicit(entry).and_then(Element::integer).ok())
    };
    Ok(KeyDescription {
        attestation_version,
        security_level,
        attestation_challenge,
        root_of_trust: entries
            .root_of_trust
            .value()
            .and_then(|entry| root_of_trust(entry).ok()),
        os_version: integer(entries.os_version),
        os_patch_level: integer(entries.os_patch_level).and_then(patch_level),
        vendor_patch_level: integer(entries.vendor_patch_level).and_then(patch_level),
        boot_patch_level: integer(entries.boot_patch_level).and_then(patch_level),
    })
}

/// A patch level as `YYYYMM`, from `YYYYMM` or `YYYYMMDD`, the two forms keystores write (the
/// vendor and boot levels carry the day since `KeyMint`, but some keystores leave it out). Any
/// other value is malformed, as Google's verifier also reads it, and so absent; a month outside 1 to
/// 12 too, since it could only be shown as a date that does not exist.
fn patch_level(value: u32) -> Option<u32> {
    let year_month = match value {
        100_000..=999_999 => value,
        10_000_000..=99_999_999 => value / 100,
        _ => return None,
    };
    (1..=12).contains(&(year_month % 100)).then_some(year_month)
}

/// What an authorization list holds under one tag the audit reads.
#[derive(Clone, Copy, Default)]
enum Entry<'a> {
    #[default]
    Absent,
    One(Element<'a>),
    /// Two or more copies that differ.
    Conflicting,
}

impl<'a> Entry<'a> {
    fn add(&mut self, entry: Element<'a>) {
        *self = match *self {
            Self::Absent => Self::One(entry),
            Self::One(first) if first.tag == entry.tag && first.content == entry.content => {
                Self::One(first)
            }
            Self::One(_) | Self::Conflicting => Self::Conflicting,
        };
    }

    fn value(self) -> Option<Element<'a>> {
        match self {
            Self::One(entry) => Some(entry),
            Self::Absent | Self::Conflicting => None,
        }
    }
}

/// The entries of an authorization list that the audit reads.
#[derive(Default)]
struct Entries<'a> {
    root_of_trust: Entry<'a>,
    os_version: Entry<'a>,
    os_patch_level: Entry<'a>,
    vendor_patch_level: Entry<'a>,
    boot_patch_level: Entry<'a>,
}

/// Finds the entries the audit reads in `list`.
fn entries(list: Elements<'_>) -> Result<Entries<'_>, Error> {
    let mut found = Entries::default();
    for entry in list {
        let entry = entry?;
        if entry.tag.class != CLASS_CONTEXT {
            continue;
        }
        match entry.tag.number {
            TAG_ROOT_OF_TRUST => found.root_of_trust.add(entry),
            TAG_OS_VERSION => found.os_version.add(entry),
            TAG_OS_PATCH_LEVEL => found.os_patch_level.add(entry),
            TAG_VENDOR_PATCH_LEVEL => found.vendor_patch_level.add(entry),
            TAG_BOOT_PATCH_LEVEL => found.boot_patch_level.add(entry),
            _ => {}
        }
    }
    Ok(found)
}

fn security_level(value: u32) -> Result<SecurityLevel, Error> {
    match value {
        0 => Ok(SecurityLevel::Software),
        1 => Ok(SecurityLevel::TrustedEnvironment),
        2 => Ok(SecurityLevel::StrongBox),
        _ => Err(Error::InvalidValue),
    }
}

/// The one element inside an entry of an authorization list, whose tags are all EXPLICIT.
fn explicit(entry: Element<'_>) -> Result<Element<'_>, Error> {
    let mut inner = entry.contents(Tag {
        class: CLASS_CONTEXT,
        constructed: true,
        number: entry.tag.number,
    })?;
    let value = inner.required()?;
    inner.finish()?;
    Ok(value)
}

fn root_of_trust(entry: Element<'_>) -> Result<RootOfTrust<'_>, Error> {
    let mut fields = explicit(entry)?.contents(SEQUENCE)?;
    let verified_boot_key = fields.required()?.expect(OCTET_STRING)?;
    let device_locked = match fields.required()?.expect(BOOLEAN)? {
        [0x00] => false,
        // DER writes true as 0xFF only, but BER reads any other byte as true, and so do Google's
        // verifier and a keystore in the field: see the module documentation.
        [_] => true,
        // X.690, 8.2.1: a BOOLEAN has exactly one content byte.
        _ => return Err(Error::InvalidValue),
    };
    let verified_boot = match fields.required()?.enumerated()? {
        0 => VerifiedBootState::Verified,
        1 => VerifiedBootState::SelfSigned,
        2 => VerifiedBootState::Unverified,
        3 => VerifiedBootState::Failed,
        _ => return Err(Error::InvalidValue),
    };
    // verifiedBootHash, from attestation version 3. Earlier versions have three fields, and a
    // later keystore that leaves it out loses nothing else, so it is optional here, as in Google's
    // verifier.
    let verified_boot_hash = fields
        .next()
        .transpose()?
        .map(|hash| hash.expect(OCTET_STRING))
        .transpose()?;
    fields.finish()?;
    Ok(RootOfTrust {
        verified_boot_key,
        device_locked,
        verified_boot,
        verified_boot_hash,
    })
}

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_CONTEXT: u8 = 2;
const BOOLEAN: Tag = Tag::universal(1, false);
const INTEGER: Tag = Tag::universal(2, false);
const OCTET_STRING: Tag = Tag::universal(4, false);
const ENUMERATED: Tag = Tag::universal(10, false);
const SEQUENCE: Tag = Tag::universal(16, true);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tag {
    class: u8,
    constructed: bool,
    number: u32,
}

impl Tag {
    const fn universal(number: u32, constructed: bool) -> Self {
        Self {
            class: CLASS_UNIVERSAL,
            constructed,
            number,
        }
    }
}

/// Reads one element that must fill `input` completely.
fn read_one(input: &[u8]) -> Result<Element<'_>, Error> {
    let (element, rest) = Element::read(input)?;
    if !rest.is_empty() {
        return Err(Error::ExtraData);
    }
    Ok(element)
}

/// One DER element: its tag and the bytes of its content.
#[derive(Clone, Copy, Debug)]
struct Element<'a> {
    tag: Tag,
    content: &'a [u8],
}

impl<'a> Element<'a> {
    /// Reads the element at the start of `input`, and returns it with the bytes after it.
    fn read(input: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (&first, mut rest) = input.split_first().ok_or(Error::Truncated)?;
        let class = first >> 6;
        let constructed = first & 0x20 != 0;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            // The high tag number form: base-128 digits, most significant first. DER uses it only
            // from 31 on, and without a leading zero digit (X.690, 8.1.2.4).
            if rest.first() == Some(&0x80) {
                return Err(Error::NotDer);
            }
            number = 0;
            loop {
                let (&byte, tail) = rest.split_first().ok_or(Error::Truncated)?;
                rest = tail;
                number =
                    number.checked_mul(128).ok_or(Error::InvalidValue)? | u32::from(byte & 0x7f);
                if byte & 0x80 == 0 {
                    break;
                }
            }
            if number < 0x1f {
                return Err(Error::NotDer);
            }
        }
        let (&len_byte, tail) = rest.split_first().ok_or(Error::Truncated)?;
        rest = tail;
        let length = if len_byte & 0x80 == 0 {
            usize::from(len_byte)
        } else {
            // The long form, read as BER reads it: DER would use it only from 128 on and in as few
            // bytes as possible (X.690, 10.1), but the meaning is the same. The indefinite form
            // 0x80 is refused: see the module documentation.
            let count = usize::from(len_byte & 0x7f);
            match count {
                0 => return Err(Error::NotDer),
                // X.690, 8.1.3.5: 0xff is reserved.
                0x7f => return Err(Error::InvalidValue),
                _ => {}
            }
            let (bytes, tail) = rest.split_at_checked(count).ok_or(Error::Truncated)?;
            rest = tail;
            let length = bytes.iter().try_fold(0u32, |acc, &b| {
                acc.checked_mul(256)
                    .map(|shifted| shifted | u32::from(b))
                    .ok_or(Error::InvalidValue)
            })?;
            usize::try_from(length).map_err(|_| Error::InvalidValue)?
        };
        let (content, rest) = rest.split_at_checked(length).ok_or(Error::Truncated)?;
        Ok((
            Self {
                tag: Tag {
                    class,
                    constructed,
                    number,
                },
                content,
            },
            rest,
        ))
    }

    /// The element's content, once its tag is known to be `expected`.
    fn expect(self, expected: Tag) -> Result<&'a [u8], Error> {
        if self.tag == expected {
            Ok(self.content)
        } else {
            Err(Error::UnexpectedTag)
        }
    }

    /// The elements inside this one, once its tag is known to be `expected`.
    fn contents(self, expected: Tag) -> Result<Elements<'a>, Error> {
        self.expect(expected).map(|rest| Elements { rest })
    }

    /// A non-negative INTEGER that fits in a `u32`.
    fn integer(self) -> Result<u32, Error> {
        unsigned(self.expect(INTEGER)?)
    }

    /// A non-negative ENUMERATED that fits in a `u32`.
    fn enumerated(self) -> Result<u32, Error> {
        unsigned(self.expect(ENUMERATED)?)
    }
}

/// The value of the content of an INTEGER or ENUMERATED, which must be non-negative and fit in a
/// `u32`.
fn unsigned(content: &[u8]) -> Result<u32, Error> {
    match content {
        // X.690, 8.3.1: at least one content byte.
        [] => return Err(Error::InvalidValue),
        // X.690, 8.3.2: the first nine bits are never all zeros or all ones.
        [0x00, next, ..] if next & 0x80 == 0 => return Err(Error::NotDer),
        [0xff, next, ..] if next & 0x80 != 0 => return Err(Error::NotDer),
        [first, ..] if first & 0x80 != 0 => return Err(Error::InvalidValue),
        _ => {}
    }
    // A leading zero is left only before a byte from 0x80 on, as its sign.
    let digits = content.strip_prefix(&[0]).unwrap_or(content);
    if digits.len() > 4 {
        return Err(Error::InvalidValue);
    }
    Ok(digits
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

/// The elements inside a constructed element, read in order. After an error it yields nothing more.
struct Elements<'a> {
    rest: &'a [u8],
}

impl<'a> Elements<'a> {
    /// The next element, which the schema requires.
    fn required(&mut self) -> Result<Element<'a>, Error> {
        self.next().ok_or(Error::MissingField)?
    }

    /// Checks that no element is left.
    fn finish(&self) -> Result<(), Error> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::ExtraData)
        }
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Result<Element<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        match Element::read(self.rest) {
            Ok((element, rest)) => {
                self.rest = rest;
                Some(Ok(element))
            }
            Err(error) => {
                self.rest = &[];
                Some(Err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One element of a test extension. The tests build each extension as a tree, so that a test
    /// can change one element and have every enclosing length encoded again.
    #[derive(Clone, Debug)]
    struct Node {
        /// The identifier bytes: class, constructed bit and tag number.
        tag: Vec<u8>,
        body: Body,
        /// Whether the parser reads the content, as opposed to skipping it.
        read: bool,
        /// Whether a malformation here makes a value absent rather than the extension rejected: it
        /// sits in an entry the audit reads.
        lenient: bool,
        /// Whether the parser returns the content as it is, so that any part of it is still read.
        verbatim: bool,
    }

    #[derive(Clone, Debug)]
    enum Body {
        /// Content given as bytes.
        Bytes(Vec<u8>),
        /// Content made of elements, of which the schema requires at least `required`.
        Elements {
            children: Vec<Node>,
            required: usize,
        },
        /// The whole element given as bytes, tag and length included, for encodings that the
        /// other two forms would make canonical.
        Raw(Vec<u8>),
    }

    /// The DER length octets of `len`.
    fn length(len: usize) -> Vec<u8> {
        if len < 0x80 {
            return vec![u8::try_from(len).unwrap_or_default()];
        }
        let digits: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        let mut out = vec![0x80 | u8::try_from(digits.len()).unwrap_or_default()];
        out.extend(digits);
        out
    }

    fn content(node: &Node) -> Vec<u8> {
        match &node.body {
            Body::Bytes(bytes) | Body::Raw(bytes) => bytes.clone(),
            Body::Elements { children, .. } => children.iter().flat_map(encode).collect(),
        }
    }

    fn encode(node: &Node) -> Vec<u8> {
        if let Body::Raw(bytes) = &node.body {
            return bytes.clone();
        }
        let content = content(node);
        [node.tag.clone(), length(content.len()), content].concat()
    }

    fn primitive(tag: &[u8], content: &[u8]) -> Node {
        Node {
            tag: tag.to_vec(),
            body: Body::Bytes(content.to_vec()),
            read: true,
            lenient: false,
            verbatim: false,
        }
    }

    fn constructed(tag: &[u8], children: Vec<Node>, required: usize) -> Node {
        Node {
            tag: tag.to_vec(),
            body: Body::Elements { children, required },
            read: true,
            lenient: false,
            verbatim: false,
        }
    }

    fn raw(bytes: &[u8]) -> Node {
        Node {
            tag: Vec::new(),
            body: Body::Raw(bytes.to_vec()),
            read: true,
            lenient: false,
            verbatim: false,
        }
    }

    /// The shortest two's-complement content of a non-negative integer.
    fn unsigned_content(value: u64) -> Vec<u8> {
        let digits: Vec<u8> = value
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        match digits.first() {
            None => vec![0],
            Some(&first) if first & 0x80 != 0 => [vec![0], digits].concat(),
            Some(_) => digits,
        }
    }

    fn integer(value: u64) -> Node {
        primitive(&[0x02], &unsigned_content(value))
    }

    fn enumerated(value: u64) -> Node {
        primitive(&[0x0a], &unsigned_content(value))
    }

    fn octets(bytes: &[u8]) -> Node {
        primitive(&[0x04], bytes)
    }

    fn sequence(children: Vec<Node>, required: usize) -> Node {
        constructed(&[0x30], children, required)
    }

    fn set(children: Vec<Node>) -> Node {
        constructed(&[0x31], children, 0)
    }

    /// The identifier of a context-specific constructed tag, in the high tag number form from 31 on.
    fn context_tag(number: u32) -> Vec<u8> {
        if number < 31 {
            return vec![0xa0 | u8::try_from(number).unwrap_or_default()];
        }
        let mut digits = vec![u8::try_from(number & 0x7f).unwrap_or_default()];
        let mut rest = number >> 7;
        while rest > 0 {
            digits.push(0x80 | u8::try_from(rest & 0x7f).unwrap_or_default());
            rest >>= 7;
        }
        digits.push(0xbf);
        digits.reverse();
        digits
    }

    /// An entry of an authorization list, `[number] EXPLICIT`.
    fn explicit(number: u32, inner: Node) -> Node {
        constructed(&context_tag(number), vec![inner], 1)
    }

    /// Marks an element and everything in it as content the parser skips.
    fn unread(node: Node) -> Node {
        let body = match node.body {
            Body::Elements { children, required } => Body::Elements {
                children: children.into_iter().map(unread).collect(),
                required,
            },
            body => body,
        };
        Node {
            body,
            read: false,
            ..node
        }
    }

    /// Marks an element whose content the parser returns as it is.
    fn verbatim(node: Node) -> Node {
        Node {
            verbatim: true,
            ..node
        }
    }

    /// Marks an element and everything in it as part of an entry the audit reads.
    fn lenient(node: Node) -> Node {
        let body = match node.body {
            Body::Elements { children, required } => Body::Elements {
                children: children.into_iter().map(lenient).collect(),
                required,
            },
            body => body,
        };
        Node {
            body,
            lenient: true,
            ..node
        }
    }

    /// `[704] rootOfTrust`, with the verifiedBootHash of attestation version 3 and later.
    fn root(locked: u8, boot: u8) -> Node {
        lenient(explicit(
            TAG_ROOT_OF_TRUST,
            sequence(
                vec![
                    verbatim(octets(&[0xaa; 32])),
                    primitive(&[0x01], &[locked]),
                    enumerated(boot.into()),
                    verbatim(octets(&[0xbb; 32])),
                ],
                3,
            ),
        ))
    }

    /// `[706] osPatchLevel`.
    fn patch(level: u32) -> Node {
        lenient(explicit(TAG_OS_PATCH_LEVEL, integer(level.into())))
    }

    /// The other entries a `KeyMint` device puts in its hardware-enforced list, in tag order and
    /// split where `rootOfTrust` and `osPatchLevel` go: purpose, algorithm, key size, digest, EC
    /// curve, no authentication required, origin; then osVersion; then the vendor and boot patch
    /// levels.
    fn hardware(root: Option<Node>, patch: Option<Node>) -> Vec<Node> {
        let mut list = vec![
            unread(explicit(1, set(vec![integer(2)]))),
            unread(explicit(2, integer(3))),
            unread(explicit(3, integer(256))),
            unread(explicit(5, set(vec![integer(4)]))),
            unread(explicit(10, integer(1))),
            unread(explicit(503, primitive(&[0x05], &[]))),
            unread(explicit(702, integer(0))),
        ];
        list.extend(root);
        list.push(lenient(explicit(TAG_OS_VERSION, integer(150_000))));
        list.extend(patch);
        list.push(lenient(explicit(
            TAG_VENDOR_PATCH_LEVEL,
            integer(20_250_705),
        )));
        list.push(lenient(explicit(TAG_BOOT_PATCH_LEVEL, integer(20_250_705))));
        list
    }

    /// The entries a `KeyMint` device puts in its software-enforced list: creationDateTime and
    /// attestationApplicationId, with `extra` between them.
    fn software(extra: Vec<Node>) -> Vec<Node> {
        let mut list = vec![unread(explicit(701, integer(1_752_000_000_000)))];
        list.extend(extra);
        list.push(unread(explicit(709, octets(b"application id"))));
        list
    }

    /// The extension as `getExtensionValue` returns it, with attestation version 300 (`KeyMint`
    /// 3): the attestation's and the key's security levels, then the two lists.
    fn extension(levels: (u8, u8), software: Vec<Node>, hardware: Vec<Node>) -> Node {
        wrap(fields(levels, software, hardware))
    }

    /// The eight fields of a `KeyDescription`.
    fn fields(levels: (u8, u8), software: Vec<Node>, hardware: Vec<Node>) -> Vec<Node> {
        vec![
            integer(300),
            enumerated(levels.0.into()),
            integer(300),
            enumerated(levels.1.into()),
            verbatim(octets(b"challenge")),
            unread(octets(&[])),
            sequence(software, 0),
            sequence(hardware, 0),
        ]
    }

    /// The `KeyDescription` sequence of `fields`, in its OCTET STRING.
    fn wrap(fields: Vec<Node>) -> Node {
        constructed(&[0x04], vec![sequence(fields, 8)], 1)
    }

    const TEE: (u8, u8) = (1, 1);
    /// The root of trust `root(0xff, 0)` writes.
    const LOCKED_VERIFIED: RootOfTrust<'static> = RootOfTrust {
        verified_boot_key: &[0xaa; 32],
        device_locked: true,
        verified_boot: VerifiedBootState::Verified,
        verified_boot_hash: Some(&[0xbb; 32]),
    };

    /// A trusted environment's attestation of a locked, verified phone, as a `KeyMint` device
    /// writes it.
    fn tee_device() -> Node {
        extension(
            TEE,
            software(vec![]),
            hardware(Some(root(0xff, 0)), Some(patch(202_507))),
        )
    }

    /// The parser's result for `node`, with its bytes copied, so that it outlives the encoding.
    fn parse(node: &Node) -> Result<Owned, Error> {
        parse_key_description(&encode(node)).map(|d| Owned::from(&d))
    }

    /// A `KeyDescription` that owns its bytes.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Owned {
        attestation_version: u32,
        security_level: SecurityLevel,
        attestation_challenge: Vec<u8>,
        root_of_trust: Option<OwnedRoot>,
        os_version: Option<u32>,
        os_patch_level: Option<u32>,
        vendor_patch_level: Option<u32>,
        boot_patch_level: Option<u32>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OwnedRoot {
        verified_boot_key: Vec<u8>,
        device_locked: bool,
        verified_boot: VerifiedBootState,
        verified_boot_hash: Option<Vec<u8>>,
    }

    impl From<&RootOfTrust<'_>> for OwnedRoot {
        fn from(root: &RootOfTrust<'_>) -> Self {
            Self {
                verified_boot_key: root.verified_boot_key.to_vec(),
                device_locked: root.device_locked,
                verified_boot: root.verified_boot,
                verified_boot_hash: root.verified_boot_hash.map(<[u8]>::to_vec),
            }
        }
    }

    impl From<&KeyDescription<'_>> for Owned {
        fn from(d: &KeyDescription<'_>) -> Self {
            Self {
                attestation_version: d.attestation_version,
                security_level: d.security_level,
                attestation_challenge: d.attestation_challenge.to_vec(),
                root_of_trust: d.root_of_trust.as_ref().map(OwnedRoot::from),
                os_version: d.os_version,
                os_patch_level: d.os_patch_level,
                vendor_patch_level: d.vendor_patch_level,
                boot_patch_level: d.boot_patch_level,
            }
        }
    }

    /// The parts of a result that say which list it was read from.
    fn lock_and_patch(d: &Owned) -> (Option<(bool, VerifiedBootState)>, Option<u32>) {
        (
            d.root_of_trust
                .as_ref()
                .map(|r| (r.device_locked, r.verified_boot)),
            d.os_patch_level,
        )
    }

    /// What the parser makes of `tee_device()` with its element at `path` (child indices from the
    /// outer OCTET STRING) replaced by `replacement`.
    fn with(path: &[usize], replacement: Node) -> Result<Owned, Error> {
        fn replace(node: &mut Node, path: &[usize], replacement: Node) {
            match (path.split_first(), &mut node.body) {
                (None, _) => *node = replacement,
                (Some((&index, rest)), Body::Elements { children, .. }) => {
                    if let Some(child) = children.get_mut(index) {
                        replace(child, rest, replacement);
                    }
                }
                (Some(_), _) => {}
            }
        }
        let mut node = tee_device();
        replace(&mut node, path, replacement);
        parse(&node)
    }

    /// Paths into `tee_device()`.
    const VERSION: &[usize] = &[0, 0];
    const ATTESTATION_LEVEL: &[usize] = &[0, 1];
    const CHALLENGE: &[usize] = &[0, 4];
    const UNIQUE_ID: &[usize] = &[0, 5];
    const SOFTWARE: &[usize] = &[0, 6];
    const HARDWARE: &[usize] = &[0, 7];
    const HARDWARE_DIGEST: &[usize] = &[0, 7, 3];
    const ROOT_ENTRY: &[usize] = &[0, 7, 7];
    const ROOT_SEQUENCE: &[usize] = &[0, 7, 7, 0];
    const DEVICE_LOCKED: &[usize] = &[0, 7, 7, 0, 1];
    const BOOT_STATE: &[usize] = &[0, 7, 7, 0, 2];
    const PATCH_ENTRY: &[usize] = &[0, 7, 9];
    const PATCH_VALUE: &[usize] = &[0, 7, 9, 0];
    const VENDOR_PATCH_ENTRY: &[usize] = &[0, 7, 10];

    /// What the parser reads from `tee_device()`.
    fn tee_description() -> Owned {
        Owned::from(&KeyDescription {
            attestation_version: 300,
            security_level: SecurityLevel::TrustedEnvironment,
            attestation_challenge: b"challenge",
            root_of_trust: Some(LOCKED_VERIFIED),
            os_version: Some(150_000),
            os_patch_level: Some(202_507),
            vendor_patch_level: Some(202_507),
            boot_patch_level: Some(202_507),
        })
    }

    #[test]
    fn reads_locked_verified_tee_device() {
        assert_eq!(parse(&tee_device()), Ok(tee_description()));
    }

    #[test]
    fn reads_extensions_that_openssl_encoded() {
        // OpenSSL encoded these from configurations written from the published schema
        // (testdata/attestation/generate.sh), with no code shared with these tests' encoder.
        let tee = include_bytes!("../testdata/attestation/tee.der");
        assert_eq!(
            parse_key_description(tee).map(|d| Owned::from(&d)),
            Ok(tee_description())
        );
        // The tests' encoder writes the same bytes, so the extensions it builds are DER too.
        assert_eq!(encode(&tee_device()), tee);
        let software = include_bytes!("../testdata/attestation/software.der");
        assert_eq!(
            parse_key_description(software),
            Ok(KeyDescription {
                attestation_version: 300,
                security_level: SecurityLevel::Software,
                attestation_challenge: b"challenge",
                root_of_trust: Some(RootOfTrust {
                    verified_boot_key: &[],
                    device_locked: false,
                    verified_boot: VerifiedBootState::Unverified,
                    verified_boot_hash: Some(&[]),
                }),
                os_version: Some(160_000),
                os_patch_level: Some(202_608),
                vendor_patch_level: None,
                boot_patch_level: None,
            })
        );
    }

    // Real devices: the test chains of Google's reference library, android/keyattestation
    // (testdata/keyattestation: SOURCE, convert.py), with the values that library decodes.

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .filter_map(|pair| u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok())
            .collect()
    }

    fn level(name: &str) -> Option<SecurityLevel> {
        match name {
            "SOFTWARE" => Some(SecurityLevel::Software),
            "TRUSTED_ENVIRONMENT" => Some(SecurityLevel::TrustedEnvironment),
            "STRONG_BOX" => Some(SecurityLevel::StrongBox),
            _ => None,
        }
    }

    fn boot_state(name: &str) -> Option<VerifiedBootState> {
        match name {
            "VERIFIED" => Some(VerifiedBootState::Verified),
            "SELF_SIGNED" => Some(VerifiedBootState::SelfSigned),
            "UNVERIFIED" => Some(VerifiedBootState::Unverified),
            "FAILED" => Some(VerifiedBootState::Failed),
            _ => None,
        }
    }

    /// The rows of vectors.tsv: the file, its leaf's extension, and the columns Google's library
    /// decodes, as convert.py writes them.
    fn corpus() -> Vec<(&'static str, Vec<u8>, Vec<&'static str>)> {
        include_str!("../testdata/keyattestation/vectors.tsv")
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let columns: Vec<&str> = line.split('\t').collect();
                let (path, rest) = columns.split_first()?;
                let (extension, expected) = rest.split_first()?;
                Some((*path, hex(extension), expected.to_vec()))
            })
            .collect()
    }

    /// What `parse_key_description` must return for a row of Google's expected values: the
    /// weaker level, and the values of the list that level makes authoritative, patch levels read
    /// as Google's library reads them, by their first six digits.
    fn expected(columns: &[&str]) -> Option<Owned> {
        let level = level(columns.get(1)?)?.min(level(columns.get(2)?)?);
        let list = match level {
            SecurityLevel::Software => columns.get(4..12)?,
            _ => columns.get(12..20)?,
        };
        let present = |column: &str| (column != "-").then(|| hex(column));
        let root_of_trust = match (list.first()?, list.get(1)?) {
            (&"-", _) => None,
            (locked, state) => Some(OwnedRoot {
                verified_boot_key: present(list.get(2)?)?,
                device_locked: *locked == "true",
                verified_boot: boot_state(state)?,
                verified_boot_hash: present(list.get(3)?),
            }),
        };
        let number = |index: usize| list.get(index)?.parse().ok();
        let year_month = |index: usize| list.get(index)?.get(..6)?.parse().ok();
        Some(Owned {
            attestation_version: columns.first()?.parse().ok()?,
            security_level: level,
            attestation_challenge: hex(columns.get(3)?),
            root_of_trust,
            os_version: number(4),
            os_patch_level: year_month(5),
            vendor_patch_level: year_month(6),
            boot_patch_level: year_month(7),
        })
    }

    #[test]
    fn reads_every_real_device_as_googles_library_does() {
        let corpus = corpus();
        assert_eq!(corpus.len(), 9);
        let mut compared = 0;
        for (path, extension, columns) in &corpus {
            let parsed = parse_key_description(extension).map(|d| Owned::from(&d));
            if path.starts_with("invalid/") {
                continue;
            }
            assert_eq!(
                parsed,
                expected(columns).ok_or(Error::InvalidValue),
                "{path}"
            );
            compared += 1;
        }
        assert_eq!(compared, 7);
    }

    #[test]
    fn reads_googles_invalid_samples_as_decided() {
        let corpus = corpus();
        let parsed = |name: &str| {
            corpus
                .iter()
                .find(|(path, ..)| path.ends_with(name))
                .map(|(_, extension, _)| parse_key_description(extension))
        };
        // A genuine chain (its signatures verify) whose deviceLocked is 0x01, not DER's 0xFF: read
        // as true, as Google's library reads it.
        assert_eq!(
            parsed("malformed_rot_device_locked.pem")
                .and_then(Result::ok)
                .and_then(|d| d.root_of_trust)
                .map(|r| (r.device_locked, r.verified_boot)),
            Some((true, VerifiedBootState::Verified))
        );
        // Entries out of tag order are read; this sample's leaf signature does not verify, so the
        // chain check rejects it whatever its extension says.
        assert_eq!(
            parsed("tags_not_in_ascending_order.pem").map(|d| d.map(|d| d.os_patch_level)),
            Some(Ok(Some(202_408)))
        );
    }

    // Which list a value comes from.

    #[test]
    fn hardware_backed_attestation_ignores_the_software_list() {
        // The system can put any rootOfTrust and osPatchLevel in the software-enforced list. Where
        // the hardware left them out, they stay absent.
        for (levels, level) in [
            ((1, 1), SecurityLevel::TrustedEnvironment),
            ((2, 2), SecurityLevel::StrongBox),
        ] {
            let forged = extension(
                levels,
                software(vec![root(0xff, 0), patch(202_611)]),
                hardware(None, None),
            );
            let parsed = parse(&forged);
            assert_eq!(
                parsed.as_ref().map(lock_and_patch),
                Ok((None, None)),
                "{level:?}"
            );
            assert_eq!(parsed.map(|d| d.security_level), Ok(level));
        }
    }

    #[test]
    fn hardware_list_wins_when_both_lists_carry_values() {
        let both = extension(
            TEE,
            software(vec![root(0xff, 0), patch(202_611)]),
            hardware(Some(root(0x00, 2)), Some(patch(202_301))),
        );
        assert_eq!(
            parse(&both).as_ref().map(lock_and_patch),
            Ok((Some((false, VerifiedBootState::Unverified)), Some(202_301)))
        );
    }

    #[test]
    fn software_attestation_reads_only_the_software_list() {
        // AOSP's software keystore, as on the emulator: everything in the software-enforced list.
        // Whatever its hardware-enforced list says is no more trustworthy, and is not read.
        let software_only = extension(
            (0, 0),
            software(vec![root(0x00, 2), patch(202_608)]),
            hardware(Some(root(0xff, 0)), Some(patch(202_611))),
        );
        let parsed = parse(&software_only);
        assert_eq!(
            parsed.as_ref().map(lock_and_patch),
            Ok((Some((false, VerifiedBootState::Unverified)), Some(202_608)))
        );
        // The hardware list's other values are not read either.
        assert_eq!(
            parsed.map(|d| (d.os_version, d.vendor_patch_level, d.boot_patch_level)),
            Ok((None, None, None))
        );
    }

    #[test]
    fn security_level_is_the_weaker_of_the_two() {
        for (levels, expected) in [
            // A software keystore that attests the keys of an older trusted environment, as the
            // Pixel XL's (android/keyattestation, testdata/marlin).
            ((0, 1), SecurityLevel::Software),
            ((1, 0), SecurityLevel::Software),
            ((2, 1), SecurityLevel::TrustedEnvironment),
            ((1, 2), SecurityLevel::TrustedEnvironment),
            ((2, 2), SecurityLevel::StrongBox),
        ] {
            let attestation = extension(
                levels,
                software(vec![]),
                hardware(Some(root(0xff, 0)), Some(patch(202_507))),
            );
            assert_eq!(
                parse(&attestation).map(|d| d.security_level),
                Ok(expected),
                "levels {levels:?}"
            );
        }
    }

    // Encodings: what the parser accepts, and where it differs from DER (see the module
    // documentation).

    #[test]
    fn reads_lengths_in_any_definite_form() {
        // 300 as an INTEGER is 02 02 01 2c in DER; BER also writes its length as below.
        for encoding in [
            &[0x02, 0x81, 0x02, 0x01, 0x2c][..],
            &[0x02, 0x82, 0x00, 0x02, 0x01, 0x2c],
            &[0x02, 0x84, 0x00, 0x00, 0x00, 0x02, 0x01, 0x2c],
        ] {
            assert_eq!(
                with(VERSION, raw(encoding)).map(|d| d.attestation_version),
                Ok(300)
            );
        }
        // The hardware list is 161 bytes, 30 81 a1 in DER; 30 82 00 a1 says the same.
        let list = encode(&sequence(
            hardware(Some(root(0xff, 0)), Some(patch(202_507))),
            0,
        ));
        assert_eq!(list.get(..3), Some(&[0x30, 0x81, 0xa1][..]));
        let padded = [
            &[0x30, 0x82, 0x00, 0xa1][..],
            list.get(3..).unwrap_or_default(),
        ]
        .concat();
        assert_eq!(with(HARDWARE, raw(&padded)), parse(&tee_device()));
        // An element of exactly 128 bytes takes the long form, 04 81 80, in DER too.
        let unique_id = octets(&[0x11; 128]);
        assert_eq!(encode(&unique_id).get(..3), Some(&[0x04, 0x81, 0x80][..]));
        assert_eq!(with(UNIQUE_ID, unique_id), parse(&tee_device()));
    }

    #[test]
    fn refuses_indefinite_and_oversized_lengths() {
        // The indefinite form, with its end-of-contents octets.
        let root = encode(&root(0xff, 0));
        let fields = root.get(6..).unwrap_or_default();
        let indefinite = [&[0x30, 0x80][..], fields, &[0x00, 0x00]].concat();
        let list = content(&sequence(hardware(None, None), 0));
        let indefinite_list = [&[0x30, 0x80][..], &list, &[0x00, 0x00]].concat();
        assert_eq!(with(HARDWARE, raw(&indefinite_list)), Err(Error::NotDer));
        // Inside an entry the audit reads, it makes the entry malformed, so absent.
        assert_eq!(
            with(ROOT_SEQUENCE, raw(&indefinite)).map(|d| d.root_of_trust),
            Ok(None)
        );
        // A length beyond 32 bits, and the reserved 0xff.
        assert_eq!(
            with(VERSION, raw(&[0x02, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00])),
            Err(Error::InvalidValue)
        );
        // 0xff is reserved even where the 127 bytes after it would make a length.
        let reserved = [&[0x02, 0xff][..], &[0; 126], &[0x02, 0x01, 0x2c]].concat();
        assert_eq!(with(VERSION, raw(&reserved)), Err(Error::InvalidValue));
        // Leading zero bytes do not count against it.
        assert_eq!(
            with(
                VERSION,
                raw(&[0x02, 0x88, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x01, 0x2c])
            )
            .map(|d| d.attestation_version),
            Ok(300)
        );
    }

    #[test]
    fn rejects_tag_numbers_that_are_not_the_shortest() {
        // [5] in the high tag number form, which DER and BouncyCastle keep for 31 and above.
        let digest = encode(&explicit(5, set(vec![integer(4)])));
        let long_form = [&[0xbf, 0x05][..], digest.get(1..).unwrap_or_default()].concat();
        assert_eq!(with(HARDWARE_DIGEST, raw(&long_form)), Err(Error::NotDer));
        // The boundary: 30 in the high form is refused, 31 is its first number.
        assert_eq!(
            with(HARDWARE_DIGEST, primitive(&[0xbf, 0x1e], &[])),
            Err(Error::NotDer)
        );
        assert_eq!(
            with(HARDWARE_DIGEST, primitive(&[0xbf, 0x1f], &[])),
            parse(&tee_device())
        );
        // [704] with a leading zero digit.
        let root = encode(&root(0xff, 0));
        let padded = [
            &[0xbf, 0x80, 0x85, 0x40][..],
            root.get(3..).unwrap_or_default(),
        ]
        .concat();
        assert_eq!(with(ROOT_ENTRY, raw(&padded)), Err(Error::NotDer));
    }

    #[test]
    fn rejects_tag_numbers_beyond_32_bits() {
        // [2^32]: five base-128 digits whose value does not fit a u32.
        assert_eq!(
            with(
                HARDWARE_DIGEST,
                raw(&[0xbf, 0x90, 0x80, 0x80, 0x80, 0x00, 0x00])
            ),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn skips_elements_of_other_classes_in_a_list() {
        // No authorization list holds an element that is not a context-specific entry, but such an
        // element is skipped like an entry the audit does not use, even with a number it reads.
        let mut list = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        list.insert(0, primitive(&[0x1f, 0x85, 0x40], &[0x00]));
        list.insert(0, integer(704));
        assert_eq!(
            parse(&extension(TEE, software(vec![]), list)),
            parse(&tee_device())
        );
    }

    #[test]
    fn rejects_integers_that_are_not_the_shortest() {
        assert_eq!(
            with(VERSION, primitive(&[0x02], &[0x00, 0x01, 0x2c])),
            Err(Error::NotDer)
        );
        assert_eq!(
            with(ATTESTATION_LEVEL, primitive(&[0x0a], &[0x00, 0x01])),
            Err(Error::NotDer)
        );
        // A redundant 0xff before a negative number is NotDer, not just a negative value.
        assert_eq!(
            with(VERSION, primitive(&[0x02], &[0xff, 0x80])),
            Err(Error::NotDer)
        );
        // A negative number in its shortest form is out of range, not its byte read as 128.
        assert_eq!(
            with(VERSION, primitive(&[0x02], &[0x80])),
            Err(Error::InvalidValue)
        );
        // In an entry the audit reads, the entry is malformed, so absent.
        assert_eq!(
            with(PATCH_VALUE, primitive(&[0x02], &[0x00, 0x03, 0x17, 0x0b]))
                .map(|d| d.os_patch_level),
            Ok(None)
        );
        // A sign byte where one is needed is the shortest form.
        assert_eq!(
            with(VERSION, primitive(&[0x02], &[0x00, 0x80])).map(|d| d.attestation_version),
            Ok(128)
        );
    }

    #[test]
    fn integer_and_enumerated_are_not_interchangeable() {
        for (path, wrong) in [(VERSION, enumerated(300)), (ATTESTATION_LEVEL, integer(1))] {
            assert_eq!(with(path, wrong), Err(Error::UnexpectedTag), "{path:?}");
        }
        assert_eq!(
            with(BOOT_STATE, integer(0)).map(|d| d.root_of_trust),
            Ok(None)
        );
        assert_eq!(
            with(PATCH_VALUE, enumerated(202_507)).map(|d| d.os_patch_level),
            Ok(None)
        );
    }

    #[test]
    fn device_locked_is_false_only_as_zero() {
        let read = |content: &[u8]| {
            with(DEVICE_LOCKED, primitive(&[0x01], content))
                .map(|d| d.root_of_trust.map(|r| r.device_locked))
        };
        assert_eq!(read(&[0x00]), Ok(Some(false)));
        // DER writes only 0xff; BER, Google's verifier and a keystore in the field also others.
        for value in [0xff, 0x01, 0x02, 0x7f, 0x80, 0xfe] {
            assert_eq!(read(&[value]), Ok(Some(true)), "{value:#x}");
        }
        // Not one byte: the root of trust is malformed, so absent.
        assert_eq!(read(&[]), Ok(None));
        assert_eq!(read(&[0xff, 0xff]), Ok(None));
    }

    #[test]
    fn a_malformed_root_of_trust_is_absent() {
        let fields = || {
            vec![
                octets(&[0xaa; 32]),
                primitive(&[0x01], &[0xff]),
                enumerated(0),
                octets(&[0xbb; 32]),
            ]
        };
        let read = |node: Node| with(ROOT_SEQUENCE, node).map(|d| d.root_of_trust);
        assert_eq!(read(set(fields())), Ok(None));
        let mut three = fields();
        three.truncate(3);
        assert_eq!(
            read(sequence(three, 3)),
            Ok(Some(OwnedRoot {
                verified_boot_hash: None,
                ..OwnedRoot::from(&LOCKED_VERIFIED)
            }))
        );
        let mut two = fields();
        two.truncate(2);
        assert_eq!(read(sequence(two, 3)), Ok(None));
        let mut five = fields();
        five.push(octets(&[]));
        assert_eq!(read(sequence(five, 3)), Ok(None));
        let mut hash_as_integer = fields();
        hash_as_integer.truncate(3);
        hash_as_integer.push(integer(1));
        assert_eq!(read(sequence(hash_as_integer, 3)), Ok(None));
        let mut key_as_integer = fields();
        key_as_integer.remove(0);
        key_as_integer.insert(0, integer(1));
        assert_eq!(read(sequence(key_as_integer, 3)), Ok(None));
        // The rest of the attestation still counts.
        assert_eq!(
            with(ROOT_SEQUENCE, set(fields())).map(|d| d.os_patch_level),
            Ok(Some(202_507))
        );
    }

    #[test]
    fn an_entry_that_does_not_hold_exactly_one_element_is_absent() {
        let root_sequence = || {
            sequence(
                vec![
                    octets(&[0xaa; 32]),
                    primitive(&[0x01], &[0xff]),
                    enumerated(0),
                ],
                3,
            )
        };
        let root_entry = |children: Vec<Node>| {
            with(
                ROOT_ENTRY,
                constructed(&context_tag(TAG_ROOT_OF_TRUST), children, 1),
            )
            .map(|d| d.root_of_trust)
        };
        assert_eq!(root_entry(vec![root_sequence(), root_sequence()]), Ok(None));
        assert_eq!(root_entry(vec![]), Ok(None));
        assert_eq!(
            with(
                PATCH_ENTRY,
                constructed(
                    &context_tag(TAG_OS_PATCH_LEVEL),
                    vec![integer(202_507), integer(202_611)],
                    1
                )
            )
            .map(|d| d.os_patch_level),
            Ok(None)
        );
        // EXPLICIT tagging makes the entry constructed.
        let primitive_root = primitive(&[0x9f, 0x85, 0x40], &encode(&root_sequence()));
        assert_eq!(
            with(ROOT_ENTRY, primitive_root).map(|d| d.root_of_trust),
            Ok(None)
        );
    }

    #[test]
    fn key_description_has_exactly_its_eight_fields() {
        let tee = || fields(TEE, software(vec![]), hardware(Some(root(0xff, 0)), None));
        let mut nine = tee();
        nine.push(octets(&[]));
        assert_eq!(parse(&wrap(nine)), Err(Error::ExtraData));
        let mut seven = tee();
        seven.pop();
        assert_eq!(parse(&wrap(seven)), Err(Error::MissingField));
    }

    #[test]
    fn fields_carry_the_types_of_the_schema() {
        assert_eq!(with(CHALLENGE, integer(1)), Err(Error::UnexpectedTag));
        assert_eq!(with(UNIQUE_ID, integer(1)), Err(Error::UnexpectedTag));
        assert_eq!(
            with(HARDWARE, set(hardware(Some(root(0xff, 0)), None))),
            Err(Error::UnexpectedTag)
        );
        assert_eq!(with(SOFTWARE, octets(&[])), Err(Error::UnexpectedTag));
        // A constructed OCTET STRING around the whole: BER, never what getExtensionValue returns.
        let mut constructed_wrapper = encode(&tee_device());
        if let Some(first) = constructed_wrapper.first_mut() {
            *first = 0x24;
        }
        assert_eq!(
            parse_key_description(&constructed_wrapper),
            Err(Error::UnexpectedTag)
        );
    }

    #[test]
    fn reads_a_repeated_entry_only_when_its_copies_agree() {
        let twice = |entries: Vec<Node>| extension(TEE, software(vec![]), entries);
        let mut same = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        same.push(root(0xff, 0));
        same.push(patch(202_507));
        assert_eq!(parse(&twice(same)), parse(&tee_device()));
        let mut roots = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        roots.push(root(0x00, 2));
        assert_eq!(
            parse(&twice(roots)).map(|d| (d.root_of_trust, d.os_patch_level)),
            Ok((None, Some(202_507)))
        );
        let mut patches = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        patches.push(patch(202_611));
        assert_eq!(
            parse(&twice(patches)).map(|d| (d.root_of_trust, d.os_patch_level)),
            Ok((Some(OwnedRoot::from(&LOCKED_VERIFIED)), None))
        );
        // Copies whose content agrees but whose tags do not, the second one primitive, also differ.
        let root_sequence = encode(&sequence(
            vec![
                octets(&[0xaa; 32]),
                primitive(&[0x01], &[0xff]),
                enumerated(0),
            ],
            3,
        ));
        let mut mixed = hardware(None, Some(patch(202_507)));
        mixed.push(lenient(constructed(
            &context_tag(TAG_ROOT_OF_TRUST),
            vec![raw(&root_sequence)],
            1,
        )));
        mixed.push(lenient(primitive(&[0x9f, 0x85, 0x40], &root_sequence)));
        assert_eq!(parse(&twice(mixed)).map(|d| d.root_of_trust), Ok(None));
        // In the list that is not read, it changes nothing.
        let ignored = extension(
            TEE,
            software(vec![root(0x00, 2), root(0x00, 3)]),
            hardware(Some(root(0xff, 0)), Some(patch(202_507))),
        );
        assert_eq!(parse(&ignored), parse(&tee_device()));
    }

    #[test]
    fn reads_entries_in_any_order() {
        let mut list = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        list.reverse();
        assert_eq!(
            parse(&extension(TEE, software(vec![]), list)),
            parse(&tee_device())
        );
    }

    // Error names, and values of any size.

    #[test]
    fn names_a_missing_field_and_extra_data() {
        let mut seven = fields(TEE, software(vec![]), hardware(None, None));
        seven.pop();
        assert_eq!(parse(&wrap(seven)), Err(Error::MissingField));
        let mut trailing = encode(&tee_device());
        trailing.push(0);
        assert_eq!(parse_key_description(&trailing), Err(Error::ExtraData));
        assert_eq!(
            parse_key_description(&encode(&sequence(vec![], 0))),
            Err(Error::UnexpectedTag)
        );
        assert_eq!(parse_key_description(&[]), Err(Error::Truncated));
    }

    #[test]
    fn reads_patch_levels_of_six_or_eight_digits() {
        let read = |value: u64| with(PATCH_VALUE, integer(value)).map(|d| d.os_patch_level);
        for (value, year_month) in [
            (202_507, Some(202_507)),
            (20_250_705, Some(202_507)),
            (100_001, Some(100_001)),
            (99_991_231, Some(999_912)),
            // Not six or eight digits, or no month: malformed, so absent, as Google's verifier.
            (0, None),
            (99_999, None),
            (1_000_000, None),
            // Seven digits, whose first five would read as a year and a valid month.
            (2_020_112, None),
            (100_000_000, None),
            (202_500, None),
            (202_513, None),
            (20_251_305, None),
            (u64::from(u32::MAX), None),
            (u64::from(u32::MAX) + 1, None),
        ] {
            assert_eq!(read(value), Ok(year_month), "{value}");
        }
        assert_eq!(
            with(PATCH_VALUE, primitive(&[0x02], &[0x80])).map(|d| d.os_patch_level),
            Ok(None)
        );
        // The vendor and boot levels are read alike, from the same list.
        let vendor = lenient(explicit(TAG_VENDOR_PATCH_LEVEL, integer(202_406)));
        assert_eq!(
            with(VENDOR_PATCH_ENTRY, vendor).map(|d| d.vendor_patch_level),
            Ok(Some(202_406))
        );
    }

    #[test]
    fn refuses_integers_beyond_32_bits_and_short_patch_levels() {
        // An INTEGER beyond 32 bits whose low 32 bits are a plausible value: refused, not cut.
        assert_eq!(
            with(VERSION, integer((1 << 32) + 300)),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            with(PATCH_VALUE, integer((1 << 32) + 202_507)).map(|d| d.os_patch_level),
            Ok(None)
        );
        // Fewer than six digits, with a month in range: not a patch level.
        for value in [1, 12, 507, 2_507, 99_912] {
            assert_eq!(
                with(PATCH_VALUE, integer(value)).map(|d| d.os_patch_level),
                Ok(None),
                "{value}"
            );
        }
    }

    #[test]
    fn reads_each_verified_boot_state() {
        for (value, state) in [
            (0, VerifiedBootState::Verified),
            (1, VerifiedBootState::SelfSigned),
            (2, VerifiedBootState::Unverified),
            (3, VerifiedBootState::Failed),
        ] {
            assert_eq!(
                with(BOOT_STATE, enumerated(value))
                    .map(|d| d.root_of_trust.map(|r| r.verified_boot)),
                Ok(Some(state))
            );
        }
        // Out of range: malformed, so absent.
        assert_eq!(
            with(BOOT_STATE, enumerated(4)).map(|d| d.root_of_trust),
            Ok(None)
        );
    }

    #[test]
    fn stops_reading_elements_after_an_error() {
        // The callers return at the first error, so this is not needed for what they read; it keeps
        // the iterator from reporting the same broken element again to a caller that went on.
        let mut elements = Elements {
            rest: &[0x02, 0x05, 0x01],
        };
        assert!(matches!(elements.next(), Some(Err(Error::Truncated))));
        assert!(elements.next().is_none());
    }

    #[test]
    fn rejects_out_of_range_security_levels() {
        assert_eq!(
            with(ATTESTATION_LEVEL, enumerated(3)),
            Err(Error::InvalidValue)
        );
    }

    // Truncation of every element, not only of the outer one.

    /// What the parser must make of an extension with one element cut short.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Expect {
        /// An error: the cut left an element the parser reads incomplete, or a required one out.
        Rejected,
        /// The description of the whole extension: the parser skips the element that was cut.
        Unchanged,
        /// The whole extension's description, but for values whose entries were cut away.
        Consistent,
        /// Anything but a panic: a cut integer is still an integer, of another value.
        Any,
        /// A description, of whatever value: the parser returns the element's content as it is.
        Read,
    }

    /// Every way to cut one element's content short, each in the whole extension encoded again
    /// around it, with what the parser must make of it.
    fn truncations(node: &Node) -> Vec<(Node, Expect)> {
        let whole = content(node);
        let mut out = Vec::new();
        for cut in 0..whole.len() {
            let strict = match &node.body {
                _ if !node.read => Expect::Unchanged,
                Body::Bytes(_) | Body::Raw(_) if node.verbatim => Expect::Read,
                Body::Bytes(_) | Body::Raw(_) if cut == 0 => Expect::Rejected,
                Body::Bytes(_) | Body::Raw(_) => Expect::Any,
                Body::Elements { children, required } => {
                    // The number of children left whole, if the cut falls between two.
                    let mut end = 0;
                    let kept = std::iter::once(0)
                        .chain(children.iter().map(|child| {
                            end += encode(child).len();
                            end
                        }))
                        .position(|boundary| boundary == cut);
                    match kept {
                        Some(kept) if kept >= *required => Expect::Consistent,
                        _ => Expect::Rejected,
                    }
                }
            };
            // In an entry the audit reads, what would reject the extension makes the value absent.
            let expect = match strict {
                Expect::Rejected if node.lenient => Expect::Consistent,
                other => other,
            };
            let cut_node = Node {
                body: Body::Bytes(whole.get(..cut).unwrap_or_default().to_vec()),
                ..node.clone()
            };
            out.push((cut_node, expect));
        }
        if let Body::Elements { children, required } = &node.body {
            for (index, child) in children.iter().enumerate() {
                for (cut_child, expect) in truncations(child) {
                    let mut children = children.clone();
                    if let Some(slot) = children.get_mut(index) {
                        *slot = cut_child;
                    }
                    let body = Body::Elements {
                        children,
                        required: *required,
                    };
                    out.push((
                        Node {
                            body,
                            ..node.clone()
                        },
                        expect,
                    ));
                }
            }
        }
        out
    }

    fn check_every_truncation(extension: &Node) -> usize {
        let Ok(whole) = parse(extension) else {
            return 0;
        };
        let cases = truncations(extension);
        for (index, (cut, expect)) in cases.iter().enumerate() {
            let parsed = parse(cut);
            match expect {
                Expect::Rejected => assert!(parsed.is_err(), "case {index}: {parsed:?}"),
                Expect::Unchanged => assert_eq!(parsed.as_ref(), Ok(&whole), "case {index}"),
                Expect::Consistent => {
                    let Ok(cut) = parsed else {
                        assert!(parsed.is_ok(), "case {index}: {parsed:?}");
                        continue;
                    };
                    assert_eq!(cut.attestation_version, whole.attestation_version);
                    assert_eq!(cut.security_level, whole.security_level);
                    assert_eq!(cut.attestation_challenge, whole.attestation_challenge);
                    // A root of trust is whole, or absent, or without its optional last field.
                    let root = |hash| {
                        whole.root_of_trust.clone().map(|r| OwnedRoot {
                            verified_boot_hash: hash,
                            ..r
                        })
                    };
                    assert!(
                        cut.root_of_trust.is_none()
                            || cut.root_of_trust == whole.root_of_trust
                            || cut.root_of_trust == root(None),
                        "case {index}: {cut:?}"
                    );
                    for (value, whole) in [
                        (cut.os_version, whole.os_version),
                        (cut.os_patch_level, whole.os_patch_level),
                        (cut.vendor_patch_level, whole.vendor_patch_level),
                        (cut.boot_patch_level, whole.boot_patch_level),
                    ] {
                        assert!(value.is_none() || value == whole, "case {index}: {cut:?}");
                    }
                }
                Expect::Read => assert!(parsed.is_ok(), "case {index}: {parsed:?}"),
                Expect::Any => {}
            }
        }
        cases.len()
    }

    #[test]
    fn rejects_every_truncation_of_every_element() {
        // A trusted environment's attestation whose software list carries a forged root of trust
        // and patch level: no cut may bring them in.
        let tee = extension(
            TEE,
            software(vec![unread(root(0xff, 0)), unread(patch(202_611))]),
            hardware(Some(root(0x00, 2)), Some(patch(202_301))),
        );
        // A software attestation, with the hardware list of a keystore that attests in software
        // for an older trusted environment.
        let software_only = extension(
            (0, 1),
            software(vec![root(0x00, 2), patch(202_608)]),
            hardware(None, None),
        );
        for fixture in [tee, software_only] {
            let whole = encode(&fixture).len();
            let cases = check_every_truncation(&fixture);
            // Each byte of each element's content is a cut, so there are far more cases than the
            // outer element's own cuts.
            assert!(cases > 4 * whole, "{cases} cases for {whole} bytes");
        }
    }
}
