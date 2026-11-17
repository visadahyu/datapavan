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
//! The schema requires DER, and every element the parser reads must be DER (X.690, section 10):
//! lengths and tag numbers in their shortest form, integers without a redundant leading byte,
//! INTEGER and ENUMERATED each where the schema puts it, a BOOLEAN of 0x00 or 0xFF, and no element
//! beyond those the schema allows. DER gives each value one encoding, so this parser and any other
//! strict one, such as a verifier on a server, cannot read the same bytes in two ways. Two
//! tolerances follow Google's reference verifier, each for an encoding whose meaning is not in
//! doubt:
//!
//! - `deviceLocked` as 0x01 is read as true. Google's verifier accepts it and only logs it
//!   (`android/keyattestation`: the sample `testdata/invalid/malformed_rot_device_locked.pem`, a
//!   chain of four certificates, and commit 2462d01 of 2026-09-23), which suggests that a keystore
//!   in the field writes it; rejecting it would cost such a phone the whole check. Other values
//!   that DER forbids stay errors.
//! - The entries of an authorization list may come in any order, and the content of an entry the
//!   audit does not use (such as the purposes' SET OF) is not read. Google's verifier checks the
//!   order only on request and tolerates malformed entries it does not need (commits a6e9faf and
//!   4198c45), and an error there would cost the user the check over a field the audit ignores. An
//!   entry the audit reads that appears twice is an error, since the two could disagree.
//!
//! # Depth
//!
//! The parser descends by the schema, never by the input, and without recursion: the deepest
//! element it reads is a field of `RootOfTrust`, five elements below the extension's OCTET STRING
//! (`KeyDescription`, an authorization list, the `[704]` wrapper, `RootOfTrust`, the field).
//! Nesting in the input cannot take it deeper, so it needs no depth limit.

use core::fmt;

/// Context-specific tag of `rootOfTrust` in an `AuthorizationList`.
const TAG_ROOT_OF_TRUST: u32 = 704;
/// Context-specific tag of `osPatchLevel` in an `AuthorizationList`.
const TAG_OS_PATCH_LEVEL: u32 = 706;

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

/// Bootloader state from the `RootOfTrust` sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootOfTrust {
    /// Whether the bootloader is locked.
    pub device_locked: bool,
    /// Result of verified boot.
    pub verified_boot: VerifiedBootState,
}

/// The fields of a `KeyDescription` that the audit uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDescription {
    /// Attestation format version, e.g. 3 for Keymaster 4 or 400 for `KeyMint` 4.
    pub attestation_version: u32,
    /// Where the attestation was produced: the weaker of the attestation's and the key's levels.
    pub security_level: SecurityLevel,
    /// Bootloader state, from the hardware-enforced list unless [`Self::security_level`] is
    /// [`SecurityLevel::Software`], and then from the software-enforced list; never from the other
    /// list (see the module documentation).
    pub root_of_trust: Option<RootOfTrust>,
    /// Operating-system patch level as `YYYYMM`, from the same list as [`Self::root_of_trust`].
    pub os_patch_level: Option<u32>,
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
    /// An encoding that BER allows but DER, which the schema requires, does not.
    NotDer,
    /// A value outside its range, such as an unknown enumeration value or a negative number.
    InvalidValue,
    /// A field that the audit reads appears twice in one authorization list.
    DuplicateField,
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
            Self::DuplicateField => "repeated field in attestation extension",
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
pub fn parse_key_description(extension: &[u8]) -> Result<KeyDescription, Error> {
    let wrapper = read_one(extension)?.expect(OCTET_STRING)?;
    let mut fields = read_one(wrapper)?.contents(SEQUENCE)?;

    let attestation_version = fields.required()?.integer()?;
    let attestation_level = security_level(fields.required()?.enumerated()?)?;
    // keyMintVersion: checked, but the audit does not use it.
    fields.required()?.integer()?;
    let keymint_level = security_level(fields.required()?.enumerated()?)?;
    // attestationChallenge and uniqueId.
    fields.required()?.expect(OCTET_STRING)?;
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

    Ok(KeyDescription {
        attestation_version,
        security_level,
        root_of_trust: entries.root_of_trust.map(root_of_trust).transpose()?,
        os_patch_level: entries
            .os_patch_level
            .map(|entry| explicit(entry)?.integer())
            .transpose()?,
    })
}

/// The entries of an authorization list that the audit reads.
#[derive(Default)]
struct Entries<'a> {
    root_of_trust: Option<Element<'a>>,
    os_patch_level: Option<Element<'a>>,
}

/// Finds the entries the audit reads in `list`, each of which may appear once.
fn entries(list: Elements<'_>) -> Result<Entries<'_>, Error> {
    let mut found = Entries::default();
    for entry in list {
        let entry = entry?;
        if entry.tag.class != CLASS_CONTEXT {
            continue;
        }
        let slot = match entry.tag.number {
            TAG_ROOT_OF_TRUST => &mut found.root_of_trust,
            TAG_OS_PATCH_LEVEL => &mut found.os_patch_level,
            _ => continue,
        };
        if slot.replace(entry).is_some() {
            return Err(Error::DuplicateField);
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

fn root_of_trust(entry: Element<'_>) -> Result<RootOfTrust, Error> {
    let mut fields = explicit(entry)?.contents(SEQUENCE)?;
    // verifiedBootKey: checked, but the audit does not use it.
    fields.required()?.expect(OCTET_STRING)?;
    let device_locked = match fields.required()?.expect(BOOLEAN)? {
        [0x00] => false,
        // 0x01 is not DER, but Google's verifier accepts it: see the module documentation.
        [0xff | 0x01] => true,
        [_] => return Err(Error::NotDer),
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
    // later keystore that leaves it out loses nothing the audit reads, so it is optional here.
    if let Some(hash) = fields.next() {
        hash?.expect(OCTET_STRING)?;
    }
    fields.finish()?;
    Ok(RootOfTrust {
        device_locked,
        verified_boot,
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
            // The long form: DER uses it only from 128 on, in as few bytes as possible, and never
            // the indefinite form 0x80 (X.690, 10.1).
            let count = usize::from(len_byte & 0x7f);
            if count == 0 {
                return Err(Error::NotDer);
            }
            if count > 4 {
                return Err(Error::InvalidValue);
            }
            let (bytes, tail) = rest.split_at_checked(count).ok_or(Error::Truncated)?;
            rest = tail;
            if bytes.first() == Some(&0) {
                return Err(Error::NotDer);
            }
            let length = bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            if length < 0x80 {
                return Err(Error::NotDer);
            }
            length
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
        }
    }

    fn constructed(tag: &[u8], children: Vec<Node>, required: usize) -> Node {
        Node {
            tag: tag.to_vec(),
            body: Body::Elements { children, required },
            read: true,
        }
    }

    fn raw(bytes: &[u8]) -> Node {
        Node {
            tag: Vec::new(),
            body: Body::Raw(bytes.to_vec()),
            read: true,
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

    /// `[704] rootOfTrust`, with the verifiedBootHash of attestation version 3 and later.
    fn root(locked: u8, boot: u8) -> Node {
        explicit(
            TAG_ROOT_OF_TRUST,
            sequence(
                vec![
                    unread(octets(&[0xaa; 32])),
                    primitive(&[0x01], &[locked]),
                    enumerated(boot.into()),
                    unread(octets(&[0xbb; 32])),
                ],
                3,
            ),
        )
    }

    /// `[706] osPatchLevel`.
    fn patch(level: u32) -> Node {
        explicit(TAG_OS_PATCH_LEVEL, integer(level.into()))
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
        list.push(unread(explicit(705, integer(150_000))));
        list.extend(patch);
        list.push(unread(explicit(718, integer(20_250_705))));
        list.push(unread(explicit(719, integer(20_250_705))));
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
            unread(octets(b"challenge")),
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
    const LOCKED_VERIFIED: RootOfTrust = RootOfTrust {
        device_locked: true,
        verified_boot: VerifiedBootState::Verified,
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

    fn parse(node: &Node) -> Result<KeyDescription, Error> {
        parse_key_description(&encode(node))
    }

    /// What the parser makes of `tee_device()` with its element at `path` (child indices from the
    /// outer OCTET STRING) replaced by `replacement`.
    fn with(path: &[usize], replacement: Node) -> Result<KeyDescription, Error> {
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
    const SOFTWARE: &[usize] = &[0, 6];
    const HARDWARE: &[usize] = &[0, 7];
    const HARDWARE_DIGEST: &[usize] = &[0, 7, 3];
    const ROOT_ENTRY: &[usize] = &[0, 7, 7];
    const ROOT_SEQUENCE: &[usize] = &[0, 7, 7, 0];
    const DEVICE_LOCKED: &[usize] = &[0, 7, 7, 0, 1];
    const BOOT_STATE: &[usize] = &[0, 7, 7, 0, 2];
    const PATCH_ENTRY: &[usize] = &[0, 7, 9];
    const PATCH_VALUE: &[usize] = &[0, 7, 9, 0];

    fn description(
        security_level: SecurityLevel,
        root_of_trust: Option<RootOfTrust>,
        os_patch_level: Option<u32>,
    ) -> KeyDescription {
        KeyDescription {
            attestation_version: 300,
            security_level,
            root_of_trust,
            os_patch_level,
        }
    }

    #[test]
    fn reads_locked_verified_tee_device() {
        assert_eq!(
            parse(&tee_device()),
            Ok(description(
                SecurityLevel::TrustedEnvironment,
                Some(LOCKED_VERIFIED),
                Some(202_507)
            ))
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
            assert_eq!(parse(&forged), Ok(description(level, None, None)));
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
            parse(&both),
            Ok(description(
                SecurityLevel::TrustedEnvironment,
                Some(RootOfTrust {
                    device_locked: false,
                    verified_boot: VerifiedBootState::Unverified,
                }),
                Some(202_301)
            ))
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
        assert_eq!(
            parse(&software_only),
            Ok(description(
                SecurityLevel::Software,
                Some(RootOfTrust {
                    device_locked: false,
                    verified_boot: VerifiedBootState::Unverified,
                }),
                Some(202_608)
            ))
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

    // DER.

    #[test]
    fn rejects_lengths_that_are_not_the_shortest() {
        // 300 as an INTEGER is 02 02 01 2c.
        for encoding in [
            &[0x02, 0x81, 0x02, 0x01, 0x2c][..],
            &[0x02, 0x82, 0x00, 0x02, 0x01, 0x2c],
            &[0x02, 0x84, 0x00, 0x00, 0x00, 0x02, 0x01, 0x2c],
        ] {
            assert_eq!(with(VERSION, raw(encoding)), Err(Error::NotDer));
        }
        // The indefinite form, with its end-of-contents octets.
        let root = encode(&root(0xff, 0));
        let fields = root.get(6..).unwrap_or_default();
        let indefinite = [&[0x30, 0x80][..], fields, &[0x00, 0x00]].concat();
        assert_eq!(with(ROOT_SEQUENCE, raw(&indefinite)), Err(Error::NotDer));
        // A length too large for any extension.
        assert_eq!(
            with(VERSION, raw(&[0x02, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00])),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn rejects_tag_numbers_that_are_not_the_shortest() {
        // [5] in the high tag number form, which DER keeps for 31 and above.
        let digest = encode(&explicit(5, set(vec![integer(4)])));
        let long_form = [&[0xbf, 0x05][..], digest.get(1..).unwrap_or_default()].concat();
        assert_eq!(with(HARDWARE_DIGEST, raw(&long_form)), Err(Error::NotDer));
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
    fn rejects_integers_that_are_not_the_shortest() {
        assert_eq!(
            with(PATCH_VALUE, primitive(&[0x02], &[0x00, 0x03, 0x17, 0x0b])),
            Err(Error::NotDer)
        );
        assert_eq!(
            with(VERSION, primitive(&[0x02], &[0x00, 0x01, 0x2c])),
            Err(Error::NotDer)
        );
        assert_eq!(
            with(ATTESTATION_LEVEL, primitive(&[0x0a], &[0x00, 0x01])),
            Err(Error::NotDer)
        );
        assert_eq!(
            with(VERSION, primitive(&[0x02], &[0xff, 0x80])),
            Err(Error::NotDer)
        );
        // A sign byte where one is needed is the shortest form.
        assert_eq!(
            with(PATCH_VALUE, primitive(&[0x02], &[0x00, 0x80])).map(|d| d.os_patch_level),
            Ok(Some(128))
        );
    }

    #[test]
    fn integer_and_enumerated_are_not_interchangeable() {
        for (path, wrong) in [
            (VERSION, enumerated(300)),
            (ATTESTATION_LEVEL, integer(1)),
            (BOOT_STATE, integer(0)),
            (PATCH_VALUE, enumerated(202_507)),
        ] {
            assert_eq!(with(path, wrong), Err(Error::UnexpectedTag), "{path:?}");
        }
    }

    #[test]
    fn device_locked_is_der_but_for_one_tolerance() {
        let read = |content: &[u8]| {
            with(DEVICE_LOCKED, primitive(&[0x01], content))
                .map(|d| d.root_of_trust.map(|r| r.device_locked))
        };
        assert_eq!(read(&[0x00]), Ok(Some(false)));
        assert_eq!(read(&[0xff]), Ok(Some(true)));
        // Google's verifier accepts 0x01; see the module documentation.
        assert_eq!(read(&[0x01]), Ok(Some(true)));
        for value in [0x02, 0x7f, 0x80, 0xfe] {
            assert_eq!(read(&[value]), Err(Error::NotDer), "{value:#x}");
        }
        assert_eq!(read(&[]), Err(Error::InvalidValue));
        assert_eq!(read(&[0xff, 0xff]), Err(Error::InvalidValue));
    }

    #[test]
    fn root_of_trust_is_a_sequence_of_three_or_four_fields() {
        let fields = || {
            vec![
                octets(&[0xaa; 32]),
                primitive(&[0x01], &[0xff]),
                enumerated(0),
                octets(&[0xbb; 32]),
            ]
        };
        assert_eq!(
            with(ROOT_SEQUENCE, set(fields())),
            Err(Error::UnexpectedTag)
        );
        let mut three = fields();
        three.truncate(3);
        assert_eq!(
            with(ROOT_SEQUENCE, sequence(three, 3)).map(|d| d.root_of_trust),
            Ok(Some(LOCKED_VERIFIED))
        );
        let mut five = fields();
        five.push(octets(&[]));
        assert_eq!(
            with(ROOT_SEQUENCE, sequence(five, 3)),
            Err(Error::ExtraData)
        );
        let mut hash_as_integer = fields();
        hash_as_integer.truncate(3);
        hash_as_integer.push(integer(1));
        assert_eq!(
            with(ROOT_SEQUENCE, sequence(hash_as_integer, 3)),
            Err(Error::UnexpectedTag)
        );
    }

    #[test]
    fn an_entry_holds_exactly_one_element() {
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
        assert_eq!(
            with(
                ROOT_ENTRY,
                constructed(
                    &context_tag(TAG_ROOT_OF_TRUST),
                    vec![root_sequence(), root_sequence()],
                    1
                )
            ),
            Err(Error::ExtraData)
        );
        assert_eq!(
            with(
                PATCH_ENTRY,
                constructed(
                    &context_tag(TAG_OS_PATCH_LEVEL),
                    vec![integer(202_507), integer(202_611)],
                    1
                )
            ),
            Err(Error::ExtraData)
        );
        assert_eq!(
            with(
                ROOT_ENTRY,
                constructed(&context_tag(TAG_ROOT_OF_TRUST), vec![], 1)
            ),
            Err(Error::MissingField)
        );
        // EXPLICIT tagging makes the entry constructed.
        let primitive_root = primitive(&[0x9f, 0x85, 0x40], &encode(&root_sequence()));
        assert_eq!(with(ROOT_ENTRY, primitive_root), Err(Error::UnexpectedTag));
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
        assert_eq!(
            with(HARDWARE, set(hardware(Some(root(0xff, 0)), None))),
            Err(Error::UnexpectedTag)
        );
        assert_eq!(with(SOFTWARE, octets(&[])), Err(Error::UnexpectedTag));
    }

    #[test]
    fn rejects_a_field_the_audit_reads_twice() {
        let twice = |entries: Vec<Node>| extension(TEE, software(vec![]), entries);
        let mut roots = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        roots.push(root(0x00, 2));
        assert_eq!(parse(&twice(roots)), Err(Error::DuplicateField));
        let mut patches = hardware(Some(root(0xff, 0)), Some(patch(202_507)));
        patches.push(patch(202_611));
        assert_eq!(parse(&twice(patches)), Err(Error::DuplicateField));
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
        assert_eq!(
            with(ROOT_SEQUENCE, sequence(vec![octets(&[0xaa; 32])], 3)),
            Err(Error::MissingField)
        );
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
    fn reads_patch_levels_of_any_size() {
        for level in [0, 127, 128, 202_507, 20_250_705, u32::MAX] {
            assert_eq!(
                with(PATCH_VALUE, integer(level.into())).map(|d| d.os_patch_level),
                Ok(Some(level))
            );
        }
        assert_eq!(
            with(PATCH_VALUE, integer(u64::from(u32::MAX) + 1)),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            with(PATCH_VALUE, primitive(&[0x02], &[0x80])),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn rejects_out_of_range_enums() {
        assert_eq!(with(BOOT_STATE, enumerated(4)), Err(Error::InvalidValue));
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
    }

    /// Every way to cut one element's content short, each in the whole extension encoded again
    /// around it, with what the parser must make of it.
    fn truncations(node: &Node) -> Vec<(Node, Expect)> {
        let whole = content(node);
        let mut out = Vec::new();
        for cut in 0..whole.len() {
            let expect = match &node.body {
                _ if !node.read => Expect::Unchanged,
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
                Expect::Unchanged => assert_eq!(parsed, Ok(whole), "case {index}"),
                Expect::Consistent => {
                    let Ok(cut) = parsed else {
                        assert!(parsed.is_ok(), "case {index}: {parsed:?}");
                        continue;
                    };
                    assert_eq!(cut.attestation_version, whole.attestation_version);
                    assert_eq!(cut.security_level, whole.security_level);
                    assert!(
                        cut.root_of_trust.is_none() || cut.root_of_trust == whole.root_of_trust,
                        "case {index}: {cut:?}"
                    );
                    assert!(
                        cut.os_patch_level.is_none() || cut.os_patch_level == whole.os_patch_level,
                        "case {index}: {cut:?}"
                    );
                }
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
