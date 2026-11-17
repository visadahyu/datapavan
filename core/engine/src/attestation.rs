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

/// Where the attested key lives, and so how much the attestation can be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Where the attestation was produced.
    pub security_level: SecurityLevel,
    /// Bootloader state, taken from the hardware-enforced list when present.
    pub root_of_trust: Option<RootOfTrust>,
    /// Operating-system patch level as `YYYYMM`.
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
    /// A length or a value could not be represented.
    InvalidValue,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated attestation extension",
            Self::MissingField => "missing field in attestation extension",
            Self::ExtraData => "unexpected data after a field of attestation extension",
            Self::UnexpectedTag => "unexpected element in attestation extension",
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
/// Returns an [`Error`] when the input is not a well-formed `KeyDescription`.
pub fn parse_key_description(extension: &[u8]) -> Result<KeyDescription, Error> {
    let wrapper = Element::read_one(extension, Tag::universal(TAG_OCTET_STRING, false))?;
    let sequence = Element::read_one(wrapper.content, Tag::universal(TAG_SEQUENCE, true))?;
    let fields = sequence.children()?;

    let attestation_version = fields.first().ok_or(Error::MissingField)?.unsigned()?;
    let security_level = match fields.get(1).ok_or(Error::MissingField)?.unsigned()? {
        0 => SecurityLevel::Software,
        1 => SecurityLevel::TrustedEnvironment,
        2 => SecurityLevel::StrongBox,
        _ => return Err(Error::InvalidValue),
    };
    let software = fields.get(6).ok_or(Error::MissingField)?.children()?;
    let hardware = fields.get(7).ok_or(Error::MissingField)?.children()?;

    // The hardware-enforced list is authoritative; software keystores fill only the other one.
    let root_of_trust = match find(&hardware, TAG_ROOT_OF_TRUST) {
        Some(element) => Some(root_of_trust(element)?),
        None => find(&software, TAG_ROOT_OF_TRUST)
            .map(root_of_trust)
            .transpose()?,
    };
    let os_patch_level = find(&hardware, TAG_OS_PATCH_LEVEL)
        .or_else(|| find(&software, TAG_OS_PATCH_LEVEL))
        .map(|explicit| {
            explicit
                .children()?
                .first()
                .ok_or(Error::MissingField)?
                .unsigned()
        })
        .transpose()?;

    Ok(KeyDescription {
        attestation_version,
        security_level,
        root_of_trust,
        os_patch_level,
    })
}

fn find<'l, 'a>(list: &'l [Element<'a>], tag: u32) -> Option<&'l Element<'a>> {
    list.iter()
        .find(|e| e.tag.class == CLASS_CONTEXT && e.tag.number == tag)
}

fn root_of_trust(explicit: &Element<'_>) -> Result<RootOfTrust, Error> {
    let inner = explicit.children()?;
    let sequence = inner.first().ok_or(Error::MissingField)?;
    let fields = sequence.children()?;
    let locked = fields.get(1).ok_or(Error::MissingField)?;
    if locked.tag != Tag::universal(TAG_BOOLEAN, false) {
        return Err(Error::UnexpectedTag);
    }
    let device_locked = match locked.content {
        [0] => false,
        [_] => true,
        _ => return Err(Error::InvalidValue),
    };
    let verified_boot = match fields.get(2).ok_or(Error::MissingField)?.unsigned()? {
        0 => VerifiedBootState::Verified,
        1 => VerifiedBootState::SelfSigned,
        2 => VerifiedBootState::Unverified,
        3 => VerifiedBootState::Failed,
        _ => return Err(Error::InvalidValue),
    };
    Ok(RootOfTrust {
        device_locked,
        verified_boot,
    })
}

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_CONTEXT: u8 = 2;
const TAG_BOOLEAN: u32 = 1;
const TAG_INTEGER: u32 = 2;
const TAG_OCTET_STRING: u32 = 4;
const TAG_ENUMERATED: u32 = 10;
const TAG_SEQUENCE: u32 = 16;

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

/// One DER element: its tag and the bytes of its content.
#[derive(Clone, Copy, Debug)]
struct Element<'a> {
    tag: Tag,
    content: &'a [u8],
}

impl<'a> Element<'a> {
    /// Reads one element that must fill `input` completely and carry `expected` as its tag.
    fn read_one(input: &'a [u8], expected: Tag) -> Result<Self, Error> {
        let (element, rest) = Self::read(input)?;
        if element.tag != expected {
            return Err(Error::UnexpectedTag);
        }
        if !rest.is_empty() {
            return Err(Error::ExtraData);
        }
        Ok(element)
    }

    fn read(input: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let (&first, mut rest) = input.split_first().ok_or(Error::Truncated)?;
        let class = first >> 6;
        let constructed = first & 0x20 != 0;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
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
        }
        let (&len_byte, tail) = rest.split_first().ok_or(Error::Truncated)?;
        rest = tail;
        let length = if len_byte & 0x80 == 0 {
            usize::from(len_byte)
        } else {
            let count = usize::from(len_byte & 0x7f);
            if count == 0 || count > 4 {
                return Err(Error::InvalidValue);
            }
            let (bytes, tail) = rest.split_at_checked(count).ok_or(Error::Truncated)?;
            rest = tail;
            bytes
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b))
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

    /// The elements inside a constructed element.
    fn children(&self) -> Result<Vec<Self>, Error> {
        if !self.tag.constructed {
            return Err(Error::UnexpectedTag);
        }
        let mut out = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (child, tail) = Self::read(rest)?;
            out.push(child);
            rest = tail;
        }
        Ok(out)
    }

    /// A non-negative INTEGER or ENUMERATED that fits in a `u32`.
    fn unsigned(&self) -> Result<u32, Error> {
        let integer = Tag::universal(TAG_INTEGER, false);
        let enumerated = Tag::universal(TAG_ENUMERATED, false);
        if self.tag != integer && self.tag != enumerated {
            return Err(Error::UnexpectedTag);
        }
        let bytes = match self.content {
            [] => return Err(Error::InvalidValue),
            [first, ..] if first & 0x80 != 0 => return Err(Error::InvalidValue),
            [0, rest @ ..] if !rest.is_empty() => rest,
            all => all,
        };
        if bytes.len() > 4 {
            return Err(Error::InvalidValue);
        }
        Ok(bytes.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
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
            Body::Bytes(bytes) => bytes.clone(),
            Body::Elements { children, .. } => children.iter().flat_map(encode).collect(),
        }
    }

    fn encode(node: &Node) -> Vec<u8> {
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
            body @ Body::Bytes(_) => body,
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
            unread(integer(300)),
            unread(enumerated(levels.1.into())),
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
    const ATTESTATION_LEVEL: &[usize] = &[0, 1];
    const ROOT_SEQUENCE: &[usize] = &[0, 7, 7, 0];
    const BOOT_STATE: &[usize] = &[0, 7, 7, 0, 2];
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

    #[test]
    fn reads_software_attestation_from_the_software_list() {
        let software_only = extension(
            (0, 0),
            software(vec![root(0x00, 2), patch(202_608)]),
            hardware(None, None),
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
                Body::Bytes(_) if cut == 0 => Expect::Rejected,
                Body::Bytes(_) => Expect::Any,
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
        // A trusted environment's attestation of an unlocked phone.
        let tee = extension(
            TEE,
            software(vec![]),
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
