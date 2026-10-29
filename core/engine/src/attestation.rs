//! Android key attestation: the `KeyDescription` extension of an attestation certificate.
//!
//! The extension (OID 1.3.6.1.4.1.11129.2.1.17) states, among other things, whether the bootloader
//! is locked and whether verified boot succeeded. The bytes come from the device's keystore, which
//! a compromised system can tamper with, so they are parsed as untrusted input: every length is
//! checked, nesting is bounded, and malformed input is an error, never a panic.
//!
//! Only the fields the audit needs are decoded. Schema:
//! <https://source.android.com/docs/security/features/keystore/attestation#schema>

use core::fmt;

/// Context-specific tag of `rootOfTrust` in an `AuthorizationList`.
const TAG_ROOT_OF_TRUST: u32 = 704;
/// Context-specific tag of `osPatchLevel` in an `AuthorizationList`.
const TAG_OS_PATCH_LEVEL: u32 = 706;
/// Deeper nesting than this never occurs in a valid `KeyDescription`.
const MAX_DEPTH: u8 = 8;

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
    /// An element had a tag other than the one the schema requires.
    UnexpectedTag,
    /// A length or a value could not be represented.
    InvalidValue,
    /// Elements were nested deeper than any valid `KeyDescription`.
    TooDeep,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated attestation extension",
            Self::UnexpectedTag => "unexpected element in attestation extension",
            Self::InvalidValue => "invalid value in attestation extension",
            Self::TooDeep => "attestation extension nested too deeply",
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

    let attestation_version = fields.first().ok_or(Error::Truncated)?.unsigned()?;
    let security_level = match fields.get(1).ok_or(Error::Truncated)?.unsigned()? {
        0 => SecurityLevel::Software,
        1 => SecurityLevel::TrustedEnvironment,
        2 => SecurityLevel::StrongBox,
        _ => return Err(Error::InvalidValue),
    };
    let software = fields.get(6).ok_or(Error::Truncated)?.children()?;
    let hardware = fields.get(7).ok_or(Error::Truncated)?.children()?;

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
                .ok_or(Error::Truncated)?
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
    let sequence = inner.first().ok_or(Error::Truncated)?;
    let fields = sequence.children()?;
    let locked = fields.get(1).ok_or(Error::Truncated)?;
    if locked.tag != Tag::universal(TAG_BOOLEAN, false) {
        return Err(Error::UnexpectedTag);
    }
    let device_locked = match locked.content {
        [0] => false,
        [_] => true,
        _ => return Err(Error::InvalidValue),
    };
    let verified_boot = match fields.get(2).ok_or(Error::Truncated)?.unsigned()? {
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
    depth: u8,
}

impl<'a> Element<'a> {
    /// Reads one element that must fill `input` completely and carry `expected` as its tag.
    fn read_one(input: &'a [u8], expected: Tag) -> Result<Self, Error> {
        let (element, rest) = Self::read(input, 0)?;
        if element.tag != expected {
            return Err(Error::UnexpectedTag);
        }
        if !rest.is_empty() {
            return Err(Error::InvalidValue);
        }
        Ok(element)
    }

    fn read(input: &'a [u8], depth: u8) -> Result<(Self, &'a [u8]), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
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
                depth,
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
            let (child, tail) = Self::read(rest, self.depth.saturating_add(1))?;
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

    /// Encodes one DER element with a short or long length.
    fn der(tag: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        let len = content.len();
        if len < 128 {
            out.push(u8::try_from(len).unwrap_or_default());
        } else {
            out.extend_from_slice(&[
                0x82,
                u8::try_from(len >> 8).unwrap_or_default(),
                u8::try_from(len & 0xff).unwrap_or_default(),
            ]);
        }
        out.extend_from_slice(content);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        der(&[0x30], &parts.concat())
    }

    /// Context-specific constructed tag with a multi-byte number (704 = 0x05 0x40, 706 = 0x05 0x42).
    fn explicit(number: u32, inner: &[u8]) -> Vec<u8> {
        let high = u8::try_from(number >> 7).unwrap_or_default() | 0x80;
        let low = u8::try_from(number & 0x7f).unwrap_or_default();
        der(&[0xbf, high, low], inner)
    }

    fn key_description(
        locked: u8,
        boot: u8,
        level: u8,
        patch: Option<u32>,
        in_hardware: bool,
    ) -> Vec<u8> {
        let root = explicit(
            TAG_ROOT_OF_TRUST,
            &seq(&[
                der(&[0x04], &[0xaa; 32]),
                der(&[0x01], &[locked]),
                der(&[0x0a], &[boot]),
                der(&[0x04], &[0xbb; 32]),
            ]),
        );
        let mut list = vec![root];
        if let Some(p) = patch {
            list.push(explicit(
                TAG_OS_PATCH_LEVEL,
                &der(
                    &[0x02],
                    &[
                        0x03,
                        u8::try_from((p >> 8) & 0xff).unwrap_or_default(),
                        u8::try_from(p & 0xff).unwrap_or_default(),
                    ],
                ),
            ));
        }
        let filled = seq(&list);
        let empty = seq(&[]);
        let (software, hardware) = if in_hardware {
            (empty, filled)
        } else {
            (filled, empty)
        };
        let body = seq(&[
            der(&[0x02], &[0x03]),
            der(&[0x0a], &[level]),
            der(&[0x02], &[0x04]),
            der(&[0x0a], &[level]),
            der(&[0x04], b"challenge"),
            der(&[0x04], &[]),
            software,
            hardware,
        ]);
        der(&[0x04], &body)
    }

    #[test]
    fn reads_locked_verified_tee_device() {
        let parsed = parse_key_description(&key_description(0xff, 0, 1, Some(202_303), true));
        assert_eq!(
            parsed,
            Ok(KeyDescription {
                attestation_version: 3,
                security_level: SecurityLevel::TrustedEnvironment,
                root_of_trust: Some(RootOfTrust {
                    device_locked: true,
                    verified_boot: VerifiedBootState::Verified
                }),
                os_patch_level: Some(202_303),
            })
        );
    }

    #[test]
    fn reads_software_attestation_from_the_software_list() {
        let parsed = parse_key_description(&key_description(0, 2, 0, None, false));
        assert_eq!(
            parsed.map(|d| (d.security_level, d.root_of_trust, d.os_patch_level)),
            Ok((
                SecurityLevel::Software,
                Some(RootOfTrust {
                    device_locked: false,
                    verified_boot: VerifiedBootState::Unverified
                }),
                None
            ))
        );
    }

    #[test]
    fn rejects_every_truncation_without_panicking() {
        let full = key_description(0xff, 0, 1, Some(202_303), true);
        for cut in 0..full.len() {
            assert!(
                parse_key_description(full.get(..cut).unwrap_or_default()).is_err(),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes_and_wrong_tags() {
        let mut extra = key_description(0xff, 0, 1, None, true);
        extra.push(0);
        assert_eq!(parse_key_description(&extra), Err(Error::InvalidValue));
        assert_eq!(
            parse_key_description(&der(&[0x30], &[])),
            Err(Error::UnexpectedTag)
        );
    }

    #[test]
    fn rejects_out_of_range_enums_and_negative_integers() {
        assert_eq!(
            parse_key_description(&key_description(0xff, 7, 1, None, true)),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            parse_key_description(&key_description(0xff, 0, 5, None, true)),
            Err(Error::InvalidValue)
        );
        assert_eq!(
            Element {
                tag: Tag::universal(TAG_INTEGER, false),
                content: &[0x80],
                depth: 0
            }
            .unsigned(),
            Err(Error::InvalidValue)
        );
    }

    #[test]
    fn bounds_nesting_depth() {
        let mut nested = der(&[0x02], &[0x01]);
        for _ in 0..20 {
            nested = seq(&[nested]);
        }
        let mut current = Element::read(&nested, 0).map(|(e, _)| e);
        let outcome = loop {
            match current {
                Ok(e) => match e.children() {
                    Ok(kids) => current = kids.first().copied().ok_or(Error::Truncated),
                    Err(err) => break err,
                },
                Err(err) => break err,
            }
        };
        assert_eq!(outcome, Error::TooDeep);
    }
}
