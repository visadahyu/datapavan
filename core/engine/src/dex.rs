//! DEX files: the classes that an app's code defines.
//!
//! The tracker scanner matches these class names against tracker signatures. The bytes come from
//! other apps' packages, which may be built to attack a scanner, so they are parsed as untrusted
//! input: every offset, count and length is checked against the file, and malformed input is an
//! error, never a panic. Only what the scanner needs is decoded: the descriptors of the classes in
//! `class_defs`, the list that `dexdump` prints as "Class descriptor". Format:
//! <https://source.android.com/docs/core/runtime/dex-format>

use core::fmt;

/// Size of `header_item` up to version 040.
const HEADER_SIZE: u32 = 0x70;
/// Size of `header_item` from version 041, which adds `container_size` and `header_offset`.
const CONTAINER_HEADER_SIZE: u32 = 0x78;
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;
/// `type_ids` holds at most this many entries, and each class is defined once.
const MAX_TYPE_IDS: u32 = 65_535;
const CLASS_DEF_SIZE: u32 = 0x20;
/// Logical DEX files in one version-041 container; real containers hold a handful.
const MAX_LOGICAL_FILES: usize = 256;

/// Why a DEX file could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input does not start like a DEX file.
    NotDex,
    /// A DEX version this parser does not know.
    UnsupportedVersion,
    /// A byte-swapped file, which Android itself does not load.
    ReverseEndian,
    /// The input ended, or an offset pointed, outside the file.
    OutOfBounds,
    /// A header field or a table entry has an impossible value.
    InvalidValue,
    /// A string is not valid modified UTF-8 or does not have its declared length.
    InvalidString,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotDex => "not a DEX file",
            Self::UnsupportedVersion => "unsupported DEX version",
            Self::ReverseEndian => "byte-swapped DEX file",
            Self::OutOfBounds => "offset outside the DEX file",
            Self::InvalidValue => "invalid value in DEX file",
            Self::InvalidString => "invalid string in DEX file",
        })
    }
}

impl std::error::Error for Error {}

/// Lists the classes that a DEX file defines, as Java names (`com.example.Foo`, `a.b$C`), in the
/// order of its `class_defs`. A version-041 container yields the classes of all its logical files.
///
/// # Errors
///
/// Returns an [`Error`] when the input is not a well-formed DEX file of version 035 to 041.
pub fn defined_classes(dex: &[u8]) -> Result<Vec<String>, Error> {
    let mut classes = Vec::new();
    let mut start = 0;
    for _ in 0..MAX_LOGICAL_FILES {
        let header = Header::read(dex, start)?;
        header.read_classes(dex, &mut classes)?;
        match header.next {
            Some(next) if next < dex.len() => start = next,
            _ => return Ok(classes),
        }
    }
    Err(Error::InvalidValue)
}

/// The fields of one `header_item` that the class list needs. Offsets are from the start of the
/// input, also for the later logical files of a container.
struct Header {
    string_ids: Table,
    type_ids: Table,
    class_defs: Table,
    /// Start of the next logical file in a container.
    next: Option<usize>,
}

/// An array of fixed-size items.
struct Table {
    size: u32,
    offset: usize,
}

impl Header {
    fn read(dex: &[u8], start: usize) -> Result<Self, Error> {
        let magic = dex.get(start..start.checked_add(8).ok_or(Error::OutOfBounds)?);
        let version = match magic {
            Some([b'd', b'e', b'x', b'\n', d1, d2, d3, 0])
                if [d1, d2, d3].iter().all(|d| d.is_ascii_digit()) =>
            {
                u32::from(d1 - b'0') * 100 + u32::from(d2 - b'0') * 10 + u32::from(d3 - b'0')
            }
            Some(_) => return Err(Error::NotDex),
            None => {
                return Err(if start == 0 {
                    Error::NotDex
                } else {
                    Error::OutOfBounds
                });
            }
        };
        if !matches!(version, 35 | 37..=41) {
            return Err(Error::UnsupportedVersion);
        }
        let field =
            |offset: usize| read_u32(dex, start.checked_add(offset).ok_or(Error::OutOfBounds)?);

        match field(0x28)? {
            ENDIAN_CONSTANT => {}
            REVERSE_ENDIAN_CONSTANT => return Err(Error::ReverseEndian),
            _ => return Err(Error::InvalidValue),
        }
        let container = version >= 41;
        let header_size = if container {
            CONTAINER_HEADER_SIZE
        } else {
            HEADER_SIZE
        };
        if field(0x24)? != header_size {
            return Err(Error::InvalidValue);
        }
        let file_size = index(field(0x20)?)?;
        let end = start.checked_add(file_size).ok_or(Error::OutOfBounds)?;
        if file_size < index(header_size)? || end > dex.len() {
            return Err(Error::OutOfBounds);
        }
        let next = if container {
            if index(field(0x70)?)? != dex.len() || index(field(0x74)?)? != start {
                return Err(Error::InvalidValue);
            }
            Some(end)
        } else {
            if start != 0 || end != dex.len() {
                return Err(Error::InvalidValue);
            }
            None
        };

        let table = |offset: usize, item_size: u32| -> Result<Table, Error> {
            let size = field(offset)?;
            let table = Table {
                size,
                offset: index(field(offset + 4)?)?,
            };
            let length = index(size)?
                .checked_mul(index(item_size)?)
                .ok_or(Error::OutOfBounds)?;
            let table_end = table.offset.checked_add(length).ok_or(Error::OutOfBounds)?;
            if table_end > dex.len() {
                return Err(Error::OutOfBounds);
            }
            Ok(table)
        };
        let header = Self {
            string_ids: table(0x38, 4)?,
            type_ids: table(0x40, 4)?,
            class_defs: table(0x60, CLASS_DEF_SIZE)?,
            next,
        };
        if header.type_ids.size > MAX_TYPE_IDS || header.class_defs.size > header.type_ids.size {
            return Err(Error::InvalidValue);
        }
        Ok(header)
    }

    fn read_classes(&self, dex: &[u8], classes: &mut Vec<String>) -> Result<(), Error> {
        classes.reserve(index(self.class_defs.size)?);
        for class in 0..self.class_defs.size {
            let class_idx = read_u32(dex, item(&self.class_defs, class, CLASS_DEF_SIZE)?)?;
            if class_idx >= self.type_ids.size {
                return Err(Error::InvalidValue);
            }
            let descriptor_idx = read_u32(dex, item(&self.type_ids, class_idx, 4)?)?;
            if descriptor_idx >= self.string_ids.size {
                return Err(Error::InvalidValue);
            }
            let data = index(read_u32(dex, item(&self.string_ids, descriptor_idx, 4)?)?)?;
            classes.push(class_name(&read_string(dex, data)?)?);
        }
        Ok(())
    }
}

/// Offset of item `number` in `table`; the table's bounds were checked when the header was read.
fn item(table: &Table, number: u32, item_size: u32) -> Result<usize, Error> {
    index(number)?
        .checked_mul(index(item_size)?)
        .and_then(|relative| table.offset.checked_add(relative))
        .ok_or(Error::OutOfBounds)
}

fn index(value: u32) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::OutOfBounds)
}

fn read_u32(dex: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = dex
        .get(offset..offset.checked_add(4).ok_or(Error::OutOfBounds)?)
        .ok_or(Error::OutOfBounds)?;
    let mut word = [0; 4];
    word.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(word))
}

/// Reads a `string_data_item`: the length in UTF-16 code units as `uleb128`, then modified UTF-8
/// ending in a zero byte. Modified UTF-8 writes U+0000 as two bytes and each half of a surrogate
/// pair as three bytes, so it decodes to UTF-16 code units first.
fn read_string(dex: &[u8], offset: usize) -> Result<String, Error> {
    let (declared, mut position) = read_uleb128(dex, offset)?;
    let mut units: Vec<u16> = Vec::new();
    let byte = |position: &mut usize| -> Result<u8, Error> {
        let value = *dex.get(*position).ok_or(Error::OutOfBounds)?;
        *position += 1;
        Ok(value)
    };
    let continuation = |value: u8| -> Result<u16, Error> {
        if value & 0xc0 == 0x80 {
            Ok(u16::from(value & 0x3f))
        } else {
            Err(Error::InvalidString)
        }
    };
    loop {
        let first = byte(&mut position)?;
        let unit = match first {
            0 => break,
            0x01..=0x7f => u16::from(first),
            0xc0..=0xdf => (u16::from(first & 0x1f) << 6) | continuation(byte(&mut position)?)?,
            0xe0..=0xef => {
                let second = continuation(byte(&mut position)?)?;
                let third = continuation(byte(&mut position)?)?;
                (u16::from(first & 0x0f) << 12) | (second << 6) | third
            }
            _ => return Err(Error::InvalidString),
        };
        units.push(unit);
        if units.len() > index(declared)? {
            return Err(Error::InvalidString);
        }
    }
    if units.len() != index(declared)? {
        return Err(Error::InvalidString);
    }
    Ok(String::from_utf16_lossy(&units))
}

/// Reads an unsigned LEB128 value of at most five bytes that fits in 32 bits; returns it and the
/// offset after it.
fn read_uleb128(dex: &[u8], offset: usize) -> Result<(u32, usize), Error> {
    let mut value = 0_u32;
    for (shift, position) in (0..5).map(|n| (n * 7, offset.checked_add(n))) {
        let position = position.ok_or(Error::OutOfBounds)?;
        let byte = *dex.get(position).ok_or(Error::OutOfBounds)?;
        if shift == 28 && byte > 0x0f {
            return Err(Error::InvalidValue);
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, position + 1));
        }
    }
    Err(Error::InvalidValue)
}

/// `Lcom/example/Foo;` becomes `com.example.Foo`. A class definition always names a class type, so
/// anything else (a primitive, an array) makes the file invalid.
fn class_name(descriptor: &str) -> Result<String, Error> {
    descriptor
        .strip_prefix('L')
        .and_then(|rest| rest.strip_suffix(';'))
        .filter(|name| !name.is_empty())
        .map(|name| name.replace('/', "."))
        .ok_or(Error::InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::{Error, defined_classes};

    /// A real DEX file: the test fixture app of `scripts/verify-audit.sh`, compiled by d8.
    const FIXTURE: &[u8] = include_bytes!("../testdata/fixture.dex");

    fn u32_le(value: usize) -> [u8; 4] {
        u32::try_from(value).unwrap_or(u32::MAX).to_le_bytes()
    }

    fn put(buffer: &mut [u8], offset: usize, value: usize) {
        if let Some(slot) = buffer.get_mut(offset..offset + 4) {
            slot.copy_from_slice(&u32_le(value));
        }
    }

    fn uleb128(mut value: usize, out: &mut Vec<u8>) {
        loop {
            let low = u8::try_from(value & 0x7f).unwrap_or_default();
            value >>= 7;
            if value == 0 {
                out.push(low);
                return;
            }
            out.push(low | 0x80);
        }
    }

    /// Modified UTF-8, as d8 writes it.
    fn mutf8(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            let unit = u32::from(unit);
            let byte = |value: u32| u8::try_from(value).unwrap_or_default();
            match unit {
                0x01..=0x7f => out.push(byte(unit)),
                0x00 | 0x80..=0x7ff => {
                    out.extend([byte(0xc0 | (unit >> 6)), byte(0x80 | (unit & 0x3f))]);
                }
                _ => out.extend([
                    byte(0xe0 | (unit >> 12)),
                    byte(0x80 | ((unit >> 6) & 0x3f)),
                    byte(0x80 | (unit & 0x3f)),
                ]),
            }
        }
        out
    }

    /// One logical DEX file whose header starts at `base` of the final input; every descriptor is
    /// both a type and a class definition.
    fn logical(version: &str, base: usize, descriptors: &[&str]) -> Vec<u8> {
        let container = version == "041";
        let header_size = if container { 0x78 } else { 0x70 };
        let count = descriptors.len();
        let string_ids = base + header_size;
        let type_ids = string_ids + 4 * count;
        let class_defs = type_ids + 4 * count;
        let mut strings = Vec::new();
        let mut string_offsets = Vec::new();
        for descriptor in descriptors {
            string_offsets.push(class_defs + 32 * count + strings.len());
            uleb128(descriptor.encode_utf16().count(), &mut strings);
            strings.extend(mutf8(descriptor));
            strings.push(0);
        }

        let mut out = vec![0; header_size];
        out[..4].copy_from_slice(b"dex\n");
        out[4..7].copy_from_slice(version.as_bytes());
        put(&mut out, 0x24, header_size);
        put(&mut out, 0x28, 0x1234_5678);
        put(&mut out, 0x38, count);
        put(&mut out, 0x3c, string_ids);
        put(&mut out, 0x40, count);
        put(&mut out, 0x44, type_ids);
        put(&mut out, 0x60, count);
        put(&mut out, 0x64, class_defs);
        if container {
            put(&mut out, 0x74, base);
        }
        for offset in &string_offsets {
            out.extend(u32_le(*offset));
        }
        for number in 0..count {
            out.extend(u32_le(number));
        }
        for number in 0..count {
            let mut class_def = [0_u8; 32];
            class_def[..4].copy_from_slice(&u32_le(number));
            out.extend(class_def);
        }
        out.extend(strings);
        let size = out.len();
        put(&mut out, 0x20, size);
        out
    }

    fn dex(version: &str, descriptors: &[&str]) -> Vec<u8> {
        let mut file = logical(version, 0, descriptors);
        if version == "041" {
            let size = file.len();
            put(&mut file, 0x70, size);
        }
        file
    }

    const APP: &[&str] = &[
        "Lcom/example/App;",
        "Lcom/google/firebase/analytics/FirebaseAnalytics;",
    ];

    #[test]
    fn reads_the_classes_a_real_dex_file_defines() {
        assert_eq!(
            defined_classes(FIXTURE),
            Ok(vec![
                "org.visadahyu.datapavan.fixture.FixtureAccessibilityService".to_owned(),
                "org.visadahyu.datapavan.fixture.FixtureVpnService".to_owned(),
            ])
        );
    }

    #[test]
    fn reads_every_production_version() {
        for version in ["035", "037", "038", "039", "040"] {
            assert_eq!(
                defined_classes(&dex(version, APP)),
                Ok(vec![
                    "com.example.App".to_owned(),
                    "com.google.firebase.analytics.FirebaseAnalytics".to_owned()
                ]),
            );
        }
    }

    #[test]
    fn rejects_other_versions_and_other_files() {
        assert_eq!(
            defined_classes(&dex("034", APP)),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(
            defined_classes(&dex("036", APP)),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(
            defined_classes(&dex("042", APP)),
            Err(Error::UnsupportedVersion)
        );
        assert_eq!(
            defined_classes(b"PK\x03\x04 not a dex file"),
            Err(Error::NotDex)
        );
        assert_eq!(defined_classes(b""), Err(Error::NotDex));
    }

    #[test]
    fn rejects_byte_swapped_files_and_wrong_header_sizes() {
        let mut swapped = dex("039", APP);
        swapped[0x28..0x2c].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(defined_classes(&swapped), Err(Error::ReverseEndian));

        let mut header = dex("039", APP);
        header[0x24] = 0x78;
        assert_eq!(defined_classes(&header), Err(Error::InvalidValue));
    }

    #[test]
    fn decodes_modified_utf8() {
        // Two-byte, three-byte and surrogate-pair characters, and U+0000 written as two bytes.
        let names = [
            "Lcom/exämple/Ünï;",
            "Lcom/example/\u{20ac}\u{1f600};",
            "La\u{0}b;",
        ];
        assert_eq!(
            defined_classes(&dex("039", &names)),
            Ok(vec![
                "com.exämple.Ünï".to_owned(),
                "com.example.\u{20ac}\u{1f600}".to_owned(),
                "a\u{0}b".to_owned()
            ])
        );
    }

    #[test]
    fn rejects_a_string_that_does_not_match_its_length_or_encoding() {
        let file = dex("039", &["Lcom/A;"]);
        let data = file.len() - "Lcom/A;".len() - 2;

        let mut longer = file.clone();
        longer[data] = 3;
        assert_eq!(defined_classes(&longer), Err(Error::InvalidString));

        let mut bad_byte = file.clone();
        bad_byte[data + 2] = 0xff;
        assert_eq!(defined_classes(&bad_byte), Err(Error::InvalidString));

        // Without its terminator the string runs on past its declared length.
        let mut unterminated = file;
        let last = unterminated.len() - 1;
        unterminated[last] = b'x';
        assert_eq!(defined_classes(&unterminated), Err(Error::InvalidString));
    }

    #[test]
    fn rejects_indices_and_offsets_outside_their_tables() {
        let file = dex("039", APP);
        let class_defs = 0x70 + 8 + 8;

        let mut class_idx = file.clone();
        class_idx[class_defs] = 7;
        assert_eq!(defined_classes(&class_idx), Err(Error::InvalidValue));

        let mut descriptor_idx = file.clone();
        descriptor_idx[0x70 + 8] = 9;
        assert_eq!(defined_classes(&descriptor_idx), Err(Error::InvalidValue));

        let mut string_data = file.clone();
        string_data[0x70..0x74].copy_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
        assert_eq!(defined_classes(&string_data), Err(Error::OutOfBounds));

        let mut count = file;
        count[0x60..0x64].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(defined_classes(&count), Err(Error::OutOfBounds));
    }

    #[test]
    fn rejects_class_definitions_of_non_class_types() {
        for descriptor in ["I", "[Lcom/A;", "L;", "Lcom/A"] {
            assert_eq!(
                defined_classes(&dex("039", &[descriptor])),
                Err(Error::InvalidValue),
                "{descriptor}"
            );
        }
    }

    #[test]
    fn rejects_every_truncation_without_panicking() {
        for file in [FIXTURE.to_vec(), dex("041", APP)] {
            for length in 0..file.len() {
                assert!(defined_classes(&file[..length]).is_err(), "length {length}");
            }
        }
    }

    #[test]
    fn reads_every_logical_file_of_a_container() {
        let mut container = logical("041", 0, &["Lcom/a/First;"]);
        let second = logical("041", container.len(), &["Lcom/b/Second;", "Lcom/b/Third;"]);
        container.extend(second);
        let size = container.len();
        let second_start = size - logical("041", 0, &["Lcom/b/Second;", "Lcom/b/Third;"]).len();
        put(&mut container, 0x70, size);
        put(&mut container, second_start + 0x70, size);
        assert_eq!(
            defined_classes(&container),
            Ok(vec![
                "com.a.First".to_owned(),
                "com.b.Second".to_owned(),
                "com.b.Third".to_owned()
            ])
        );

        let mut wrong_offset = container;
        put(&mut wrong_offset, second_start + 0x74, 0);
        assert_eq!(defined_classes(&wrong_offset), Err(Error::InvalidValue));
    }

    #[test]
    fn rejects_trailing_bytes_after_a_single_file() {
        let mut file = dex("039", APP);
        file.push(0);
        assert_eq!(defined_classes(&file), Err(Error::InvalidValue));
    }
}
