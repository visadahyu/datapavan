//! Watch's offline table from IP address to network and organisation (ADR 0036), built by
//! `data/dbip-asn/update.py` from DB-IP's IP to ASN Lite: the last way a flow gets a name, when no DNS
//! answer, TLS server name or QUIC server name gave one (W3).
//!
//! The table is about 10 MB, so it is read where it lies, a few bytes per step of a binary search,
//! not loaded into memory: a lookup costs about twenty small reads and runs only for flows nothing
//! else named. Its layout is in update.py. The table comes in the APK or a data pack, but it is still
//! read as untrusted: every count, index and offset is checked (`fuzz_targets/organisations.rs`).

use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::FileExt;

const MAGIC: &[u8; 8] = b"DPASN\0\0\x01";
const HEADER: u64 = 8 + 8 + 32 + 16;
const V4_ROW: u64 = 12;
const V6_ROW: u64 = 36;
const AS_ROW: u64 = 12;
/// The longest name the converter writes.
const MAX_NAME: u32 = 512;

/// Where the table's bytes are: a file, or memory in tests and fuzzing.
pub trait Source: Send + Sync {
    /// Fills `buffer` from `offset`, or fails.
    ///
    /// # Errors
    /// When the bytes are not there.
    fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()>;

    /// How many bytes there are.
    ///
    /// # Errors
    /// When the size cannot be read.
    fn size(&self) -> io::Result<u64>;
}

/// A file, or a part of one: an asset inside the APK starts at an offset.
pub struct FilePart {
    file: File,
    start: u64,
    length: u64,
}

impl FilePart {
    /// The `length` bytes of `file` from `start`.
    #[must_use]
    pub fn new(file: File, start: u64, length: u64) -> Self {
        Self {
            file,
            start,
            length,
        }
    }
}

impl Source for FilePart {
    fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if end > self.length {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        FileExt::read_exact_at(&self.file, buffer, self.start + offset)
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.length)
    }
}

impl Source for Vec<u8> {
    fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::InvalidInput)?;
        let bytes = self
            .get(
                start
                    ..start
                        .checked_add(buffer.len())
                        .ok_or(io::ErrorKind::InvalidInput)?,
            )
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buffer.copy_from_slice(bytes);
        Ok(())
    }

    fn size(&self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
}

/// The network an address belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organisation {
    /// Its AS number.
    pub asn: u32,
    /// The organisation's name, as the registry has it.
    pub name: String,
}

/// An open table.
pub struct Organisations {
    source: Box<dyn Source>,
    month: String,
    v4: u64,
    v4_count: u64,
    v6: u64,
    v6_count: u64,
    ases: u64,
    as_count: u32,
    names: u64,
    names_length: u32,
}

fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

impl Organisations {
    /// Opens a table, checking its header and that its parts add up to its size.
    ///
    /// # Errors
    /// When the bytes cannot be read or are not such a table.
    pub fn open(source: Box<dyn Source>) -> io::Result<Self> {
        let invalid = || {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "not an IP-to-organisation table",
            )
        };
        let mut header = [0u8; 64];
        source.read_exact_at(&mut header, 0)?;
        if &header[..8] != MAGIC || header[15] != 0 {
            return Err(invalid());
        }
        let month = std::str::from_utf8(&header[8..15])
            .map_err(|_| invalid())?
            .to_owned();
        let (v4_count, v6_count) = (
            u64::from(u32_le(&header, 48)),
            u64::from(u32_le(&header, 52)),
        );
        let (as_count, names_length) = (u32_le(&header, 56), u32_le(&header, 60));
        let v4 = HEADER;
        let v6 = v4 + v4_count * V4_ROW;
        let ases = v6 + v6_count * V6_ROW;
        let names = ases + u64::from(as_count) * AS_ROW;
        if names + u64::from(names_length) != source.size()? {
            return Err(invalid());
        }
        Ok(Self {
            source,
            month,
            v4,
            v4_count,
            v6,
            v6_count,
            ases,
            as_count,
            names,
            names_length,
        })
    }

    /// The release month of the data, as `2026-11`.
    #[must_use]
    pub fn month(&self) -> &str {
        &self.month
    }

    /// The network `address` belongs to, if the table has one.
    #[must_use]
    pub fn lookup(&self, address: IpAddr) -> Option<Organisation> {
        let index = match address {
            IpAddr::V4(a) => self.find(self.v4, self.v4_count, V4_ROW, u128::from(u32::from(a)))?,
            IpAddr::V6(a) => self.find(self.v6, self.v6_count, V6_ROW, u128::from(a))?,
        };
        if index >= self.as_count {
            return None;
        }
        let mut row = [0u8; 12];
        self.source
            .read_exact_at(&mut row, self.ases + u64::from(index) * AS_ROW)
            .ok()?;
        let (asn, offset, length) = (u32_le(&row, 0), u32_le(&row, 4), u32_le(&row, 8));
        if length > MAX_NAME || offset.checked_add(length)? > self.names_length {
            return None;
        }
        let mut name = vec![0u8; usize::try_from(length).ok()?];
        self.source
            .read_exact_at(&mut name, self.names + u64::from(offset))
            .ok()?;
        let name = String::from_utf8(name).ok()?;
        if name.chars().any(char::is_control) {
            return None;
        }
        Some(Organisation { asn, name })
    }

    /// Binary search for the last range starting at or before `address`; its AS index, if the range
    /// holds the address.
    fn find(&self, base: u64, count: u64, row: u64, address: u128) -> Option<u32> {
        let wide = row == V6_ROW;
        let read = |i: u64| -> Option<(u128, u128, u32)> {
            let mut bytes = [0u8; 36];
            let bytes = &mut bytes[..usize::try_from(row).ok()?];
            self.source.read_exact_at(bytes, base + i * row).ok()?;
            Some(if wide {
                let start = u128::from_le_bytes(bytes[..16].try_into().ok()?);
                let end = u128::from_le_bytes(bytes[16..32].try_into().ok()?);
                (start, end, u32_le(bytes, 32))
            } else {
                (
                    u128::from(u32_le(bytes, 0)),
                    u128::from(u32_le(bytes, 4)),
                    u32_le(bytes, 8),
                )
            })
        };
        let (mut low, mut high) = (0u64, count);
        while low < high {
            let middle = low + (high - low) / 2;
            if read(middle)?.0 <= address {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let (start, end, index) = read(low.checked_sub(1)?)?;
        (start <= address && address <= end).then_some(index)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// A table as update.py writes it: two IPv4 ranges, one IPv6 range, two networks.
    pub(crate) fn sample() -> Vec<u8> {
        let mut t = MAGIC.to_vec();
        t.extend_from_slice(b"2026-11\0");
        t.extend_from_slice(&[0; 32]);
        let names = b"Example Net, Inc.Meta Platforms, Inc.";
        for n in [2u32, 1, 2, u32::try_from(names.len()).unwrap_or(0)] {
            t.extend_from_slice(&n.to_le_bytes());
        }
        for (start, end, index) in [
            ([93, 184, 216, 0], [93, 184, 216, 255], 0u32),
            ([157, 240, 0, 0], [157, 240, 255, 255], 1),
        ] {
            t.extend_from_slice(&u32::from(Ipv4Addr::from(start)).to_le_bytes());
            t.extend_from_slice(&u32::from(Ipv4Addr::from(end)).to_le_bytes());
            t.extend_from_slice(&index.to_le_bytes());
        }
        t.extend_from_slice(
            &u128::from(Ipv6Addr::new(0x2a03, 0x2880, 0, 0, 0, 0, 0, 0)).to_le_bytes(),
        );
        t.extend_from_slice(
            &u128::from(Ipv6Addr::new(
                0x2a03, 0x2880, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ))
            .to_le_bytes(),
        );
        t.extend_from_slice(&1u32.to_le_bytes());
        for (asn, offset, length) in [(15133u32, 0u32, 17u32), (32934, 17, 20)] {
            for n in [asn, offset, length] {
                t.extend_from_slice(&n.to_le_bytes());
            }
        }
        t.extend_from_slice(names);
        t
    }

    #[test]
    fn finds_the_network_of_an_address_or_none() {
        let table = Organisations::open(Box::new(sample())).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(table.month(), "2026-11");
        let meta = Some(Organisation {
            asn: 32934,
            name: "Meta Platforms, Inc.".into(),
        });
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(157, 240, 1, 35))),
            meta
        );
        assert_eq!(
            table.lookup(IpAddr::V6(Ipv6Addr::new(
                0x2a03, 0x2880, 0xf12f, 0x83, 0xface, 0xb00c, 0, 0x25de
            ))),
            meta
        );
        assert_eq!(
            table
                .lookup(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                .map(|o| o.asn),
            Some(15133)
        );
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(93, 184, 217, 1))),
            None
        );
        assert_eq!(table.lookup(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), None);
        assert_eq!(table.lookup(IpAddr::V6(Ipv6Addr::LOCALHOST)), None);
    }

    /// With `DATAPAVAN_ASN_TABLE` set to a table built by update.py: a few well-known addresses.
    #[test]
    fn reads_the_real_table_when_one_is_given() {
        let Ok(path) = std::env::var("DATAPAVAN_ASN_TABLE") else {
            return;
        };
        let file = File::open(&path).unwrap_or_else(|e| unreachable!("{path}: {e}"));
        let length = file.metadata().map_or(0, |m| m.len());
        let table = Organisations::open(Box::new(FilePart::new(file, 0, length)))
            .unwrap_or_else(|e| unreachable!("{e}"));
        for (address, asn) in [
            ("157.240.1.35", 32934),
            ("8.8.8.8", 15169),
            ("1.1.1.1", 13335),
            ("2a03:2880:f12f:83:face:b00c:0:25de", 32934),
        ] {
            let found = table.lookup(address.parse().unwrap_or_else(|e| unreachable!("{e}")));
            println!("{address}: {found:?}");
            assert_eq!(found.map(|o| o.asn), Some(asn), "{address}");
        }
    }

    #[test]
    fn refuses_a_table_whose_parts_do_not_add_up() {
        let mut short = sample();
        short.pop();
        assert!(Organisations::open(Box::new(short)).is_err());
        let mut wrong = sample();
        wrong[0] = b'X';
        assert!(Organisations::open(Box::new(wrong)).is_err());
        assert!(Organisations::open(Box::new(Vec::new())).is_err());
    }
}
