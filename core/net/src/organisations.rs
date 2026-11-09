//! Watch's offline table from IP address to network and organisation (ADR 0036), built by
//! `data/dbip-asn/update.py` from DB-IP's IP to ASN Lite: the last way a flow gets a name, when no DNS
//! answer, TLS server name or QUIC server name gave one (W3).
//!
//! The table is about 2.7 MB of blocks compressed one by one, read where it lies, not loaded into
//! memory: a lookup reads a few index rows by binary search and inflates one block of a few
//! kilobytes, and runs only for flows nothing else named. Its layout is in update.py. The table comes
//! in the APK or a data pack, but it is still read as untrusted: every count, index, offset and block
//! is checked (`fuzz_targets/organisations.rs`).

use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::FileExt;

const MAGIC: &[u8; 8] = b"DPASN\0\0\x02";
const HEADER: u64 = 64;
const V4_ROW: u64 = 12;
const V6_ROW: u64 = 24;
const AS_ROW: u64 = 8;
/// The AS index of an entry that no range covers.
const GAP: u32 = 0x00FF_FFFF;
const ASES_PER_BLOCK: u32 = 256;
/// The most bytes a block may inflate to; the converter's blocks stay far below.
const MAX_INFLATED: usize = 64 * 1024;
/// The most bytes a block may take compressed.
const MAX_BLOCK: u32 = 64 * 1024;
/// The longest name kept.
const MAX_NAME: usize = 512;

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
    v4_index: u64,
    v4_blocks: u64,
    v6_index: u64,
    v6_blocks: u64,
    as_index: u64,
    as_blocks: u64,
    as_count: u32,
    data: u64,
    data_length: u64,
}

fn u32_le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Reads a varint (7 bits a byte, low first) at `*at`, moving past it.
fn varint(bytes: &[u8], at: &mut usize) -> Option<u128> {
    let mut value = 0u128;
    for shift in (0..133).step_by(7) {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u128::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

impl Organisations {
    /// Opens a table, checking its header and that its parts fit its size.
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
        let count = |at| u64::from(u32_le(&header, at));
        let (v4_blocks, v6_blocks, as_blocks) = (count(48), count(52), count(56));
        let as_count = u32_le(&header, 60);
        let v4_index = HEADER;
        let v6_index = v4_index + v4_blocks * V4_ROW;
        let as_index = v6_index + v6_blocks * V6_ROW;
        let data = as_index + as_blocks * AS_ROW;
        let data_length = source.size()?.checked_sub(data).ok_or_else(invalid)?;
        if as_blocks != u64::from(as_count.div_ceil(ASES_PER_BLOCK)) {
            return Err(invalid());
        }
        Ok(Self {
            source,
            month,
            v4_index,
            v4_blocks,
            v6_index,
            v6_blocks,
            as_index,
            as_blocks,
            as_count,
            data,
            data_length,
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
            IpAddr::V4(a) => self.find(
                self.v4_index,
                self.v4_blocks,
                false,
                u128::from(u32::from(a)),
            )?,
            IpAddr::V6(a) => self.find(self.v6_index, self.v6_blocks, true, u128::from(a))?,
        };
        self.organisation(index)
    }

    /// Reads and inflates the block at `offset` of the data, `length` bytes long.
    fn block(&self, offset: u32, length: u32) -> Option<Vec<u8>> {
        if length > MAX_BLOCK || u64::from(offset) + u64::from(length) > self.data_length {
            return None;
        }
        let mut packed = vec![0u8; usize::try_from(length).ok()?];
        self.source
            .read_exact_at(&mut packed, self.data + u64::from(offset))
            .ok()?;
        miniz_oxide::inflate::decompress_to_vec_with_limit(&packed, MAX_INFLATED).ok()
    }

    /// The AS index of the range holding `address`: the block whose first address is the last at or
    /// before it, then the last entry of that block at or before it.
    fn find(&self, index: u64, blocks: u64, wide: bool, address: u128) -> Option<u32> {
        let row_size = if wide { V6_ROW } else { V4_ROW };
        let row = |i: u64| -> Option<(u128, u32, u32)> {
            let mut bytes = [0u8; 24];
            let bytes = &mut bytes[..usize::try_from(row_size).ok()?];
            self.source
                .read_exact_at(bytes, index + i * row_size)
                .ok()?;
            let width = if wide { 16 } else { 4 };
            let mut first = [0u8; 16];
            first[..width].copy_from_slice(&bytes[..width]);
            Some((
                u128::from_le_bytes(first),
                u32_le(bytes, width),
                u32_le(bytes, width + 4),
            ))
        };
        let (mut low, mut high) = (0u64, blocks);
        while low < high {
            let middle = low + (high - low) / 2;
            if row(middle)?.0 <= address {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let (first, offset, length) = row(low.checked_sub(1)?)?;
        let block = self.block(offset, length)?;
        let (mut at, mut start, mut found) = (0, first, None);
        while at < block.len() {
            start = start.checked_add(varint(&block, &mut at)?)?;
            let as_index = u32::try_from(varint(&block, &mut at)?).ok()?;
            if start > address {
                break;
            }
            found = Some(as_index);
        }
        found.filter(|&i| i != GAP)
    }

    /// The AS number and name at `index` of the AS blocks.
    fn organisation(&self, index: u32) -> Option<Organisation> {
        if index >= self.as_count {
            return None;
        }
        let block_number = u64::from(index / ASES_PER_BLOCK);
        if block_number >= self.as_blocks {
            return None;
        }
        let mut row = [0u8; 8];
        self.source
            .read_exact_at(&mut row, self.as_index + block_number * AS_ROW)
            .ok()?;
        let block = self.block(u32_le(&row, 0), u32_le(&row, 4))?;
        let (mut at, mut asn) = (0usize, 0u128);
        for position in 0..=index % ASES_PER_BLOCK {
            asn = asn.checked_add(varint(&block, &mut at)?)?;
            let length = usize::try_from(varint(&block, &mut at)?).ok()?;
            let name = block.get(at..at.checked_add(length)?)?;
            at += length;
            if position == index % ASES_PER_BLOCK {
                if length > MAX_NAME {
                    return None;
                }
                let name = String::from_utf8(name.to_vec()).ok()?;
                if name.chars().any(char::is_control) {
                    return None;
                }
                return Some(Organisation {
                    asn: u32::try_from(asn).ok()?,
                    name,
                });
            }
        }
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn varint_bytes(mut n: u128) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let low = u8::try_from(n & 0x7f).unwrap_or(0);
            n >>= 7;
            out.push(low | if n == 0 { 0 } else { 0x80 });
            if n == 0 {
                return out;
            }
        }
    }

    fn deflated(raw: &[u8]) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(raw, 9)
    }

    /// A table as update.py writes it: two IPv4 ranges with a gap between, one IPv6 range, two networks.
    pub(crate) fn sample() -> Vec<u8> {
        let mut data = Vec::new();
        let block = |entries: &[(u128, u32)], first: u128, data: &mut Vec<u8>| -> (u32, u32) {
            let mut raw = Vec::new();
            let mut previous = first;
            for &(start, index) in entries {
                raw.extend(varint_bytes(start - previous));
                raw.extend(varint_bytes(u128::from(index)));
                previous = start;
            }
            let packed = deflated(&raw);
            let offset = u32::try_from(data.len()).unwrap_or(0);
            data.extend_from_slice(&packed);
            (offset, u32::try_from(packed.len()).unwrap_or(0))
        };
        let ip4 = |a: [u8; 4]| u128::from(u32::from(Ipv4Addr::from(a)));
        let v4 = [
            (ip4([93, 184, 216, 0]), 0),
            (ip4([93, 184, 217, 0]), GAP),
            (ip4([157, 240, 0, 0]), 1),
            (ip4([157, 241, 0, 0]), GAP),
        ];
        let (v4_offset, v4_length) = block(&v4, v4[0].0, &mut data);
        let v6_first = u128::from(Ipv6Addr::new(0x2a03, 0x2880, 0, 0, 0, 0, 0, 0));
        let v6 = [
            (v6_first, 1),
            (
                u128::from(Ipv6Addr::new(0x2a03, 0x2881, 0, 0, 0, 0, 0, 0)),
                GAP,
            ),
        ];
        let (v6_offset, v6_length) = block(&v6, v6_first, &mut data);
        let mut as_raw = Vec::new();
        for (asn, previous, name) in [
            (15133u128, 0u128, &b"Example Net, Inc."[..]),
            (32934, 15133, b"Meta Platforms, Inc."),
        ] {
            as_raw.extend(varint_bytes(asn - previous));
            as_raw.extend(varint_bytes(name.len() as u128));
            as_raw.extend_from_slice(name);
        }
        let packed = deflated(&as_raw);
        let (as_offset, as_length) = (
            u32::try_from(data.len()).unwrap_or(0),
            u32::try_from(packed.len()).unwrap_or(0),
        );
        data.extend_from_slice(&packed);

        let mut t = MAGIC.to_vec();
        t.extend_from_slice(b"2026-11\0");
        t.extend_from_slice(&[0; 32]);
        for n in [1u32, 1, 1, 2] {
            t.extend_from_slice(&n.to_le_bytes());
        }
        t.extend_from_slice(&u32::try_from(v4[0].0).unwrap_or(0).to_le_bytes());
        t.extend_from_slice(&v4_offset.to_le_bytes());
        t.extend_from_slice(&v4_length.to_le_bytes());
        t.extend_from_slice(&v6_first.to_le_bytes());
        t.extend_from_slice(&v6_offset.to_le_bytes());
        t.extend_from_slice(&v6_length.to_le_bytes());
        t.extend_from_slice(&as_offset.to_le_bytes());
        t.extend_from_slice(&as_length.to_le_bytes());
        t.extend_from_slice(&data);
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
    fn refuses_a_damaged_table_without_failing() {
        let mut wrong = sample();
        wrong[0] = b'X';
        assert!(Organisations::open(Box::new(wrong)).is_err());
        assert!(Organisations::open(Box::new(Vec::new())).is_err());
        // A cut block: the table opens, but the networks in that block are not found.
        let mut short = sample();
        short.pop();
        let table = Organisations::open(Box::new(short)).unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            table.lookup(IpAddr::V4(Ipv4Addr::new(157, 240, 1, 35))),
            None
        );
    }
}
