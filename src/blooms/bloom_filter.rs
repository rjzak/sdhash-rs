use anyhow::bail;
use lz4_compression::decompress;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::str::FromStr;

/// Bit masks for positions 0-7 within a byte.
const BITS: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

/// Minimum score cutoffs for LARGE (16 KB) Bloom filter comparisons,
/// indexed by mn = floor(2 * m / (x + y)) where x, y are element counts.
pub const CUTOFFS: [u32; 129] = [
    86511, 86511, 86511, 86511, 67010, 52623, 42139, 34377, 28532, 24026, 20499, 17687, 15407,
    13535, 11982, 10685, 9589, 8652, 7846, 7149, 6541, 6008, 5537, 5121, 4745, 4413, 4115, 3850,
    3606, 3388, 3185, 3001, 2834, 2681, 2538, 2407, 2287, 2176, 2072, 1977, 1888, 1802, 1724, 1651,
    1583, 1519, 1458, 1402, 1348, 1298, 1248, 1204, 1161, 1120, 1083, 1047, 1013, 981, 949, 921,
    892, 866, 839, 815, 791, 768, 747, 726, 706, 688, 669, 652, 635, 619, 603, 589, 575, 561, 546,
    533, 521, 510, 498, 487, 476, 467, 456, 447, 438, 429, 420, 411, 403, 395, 387, 380, 373, 365,
    358, 351, 345, 338, 332, 326, 320, 314, 309, 303, 298, 293, 288, 284, 279, 275, 271, 266, 262,
    258, 254, 250, 246, 242, 238, 235, 231, 228, 225, 221, 218,
];

#[derive(Clone, Debug)]
pub struct BloomFilter {
    /// Bloom filter bit array
    pub bf: Vec<u8>,
    /// Hamming weight (number of set bits), as u16
    pub hamming: u16,
    /// Hamming weight (number of set bits), as u32
    pub hamminglg: u32,
    /// BF size in bytes
    pub bf_size: usize,
    /// Bit-address mask: (bf_size * 8) - 1
    pub bit_mask: u64,
    /// Maximum number of elements
    pub max_elem: u64,
    /// Number of hash functions (k)
    pub hash_count: u16,

    bf_elem_count: u64,
    comp_size: usize,
    setname: String,
    bl_id: i32,
}

impl BloomFilter {
    pub fn new(mut size: usize, hash_count: u16, max_elem: u64, _max_fp: f64) -> Self {
        if size < 64 {
            size = 64;
        } else if !size.is_power_of_two() {
            size = size.checked_next_power_of_two().unwrap();
        }

        let bit_mask = (size * 8 - 1) as u64;
        Self {
            bf: vec![0; size],
            hamming: 0,
            hamminglg: 0,
            bf_size: size,
            bit_mask,
            max_elem,
            hash_count,
            bf_elem_count: 0,
            comp_size: 0,
            setname: String::new(),
            bl_id: 0,
        }
    }

    pub fn from_bloom_buffer(
        data: Vec<u8>,
        size: usize,
        id: i32,
        bf_elem_count: u64,
        hamming: u16,
    ) -> Self {
        let bit_mask = (size * 8 - 1) as u64;
        Self {
            bf: data,
            hamming,
            hamminglg: hamming as u32,
            bf_size: size,
            bit_mask,
            max_elem: 0,
            hash_count: 5,
            bf_elem_count,
            comp_size: 0,
            setname: String::new(),
            bl_id: id,
        }
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Ok(BloomFilter::from_str(&contents)?)
    }

    pub fn elem_count(&self) -> u64 {
        self.bf_elem_count
    }

    pub fn name(&self) -> &str {
        &self.setname
    }

    pub fn set_name(&mut self, name: String) {
        self.setname = name;
    }

    pub fn id(&self) -> i32 {
        self.bl_id
    }

    pub fn set_id(&mut self, id: i32) {
        self.bl_id = id;
    }

    pub fn compress(&self) -> Vec<u8> {
        lz4_compression::compress::compress(&self.bf)
    }

    pub fn compress_update_comp_size(&mut self) -> Vec<u8> {
        let compressed = self.compress();
        self.comp_size = compressed.len();
        compressed
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.to_string())
    }

    /// Fold the BF in half `times` times by OR-ing the two halves together.
    pub fn fold(&mut self, times: u32) {
        let mut rsize = self.bf_size; // bytes

        for _ in 0..times {
            let half = rsize / 2;
            let (first, second) = self.bf[..rsize].split_at_mut(half);
            for (lo, hi) in first.chunks_exact_mut(8).zip(second.chunks_exact(8)) {
                let a = u64::from_le_bytes(lo.try_into().unwrap());
                let b = u64::from_le_bytes(hi.try_into().unwrap());
                lo.copy_from_slice(&(a | b).to_le_bytes());
            }
            rsize = half;
            if rsize == 256 {
                break;
            }
        }

        self.bf_size = rsize;
        self.bit_mask = (rsize * 8 - 1) as u64;
        self.compute_hamming();
    }

    /// OR another same-size Bloom filter into this one.
    pub fn add(&mut self, other: &BloomFilter) -> anyhow::Result<()> {
        if self.bf_size != other.bf_size {
            bail!(
                "bloom filters of differing sizes {} vs {}",
                self.bf_size,
                other.bf_size
            );
        }
        for (lo, hi) in self.bf.chunks_exact_mut(8).zip(other.bf.chunks_exact(8)) {
            let a = u64::from_le_bytes(lo.try_into().unwrap());
            let b = u64::from_le_bytes(hi.try_into().unwrap());
            lo.copy_from_slice(&(a | b).to_le_bytes());
        }
        self.compute_hamming();
        Ok(())
    }

    /// Estimate the similarity of two same-size Bloom filters (0-100).
    pub fn compare(&self, other: &BloomFilter, _scale: f64) -> i32 {
        if self.bf_size != other.bf_size {
            return -1;
        }

        let result: u32 = self
            .bf
            .chunks_exact(8)
            .zip(other.bf.chunks_exact(8))
            .map(|(a, b)| {
                let wa = u64::from_le_bytes(a.try_into().unwrap());
                let wb = u64::from_le_bytes(b.try_into().unwrap());
                (wa & wb).count_ones()
            })
            .sum();

        let x = self.bf_elem_count;
        let y = other.bf_elem_count;

        if x < 32 || y < 32 {
            return 0;
        }

        let max_est = self.hamminglg.min(other.hamminglg);
        let m = (self.bf_size * 8) as f64;
        let mn = ((2.0 * m) / (x as f64 + y as f64)).round() as usize;
        let cut_off = if mn < CUTOFFS.len() {
            CUTOFFS[mn] as i32
        } else {
            (CUTOFFS[128] as i32).saturating_sub(mn as i32 - 128)
        };

        if cut_off < 0 || result as i32 <= cut_off {
            return 0;
        }

        (100.0 * (result as f64 - cut_off as f64) / (max_est as f64 - cut_off as f64)) as i32
    }

    /// Check whether `data[..hash_count]` is represented in the Bloom filter.
    pub fn query(&self, data: &[u32]) -> bool {
        let mut set_count = 0u16;
        for &d in data.iter().take(self.hash_count as usize) {
            let pos = (d as u64 & self.bit_mask) as usize;
            if self.bf[pos >> 3] & BITS[pos & 7] != 0 {
                set_count += 1;
            } else {
                return false;
            }
        }
        set_count == self.hash_count
    }

    /// Insert `data[..hash_count]` into the filter; returns true if newly inserted.
    pub fn query_and_set(&mut self, data: &[u32]) -> bool {
        let mut already_set = 0u16;
        for &d in data.iter().take(self.hash_count as usize) {
            let pos = (d as u64 & self.bit_mask) as usize;
            if self.bf[pos >> 3] & BITS[pos & 7] != 0 {
                already_set += 1;
            } else {
                self.bf[pos >> 3] |= BITS[pos & 7];
            }
        }
        self.compute_hamming();
        if already_set < self.hash_count {
            self.bf_elem_count += 1;
            return true;
        }
        false
    }

    pub fn insert_sha1(&mut self, sha1: &[u32]) -> bool {
        self.query_and_set(sha1)
    }

    pub fn query_sha1(&self, sha1: &[u32]) -> bool {
        self.query(sha1)
    }

    pub fn compute_hamming(&mut self) {
        self.hamminglg = self.bf.iter().map(|b| b.count_ones()).sum();
        self.hamming = self.hamminglg as u16;
    }

    fn decompress(&mut self, data: &[u8]) -> anyhow::Result<()> {
        match decompress::decompress(data) {
            Ok(data) => {
                self.bf = data;
                self.compute_hamming();
                Ok(())
            }
            Err(decompress::Error::UnexpectedEnd) => bail!("unexpected end"),
            Err(decompress::Error::InvalidDeduplicationOffset) => {
                bail!("invalid deduplication offset")
            }
        }
    }
}

impl Display for BloomFilter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sdbf-idx:{}:{}:{}:{:02x}:{}:{}\n{}\n",
            self.bf_size,
            self.bf_elem_count,
            self.hash_count,
            self.bit_mask,
            self.comp_size,
            self.setname,
            hex::encode(self.compress())
        )
    }
}

impl AsRef<[u8]> for BloomFilter {
    fn as_ref(&self) -> &[u8] {
        &self.bf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloomFilterError(String);

impl Display for BloomFilterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to generate Bloom Filter from string: {}", self.0)
    }
}

impl std::error::Error for BloomFilterError {}

impl FromStr for BloomFilter {
    type Err = BloomFilterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut lines = s.split('\n');

        let header = lines
            .next()
            .ok_or_else(|| BloomFilterError("premature end of string".into()))?;

        let mut parts = header.split(':');
        parts.next(); // skip "sdbf-idx"

        macro_rules! next_field {
            ($ty:ty) => {
                parts
                    .next()
                    .ok_or_else(|| BloomFilterError("premature end of string".into()))
                    .and_then(|s| {
                        s.parse::<$ty>()
                            .map_err(|e| BloomFilterError(e.to_string()))
                    })?
            };
        }

        let bf_size = next_field!(usize);
        let bf_elem_count = next_field!(u64);
        let hash_count = next_field!(u16);
        let bit_mask = parts
            .next()
            .ok_or_else(|| BloomFilterError("premature end of string".into()))
            .and_then(|s| {
                u64::from_str_radix(s, 16).map_err(|e| BloomFilterError(e.to_string()))
            })?;
        let comp_size = next_field!(usize);
        let setname = parts
            .next()
            .ok_or_else(|| BloomFilterError("premature end of string".into()))?
            .to_string();

        let hex_data = lines
            .next()
            .ok_or_else(|| BloomFilterError("premature end of string".into()))?;
        let compressed =
            hex::decode(hex_data).map_err(|e| BloomFilterError(e.to_string()))?;

        let mut bloom = Self {
            bf: vec![],
            hamming: 0,
            hamminglg: 0,
            bf_size,
            bit_mask,
            max_elem: 0,
            hash_count,
            bf_elem_count,
            comp_size,
            setname,
            bl_id: 0,
        };

        bloom
            .decompress(&compressed)
            .map_err(|_| BloomFilterError("failed to decompress".into()))?;

        if bf_size != bloom.bf.len() {
            return Err(BloomFilterError(format!(
                "size mismatch: expected {bf_size}, got {}",
                bloom.bf.len()
            )));
        }
        Ok(bloom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use rstest::rstest;

    const DATA1: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    const DATA2: [u32; 10] = [99, 99, 99, 99, 99, 99, 99, 99, 99, 99];

    #[rstest]
    #[case(10, 5)]
    #[case(10, 10)]
    #[case(128, 5)]
    #[case(256, 10)]
    fn create_store_query(#[case] size: usize, #[case] hash_count: u16) {
        let mut bf = BloomFilter::new(size, hash_count, 1000, 10.0);
        assert!(!bf.query(&DATA1), "data not present yet found");

        bf.query_and_set(&DATA1);
        assert!(bf.query(&DATA1), "data not found yet was inserted");
        assert!(!bf.query(&DATA2), "data not present yet found");
    }

    #[test]
    fn compression() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        assert!(!bf.query(&DATA1));
        assert!(!bf.query(&DATA2));

        let compressed = bf.compress();
        bf.decompress(&compressed)
            .context("failed to restore after compression")
            .unwrap();

        assert!(!bf.query(&DATA1));
        assert!(!bf.query(&DATA2));

        bf.query_and_set(&DATA1);
        assert!(bf.query(&DATA1), "data not found yet was inserted");

        let compressed = bf.compress_update_comp_size();
        bf.decompress(&compressed)
            .context("failed to restore after compression")
            .unwrap();

        assert!(bf.query(&DATA1), "data not found after compression");
        assert!(!bf.query(&DATA2));
    }

    #[test]
    fn from_existing_data() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        bf.query_and_set(&DATA1);
        assert!(bf.query(&DATA1));
        assert!(!bf.query(&DATA2));

        let bf2 =
            BloomFilter::from_bloom_buffer(bf.bf.clone(), 10, 0, bf.bf_elem_count, bf.hamming);
        assert!(bf2.query(&DATA1));
        assert!(!bf2.query(&DATA2));
    }

    #[test]
    fn addition() {
        let mut bf1 = BloomFilter::new(10, 5, 1000, 10.0);
        bf1.query_and_set(&DATA1);

        let mut bf2 = BloomFilter::new(10, 5, 1000, 10.0);
        bf2.query_and_set(&DATA2);

        bf1.add(&bf2).unwrap();
        assert!(bf1.query(&DATA2), "data added from other BF should be found");
    }

    #[test]
    fn serialization() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        bf.query_and_set(&DATA1);
        assert!(bf.query(&DATA1));

        let s = bf.to_string();
        let bf2 = BloomFilter::from_str(&s).unwrap();

        assert_eq!(bf.bf, bf2.bf, "vectors not equal after roundtrip");
        assert!(bf2.query(&DATA1), "data not found after roundtrip");
        assert!(!bf2.query(&DATA2));
    }

    #[test]
    fn folding() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        bf.query_and_set(&DATA1);
        bf.fold(2);
        assert!(bf.query(&DATA1), "data not found after fold");
    }

    #[test]
    fn compare() {
        let mut bf1 = BloomFilter::new(64, 5, 1000, 10.0);
        bf1.query_and_set(&DATA1);
        bf1.bf_elem_count = 50; // set high enough for compare() to run

        let mut bf2 = BloomFilter::new(64, 5, 1000, 10.0);
        bf2.query_and_set(&DATA2);
        bf2.bf_elem_count = 50;

        let result = bf2.compare(&bf2, 1.0);
        assert!(result >= 0);
    }
}
