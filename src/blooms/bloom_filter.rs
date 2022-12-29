#![allow(unused)]

use anyhow::bail;
use lz4_compression::decompress;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::mem::transmute;
use std::path::Path;
use std::str::FromStr;

pub const BITS: [u32; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

pub const BIT_MASKS_32: [u32; 32] = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF, 0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF,
    0x7FFF, 0xFFFF, 0x01FFFF, 0x03FFFF, 0x07FFFF, 0x0FFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF,
    0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF,
];

/// cutoffs for LARGE filters 16kb
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
    /// Contents of the Bloom Filter
    pub bf: Vec<u8>,
    /// weight of this Bloom Filter
    pub hamming: u16,
    /// weight of this Bloom Filter
    pub hamminglg: u32,
    /// BF size in bytes (==m/8)
    pub bf_size: usize,
    /// Bit mask
    pub bit_mask: u64,
    /// Max number of elements
    pub max_elem: u64,
    /// Number of hash functions used (k)
    pub hash_count: u16,

    /// Max FP rate
    max_fp: f64,
    /// Actual number of elements inserted
    bf_elem_count: u64,
    /// size of compressed bf to be read
    comp_size: usize,
    /// name associated with bloom filter
    setname: String,
    /// set if we allocated the bloom filter ourselves
    created: bool,
    /// ID
    bl_id: i32,
}

impl BloomFilter {
    pub fn new(mut size: usize, hash_count: u16, max_elem: u64, max_fp: f64) -> Self {
        if size < 64 {
            size = 64;
        } else {
            // If not a power of 2...
            if ((size as f32).log2()) as u32 * 10 % 10 != 0 {
                // ...select the next power of two
                size = size.checked_next_power_of_two().unwrap();
            }
        }

        Self {
            bf: vec![0; size],
            hamming: 0,
            hamminglg: 0,
            bf_size: size,
            bit_mask: BloomFilter::log_size(size) as u64,
            max_elem,
            hash_count,
            max_fp,
            bf_elem_count: 0,
            comp_size: 0,
            setname: "".to_string(),
            created: true,
            bl_id: 0,
        }
    }

    /// Creates bloom filter from existing buffer of bloom filter data.
    /// Experimental: sized for sdbf 256-byte bloom filters at the moment
    pub fn from_bloom_buffer(
        data: Vec<u8>,
        size: usize,
        id: i32,
        bf_elem_count: u64,
        hamming: u16,
    ) -> Self {
        // this makes several testing assumptions.
        // this is for 256-byte BFs,
        // and elem_ct = 192, bit_mask=2047 (pre-calculated)
        // and hash_count=5

        Self {
            bf: data,
            hamming,
            hamminglg: hamming as u32,
            bf_size: size,
            bit_mask: BloomFilter::log_size(size) as u64,
            max_elem: 0,
            hash_count: 5,
            max_fp: 0.0,
            bf_elem_count,
            comp_size: 0,
            setname: "".to_string(),
            created: true,
            bl_id: id,
        }
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Ok(BloomFilter::from_str(&contents)?)
    }

    fn log_size(size: usize) -> u32 {
        let mut log_size = 0u16;
        let mut temp = size;
        loop {
            if temp == 0 {
                break;
            }
            temp >>= 1;
            log_size += 1;
        }
        BIT_MASKS_32[1 + log_size as usize]
    }

    pub fn elem_count(&self) -> u64 {
        self.bf_elem_count
    }

    pub fn bits_per_elem(&self) -> f64 {
        (self.bf_size << 3) as f64 / self.bf_elem_count as f64
    }

    pub fn name(&self) -> &String {
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

    /// Write a compressed Bloom Filter to disk
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, format!("{self}"))
    }

    /// Folds bloom filter by half N times by or'ing the
    /// second half of the bloom filter onto the first half.
    pub fn fold(&mut self, times: u32) {
        let mut rsize = self.bf_size / 8;
        unsafe {
            let mut bf_64 = transmute::<&mut [u8], &mut [u64]>(&mut self.bf);

            for i in 0..times as usize {
                for j in 0..(rsize / 2) {
                    bf_64[j] |= bf_64[j + (rsize / 2)];
                }
                rsize /= 2;
                if rsize == 32 {
                    break; // also error?
                }
            }
        }

        self.bf_size = rsize * 8;
        // recalculate mask
        // Find log2(size)
        self.bit_mask = BloomFilter::log_size(self.bf_size) as u64;
        self.compute_hamming();
    }

    /// Add another Bloom Filter if they're of the same size.
    pub fn add(&mut self, other: &BloomFilter) -> anyhow::Result<()> {
        if self.bf_size != other.bf_size {
            bail!(
                "bloom filters of differing sizes {} vs {}",
                self.bf_size,
                other.bf_size
            );
        }

        unsafe {
            let mut bf_64 = transmute::<&mut [u8], &mut [u64]>(&mut self.bf);
            let mut other_bf_64 = transmute::<&[u8], &[u64]>(&other.bf);
            for j in 0..(self.bf_size / 8) {
                bf_64[j] |= other_bf_64[j];
            }
        }

        self.compute_hamming();

        Ok(())
    }

    pub fn compare(&self, other: &BloomFilter, scale: f64) -> i32 {
        if self.bf_size != other.bf_size {
            return -1; // must compare equal sized filters
        }

        let mut result = 0i32;

        unsafe {
            let mut bf_64 = transmute::<&[u8], &[u64]>(&self.bf);
            let mut other_bf_64 = transmute::<&[u8], &[u64]>(&other.bf);
            for i in 0..(self.bf_size / 8) {
                result += ((bf_64[i] & other_bf_64[i]) & 1) as i32;
            }
        }

        let max_est = self.hamminglg.min(other.hamminglg);
        let m = (self.bf_size * 8) as f64;

        let x = self.bf_elem_count;
        let y = other.bf_elem_count;

        // filtering out too-small filters
        if x < 32 || y < 32 {
            return 0;
        }

        let mn = ((2.0 * m) / (x as f64 + y as f64)).round() as usize;
        let mut cut_off = CUTOFFS[mn] as i32;

        if mn > 128 {
            cut_off = CUTOFFS[128] as i32 - (mn as i32 - 128); // setting the cutoff to cutoff -n
        }

        if cut_off < 0 || result <= cut_off {
            return 0;
        }

        (100.0 * ((result as f64 - cut_off as f64) / (max_est as f64 - cut_off as f64))) as i32
    }

    /// Check if data is represented in the Bloom Filter
    /// Issue: data has to be the same size or smaller than `hash_count`
    pub fn query(&self, data: Vec<u32>) -> bool {
        let mut pos = 0u64;
        let mut bit_count = 0u32;
        for i in 0..self.hash_count as usize {
            pos = data[i] as u64 & self.bit_mask;
            let k = pos as usize >> 3;
            // Bit is set
            if self.bf[k] as u32 & BITS[pos as usize & 0x7] > 0 {
                bit_count += 1;
            } else {
                return false;
            }
        }

        bit_count == self.hash_count as u32
    }

    /// Check if data is represented in the Bloom Filter, adding it if not.
    /// Issue: data has to be the same size or smaller than `hash_count`
    pub fn query_and_set(&mut self, data: Vec<u32>) -> bool {
        let mut pos = 0u64;
        let mut bit_count = 0u32;
        for i in 0..self.hash_count as usize {
            pos = data[i] as u64 & self.bit_mask;
            let k = pos as usize >> 3;
            // Bit is set
            if self.bf[k] as u32 & BITS[pos as usize & 0x7] > 0 {
                bit_count += 1;
            } else {
                self.bf[k] |= BITS[pos as usize & 0x7] as u8;
            }
        }

        self.compute_hamming();

        if bit_count < self.hash_count as u32 {
            self.bf_elem_count += 1;
            return true;
        }
        false
    }

    pub fn insert_sha1(&mut self, sha1: Vec<u32>) -> bool {
        self.query_and_set(sha1)
    }

    pub fn query_sha1(&self, sha1: Vec<u32>) -> bool {
        self.query(sha1)
    }

    pub fn compute_hamming(&mut self) {
        self.hamming = 0;
        self.hamminglg = 0;

        unsafe {
            let bf_64 = transmute::<&[u8], &[u64]>(&self.bf);
            for j in 0..self.bf_size / 8 {
                self.hamminglg += count_set_bits(bf_64[j]) as u32;
            }
        }
    }

    fn decompress(&mut self, data: &[u8]) -> anyhow::Result<()> {
        match decompress::decompress(data) {
            Ok(data) => {
                self.bf = data;
                self.compute_hamming();
                Ok(())
            }
            Err(decompress::Error::UnexpectedEnd) => {
                bail!("unexpected end")
            }
            Err(decompress::Error::InvalidDeduplicationOffset) => {
                bail!("invalid de-duplication offset")
            }
        }
    }
}

fn count_set_bits(mut n: u64) -> u64 {
    let mut count = 0u64;
    loop {
        if n == 0 {
            break;
        }
        count += n & 1;
        n >>= 1;
    }
    count
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

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut lines = s.split('\n');

        let mut parts = match lines.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let mut parts = parts.split(':');
        parts.next();

        let bf_size = match parts.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let bf_size = match usize::from_str(bf_size) {
            Ok(s) => s,
            Err(e) => {
                return Err(BloomFilterError(e.to_string()));
            }
        };

        let bf_elem_count = match parts.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let bf_elem_count = match u64::from_str(bf_elem_count) {
            Ok(s) => s,
            Err(e) => {
                return Err(BloomFilterError(e.to_string()));
            }
        };

        let hash_count = match parts.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let hash_count = match u16::from_str(hash_count) {
            Ok(s) => s,
            Err(e) => {
                return Err(BloomFilterError(e.to_string()));
            }
        };

        let bit_mask = match parts.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let bit_mask = match u64::from_str_radix(bit_mask, 16) {
            Ok(x) => x,
            Err(e) => {
                return Err(BloomFilterError(e.to_string()));
            }
        };

        let comp_size = match parts.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let comp_size = match usize::from_str(comp_size) {
            Ok(s) => s,
            Err(e) => {
                return Err(BloomFilterError(e.to_string()));
            }
        };

        let setname = match parts.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let bf = match lines.next() {
            Some(x) => x,
            None => {
                return Err(BloomFilterError("premature end of string".to_string()));
            }
        };

        let bf = match hex::decode(bf) {
            Ok(x) => x,
            Err(e) => {
                return Err(BloomFilterError(e.to_string()));
            }
        };

        let mut bloom = Self {
            bf: vec![],
            hamming: 0,
            hamminglg: 0,
            bf_size,
            bit_mask,
            max_elem: 0,
            hash_count,
            max_fp: 0.0,
            bf_elem_count,
            comp_size,
            setname: setname.to_string(),
            created: true,
            bl_id: 0,
        };

        match bloom.decompress(&bf) {
            Ok(_) => {
                debug_assert_eq!(bf_size, bloom.bf.len());
                Ok(bloom)
            }
            Err(_) => Err(BloomFilterError("failed to decompress".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Context;
    use rstest::rstest;

    const DATA1: [u32; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    const DATA2: [u32; 15] = [99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99];

    #[rstest]
    #[case(10, 5)]
    #[case(10, 10)]
    #[case(128, 5)]
    #[case(256, 10)]
    fn create_store_query(#[case] size: usize, #[case] hash_count: u16) {
        let mut bf = BloomFilter::new(size, hash_count, 1000, 10.0);
        assert_eq!(
            bf.query(DATA1.to_vec()),
            false,
            "data not present yet found"
        );

        bf.query_and_set(DATA1.to_vec());
        assert_eq!(
            bf.query(DATA1.to_vec()),
            true,
            "data not found yet was inserted"
        );

        assert_eq!(
            bf.query(DATA2.to_vec()),
            false,
            "data not present yet found"
        );
    }

    #[test]
    fn compression() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);

        assert_eq!(
            bf.query(DATA1.to_vec()),
            false,
            "data not present yet found"
        );

        assert_eq!(
            bf.query(DATA2.to_vec()),
            false,
            "data not present yet found"
        );

        let compressed = bf.compress();
        bf.decompress(&compressed)
            .context("failed to restore after compression")
            .unwrap();

        assert_eq!(
            bf.query(DATA1.to_vec()),
            false,
            "data not present yet found"
        );

        assert_eq!(
            bf.query(DATA2.to_vec()),
            false,
            "data not present yet found"
        );

        bf.query_and_set(DATA1.to_vec());
        assert_eq!(
            bf.query(DATA1.to_vec()),
            true,
            "data not found yet was inserted"
        );

        let compressed = bf.compress_update_comp_size();
        bf.decompress(&compressed)
            .context("failed to restore after compression")
            .unwrap();

        assert_eq!(
            bf.query(DATA1.to_vec()),
            true,
            "data not found after compression yet was inserted"
        );

        assert_eq!(
            bf.query(DATA2.to_vec()),
            false,
            "data not present yet found after compression"
        );
    }

    #[test]
    fn from_existing_data() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        bf.query_and_set(DATA1.to_vec());
        assert_eq!(
            bf.query(DATA1.to_vec()),
            true,
            "data not found yet was inserted"
        );

        assert_eq!(
            bf.query(DATA2.to_vec()),
            false,
            "data not present yet found"
        );

        let bf2 = BloomFilter::from_bloom_buffer(bf.bf, 10, 0, bf.bf_elem_count, bf.hamming);
        assert_eq!(
            bf2.query(DATA1.to_vec()),
            true,
            "data not found yet was inserted"
        );

        assert_eq!(
            bf2.query(DATA2.to_vec()),
            false,
            "data not present yet found"
        );
    }

    #[test]
    fn addition() {
        let mut bf1 = BloomFilter::new(10, 5, 1000, 10.0);
        bf1.query_and_set(DATA1.to_vec());

        let mut bf2 = BloomFilter::new(10, 5, 1000, 10.0);
        bf2.query_and_set(DATA2.to_vec());

        bf1.add(&bf2).unwrap();

        assert_eq!(
            bf1.query(DATA2.to_vec()),
            true,
            "data not present was added from other Bloom Filter"
        );
    }

    #[test]
    fn serialization() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        bf.query_and_set(DATA1.to_vec());
        assert_eq!(
            bf.query(DATA1.to_vec()),
            true,
            "data not found yet was inserted"
        );

        let serialized_string = bf.to_string();
        let bf2 = BloomFilter::from_str(&serialized_string).unwrap();

        assert_eq!(bf.bf, bf2.bf, "vectors aren't equal");

        assert_eq!(
            bf2.query(DATA1.to_vec()),
            true,
            "data not found after deserialization/serialization yet was inserted"
        );

        assert_eq!(
            bf2.query(DATA2.to_vec()),
            false,
            "data not present yet found after deserialization/serialization"
        );
    }

    #[test]
    fn folding() {
        let mut bf = BloomFilter::new(10, 5, 1000, 10.0);
        bf.query_and_set(DATA1.to_vec());
        bf.fold(2);
        assert_eq!(
            bf.query(DATA1.to_vec()),
            true,
            "data not found yet was inserted"
        );
    }

    #[test]
    fn compare() {
        let mut bf1 = BloomFilter::new(64, 5, 1000, 10.0);
        bf1.query_and_set(DATA1.to_vec());

        let mut bf2 = BloomFilter::new(64, 5, 1000, 10.0);
        bf2.query_and_set(DATA2.to_vec());

        let result = bf2.compare(&bf2, 1.0);
        eprintln!("{bf1} vs {bf2} = {result}");
        assert!(result >= 0);
    }
}
