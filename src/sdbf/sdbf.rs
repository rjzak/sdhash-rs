use crate::sdbf::config::{CUTOFFS256, ENTR64_RANKS, ENTROPY_64_INT};
use crate::sdbf::defines::*;
use sha1::{Digest, Sha1};
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const SDBF_VERSION: u32 = 3;
const HASH_COUNT: usize = 5;
const BIT_MASK: u32 = BF_SIZE as u32 * 8 - 1; // 2047

/// A Similarity Digest Bloom Filter.
#[derive(Clone, Debug)]
pub struct Sdbf {
    /// Concatenated raw bytes for all Bloom filters
    buffer: Vec<u8>,
    /// Hamming weight for each BF
    hamming: Vec<u16>,
    /// Name (usually source filename)
    hash_name: String,
    /// Number of BFs
    bf_count: u32,
    /// BF size in bytes (256)
    bf_size: u32,
    /// Number of hash functions (5)
    hash_count: u32,
    /// Bit mask (2047)
    mask: u32,
    /// Element count in the last BF
    last_count: u32,
    /// Max elements per BF (160)
    max_elem: u32,
    /// Original file size
    orig_file_size: u64,
}

impl Sdbf {
    /// Generate an Sdbf hash from raw file bytes.
    pub fn from_data(data: &[u8], name: &str) -> Option<Self> {
        if data.len() < MIN_FILE_SIZE {
            return None;
        }

        let bf_size = BF_SIZE as usize;
        let mut sdbf = Self {
            buffer: vec![0u8; bf_size],
            hamming: vec![0u16; 1],
            hash_name: name.to_string(),
            bf_count: 1,
            bf_size: bf_size as u32,
            hash_count: HASH_COUNT as u32,
            mask: BIT_MASK,
            last_count: 0,
            max_elem: MAX_ELEM_COUNT,
            orig_file_size: data.len() as u64,
        };

        sdbf.gen_sdbf(data);
        sdbf.compute_hamming();

        // Discard if too few features
        if sdbf.bf_count == 1 && sdbf.last_count < MIN_ELEM_COUNT as u32 {
            return None;
        }

        Some(sdbf)
    }

    fn gen_sdbf(&mut self, data: &[u8]) {
        if data.len() < 65 {
            return;
        }

        let bf_size = self.bf_size as usize;
        let max_elem = self.max_elem;
        let mask = self.mask;

        let mut ascii = vec![0u8; 256];
        let mut entr = entr64_init(&data[..64], &mut ascii);

        for i in 0..data.len() - 64 {
            entr = entr64_roll(entr, data[i], data[i + 64], &mut ascii);

            let rank_idx = (entr >> ENTR_POWER as u64) as usize;
            let rank = ENTR64_RANKS.get(rank_idx).copied().unwrap_or(0);

            if rank < 16 {
                continue;
            }

            let sha1_bytes: [u8; 20] = Sha1::digest(&data[i..i + 64]).into();
            let positions = sha1_to_positions(&sha1_bytes, mask);

            let curr_start = (self.bf_count as usize - 1) * bf_size;
            let curr_bf = &mut self.buffer[curr_start..curr_start + bf_size];

            if !bf_contains(curr_bf, &positions) {
                bf_set_bits(curr_bf, &positions);
                self.last_count += 1;

                if self.last_count >= max_elem {
                    self.buffer.resize(self.buffer.len() + bf_size, 0);
                    self.hamming.push(0);
                    self.bf_count += 1;
                    self.last_count = 0;
                }
            }
        }
    }

    /// Compare this Sdbf against another, returning 0-100 similarity score.
    pub fn compare(&self, other: &Sdbf) -> u32 {
        let bf_size = self.bf_size as usize;
        let mut max_score = 0;

        for i in 0..self.bf_count as usize {
            for j in 0..other.bf_count as usize {
                let bf1 = &self.buffer[i * bf_size..(i + 1) * bf_size];
                let bf2 = &other.buffer[j * bf_size..(j + 1) * bf_size];
                let h1 = self.hamming[i];
                let h2 = other.hamming[j];
                // Element counts: all BFs except the last one are full (max_elem).
                let n1 = self.elem_count_for_bf(i);
                let n2 = other.elem_count_for_bf(j);
                let score = bf_score(bf1, bf2, h1, h2, n1, n2);
                if score > max_score {
                    max_score = score;
                }
            }
        }

        max_score
    }

    fn elem_count_for_bf(&self, i: usize) -> u32 {
        if i + 1 < self.bf_count as usize {
            self.max_elem
        } else {
            self.last_count
        }
    }

    pub fn name(&self) -> &str {
        &self.hash_name
    }

    pub fn bf_count(&self) -> u32 {
        self.bf_count
    }

    fn compute_hamming(&mut self) {
        let bf_size = self.bf_size as usize;
        self.hamming.resize(self.bf_count as usize, 0);
        for i in 0..self.bf_count as usize {
            let bf = &self.buffer[i * bf_size..(i + 1) * bf_size];
            self.hamming[i] = bf.iter().map(|b| b.count_ones() as u16).sum();
        }
    }
}

// --- Entropy ---

fn entr64_init(data: &[u8], ascii: &mut [u8]) -> u64 {
    for &b in data {
        ascii[b as usize] += 1;
    }
    let mut entr = 0u64;
    for i in 0..256usize {
        if ascii[i] != 0 {
            entr += ENTROPY_64_INT[ascii[i] as usize];
        }
    }
    entr
}

fn entr64_roll(prev: u64, out: u8, in_: u8, ascii: &mut [u8]) -> u64 {
    if out == in_ {
        return prev;
    }
    let old_cnt = ascii[out as usize];
    let new_cnt = ascii[in_ as usize];
    ascii[out as usize] -= 1;
    ascii[in_ as usize] += 1;

    if old_cnt == new_cnt + 1 {
        return prev;
    }

    let old_diff = ENTROPY_64_INT[old_cnt as usize] as i64
        - ENTROPY_64_INT[(old_cnt - 1) as usize] as i64;
    let new_diff = ENTROPY_64_INT[(new_cnt + 1) as usize] as i64
        - ENTROPY_64_INT[new_cnt as usize] as i64;

    let entropy = (prev as i64 - old_diff + new_diff).clamp(0, ENTR_SCALE as i64);
    entropy as u64
}

// --- Bloom filter helpers ---

fn sha1_to_positions(sha1: &[u8; 20], mask: u32) -> [u32; 5] {
    [
        u32::from_be_bytes(sha1[0..4].try_into().unwrap()) & mask,
        u32::from_be_bytes(sha1[4..8].try_into().unwrap()) & mask,
        u32::from_be_bytes(sha1[8..12].try_into().unwrap()) & mask,
        u32::from_be_bytes(sha1[12..16].try_into().unwrap()) & mask,
        u32::from_be_bytes(sha1[16..20].try_into().unwrap()) & mask,
    ]
}

fn bf_contains(bf: &[u8], positions: &[u32; 5]) -> bool {
    positions.iter().all(|&pos| {
        let pos = pos as usize;
        bf[pos >> 3] & (1 << (pos & 7)) != 0
    })
}

fn bf_set_bits(bf: &mut [u8], positions: &[u32; 5]) {
    for &pos in positions {
        let pos = pos as usize;
        bf[pos >> 3] |= 1 << (pos & 7);
    }
}

// h1, h2: hamming weights (set-bit counts) of each filter.
// n1, n2: element counts (features inserted) into each filter.
// mn uses element counts; max_est and result use hamming weights.
fn bf_score(bf1: &[u8], bf2: &[u8], h1: u16, h2: u16, n1: u32, n2: u32) -> u32 {
    if h1 == 0 || h2 == 0 || n1 == 0 || n2 == 0 {
        return 0;
    }

    let result: u32 = bf1
        .chunks_exact(8)
        .zip(bf2.chunks_exact(8))
        .map(|(c1, c2)| {
            let w1 = u64::from_le_bytes(c1.try_into().unwrap());
            let w2 = u64::from_le_bytes(c2.try_into().unwrap());
            (w1 & w2).count_ones()
        })
        .sum();

    let max_est = h1.min(h2) as u32;
    let m = (bf1.len() * 8) as u32; // 2048
    // mn measures BF density; uses element counts so it is stable across files
    let mn = ((2 * m) / (n1 + n2)).min(148) as usize;
    let cut_off = CUTOFFS256[mn];

    if result <= cut_off || max_est <= cut_off {
        return 0;
    }

    (100 * (result - cut_off) / (max_est - cut_off)).min(100)
}

// --- Display / FromStr ---

impl Display for Sdbf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "sdbf:{}:{}:{}:{}:sha1:{}:{}:{}:{}:{}:{}",
            SDBF_VERSION,
            self.bf_count,
            self.hash_name,
            self.orig_file_size,
            self.bf_size,
            self.hash_count,
            self.mask,
            self.max_elem,
            self.last_count,
            hex::encode(&self.buffer),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdbfParseError(String);

impl Display for SdbfParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to parse sdbf: {}", self.0)
    }
}

impl std::error::Error for SdbfParseError {}

impl FromStr for Sdbf {
    type Err = SdbfParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim_end_matches('\n');
        let parts: Vec<&str> = s.splitn(12, ':').collect();

        if parts.len() < 12 {
            return Err(SdbfParseError(format!(
                "expected 12 fields, got {}",
                parts.len()
            )));
        }

        if parts[0] != "sdbf" {
            return Err(SdbfParseError("missing sdbf magic".into()));
        }

        let bf_count = parts[2]
            .parse::<u32>()
            .map_err(|e| SdbfParseError(e.to_string()))?;
        let hash_name = parts[3].to_string();
        let orig_file_size = parts[4]
            .parse::<u64>()
            .map_err(|e| SdbfParseError(e.to_string()))?;
        // parts[5] = "sha1"
        let bf_size = parts[6]
            .parse::<u32>()
            .map_err(|e| SdbfParseError(e.to_string()))?;
        let hash_count = parts[7]
            .parse::<u32>()
            .map_err(|e| SdbfParseError(e.to_string()))?;
        let mask = parts[8]
            .parse::<u32>()
            .map_err(|e| SdbfParseError(e.to_string()))?;
        let max_elem = parts[9]
            .parse::<u32>()
            .map_err(|e| SdbfParseError(e.to_string()))?;
        let last_count = parts[10]
            .parse::<u32>()
            .map_err(|e| SdbfParseError(e.to_string()))?;

        let buffer =
            hex::decode(parts[11]).map_err(|e| SdbfParseError(format!("hex: {e}")))?;

        let expected_len = bf_count as usize * bf_size as usize;
        if buffer.len() != expected_len {
            return Err(SdbfParseError(format!(
                "buffer length {} != expected {}",
                buffer.len(),
                expected_len
            )));
        }

        let mut sdbf = Self {
            buffer,
            hamming: vec![0u16; bf_count as usize],
            hash_name,
            bf_count,
            bf_size,
            hash_count,
            mask,
            last_count,
            max_elem,
            orig_file_size,
        };

        sdbf.compute_hamming();
        Ok(sdbf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generate data with medium entropy (~3 bits/byte) — 8 distinct values
    // chosen with a good LCG so entropy index falls ~500, rank >> threshold 16.
    // Max-entropy data (index 1000) has rank 0 and produces no features.
    fn make_data(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed;
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                ((s >> 56) % 8) as u8
            })
            .collect()
    }

    #[test]
    fn hash_generation() {
        let data = make_data(8192, 42);
        let sdbf = Sdbf::from_data(&data, "test.bin");
        assert!(sdbf.is_some(), "should produce a hash for 8KB of data");
        let sdbf = sdbf.unwrap();
        assert!(sdbf.bf_count() >= 1);
    }

    #[test]
    fn too_small_returns_none() {
        let data = make_data(100, 42);
        assert!(Sdbf::from_data(&data, "small.bin").is_none());
    }

    #[test]
    fn roundtrip() {
        let data = make_data(8192, 42);
        let sdbf = Sdbf::from_data(&data, "test.bin").unwrap();
        let s = sdbf.to_string();
        let sdbf2: Sdbf = s.parse().expect("parse should succeed");
        assert_eq!(sdbf.bf_count, sdbf2.bf_count);
        assert_eq!(sdbf.buffer, sdbf2.buffer);
        assert_eq!(sdbf.hamming, sdbf2.hamming);
    }

    #[test]
    fn similar_files_score_high() {
        let data1 = make_data(16384, 42);
        let mut data2 = data1.clone();
        // Modify ~5% of bytes — most 64-byte windows stay identical
        for i in (0..data2.len()).step_by(20) {
            data2[i] = data2[i].wrapping_add(1) % 8;
        }
        let s1 = Sdbf::from_data(&data1, "a.bin").unwrap();
        let s2 = Sdbf::from_data(&data2, "b.bin").unwrap();
        let score = s1.compare(&s2);
        assert!(score > 0, "similar files should have score > 0, got {score}");
    }

    #[test]
    fn identical_files_score_100() {
        let data = make_data(16384, 42);
        let s1 = Sdbf::from_data(&data, "a.bin").unwrap();
        let s2 = Sdbf::from_data(&data, "b.bin").unwrap();
        let score = s1.compare(&s2);
        assert_eq!(score, 100, "identical content should score 100");
    }

    #[test]
    fn dissimilar_files_score_low() {
        // Two independent random streams → different SHA-1 for every window
        let s1 = Sdbf::from_data(&make_data(8192, 0xAAAAAAAA), "a.bin").unwrap();
        let s2 = Sdbf::from_data(&make_data(8192, 0x55555555), "b.bin").unwrap();
        let score = s1.compare(&s2);
        assert!(score < 50, "unrelated data should score < 50, got {score}");
    }
}
