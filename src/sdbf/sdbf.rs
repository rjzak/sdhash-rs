#![allow(unused)]

use crate::blooms::BloomFilter;
use crate::sdbf::defines::BF_SIZE;
use crate::sdbf::index_info::IndexInfo;
use crate::sdbf::{config, defines};
use std::mem::transmute;

/// A Similarity Digest Bloom Filter class.
#[derive(Clone, Debug)]
pub struct Sdbf {
    /// Beginning of the Bloom Filter cluster
    pub buffer: Vec<u8>,
    /// Hamming weight for each BF
    pub hamming: Vec<u16>,
    /// Max number of elements per filter (n)
    pub max_elem: u32,
    pub big_filters: Vec<BloomFilter>,

    info: Option<IndexInfo>,
    index_results: String,
    /// name (usually, source file)
    hash_name: String,
    /// Number of Bloom Filters
    bf_count: u32,
    /// Bloom Filter size in bytes (==m/8)
    bf_size: u32,
    /// Number of hash functions used (k)
    hash_count: u32,
    /// Bit mask used (must agree with m)
    mask: u32,
    /// Actual number of elements in last filter (n_last), ZERO means look at elem_counts value
    last_count: u32,
    /// Individual elements counts for each BF (used in dd mode)
    elem_counts: Vec<u16>,
    /// Size of the base block in dd mode
    dd_block_size: u32,
    /// size of the original file
    orig_file_size: u64,
}

impl Sdbf {
    /// Create and initialize an Sdbf structure ready for stream mode.
    fn new(name: String) -> Self {
        Self {
            buffer: vec![],
            hamming: vec![],
            max_elem: 0,
            big_filters: vec![BloomFilter::new(
                defines::BIGFILTER,
                5,
                defines::BIGFILTER_ELEM,
                0.01,
            )],
            info: None,
            index_results: "".to_string(),
            hash_name: name,
            bf_count: 0,
            bf_size: 0,
            hash_count: 0,
            mask: 0,
            last_count: 0,
            elem_counts: vec![],
            dd_block_size: 0,
            orig_file_size: 0,
        }
    }

    /// Pre-compute Hamming weights for each Bloom Filter and add them to the Sdbf descriptor.
    fn compute_hamming(&mut self) {
        self.hamming.resize(self.bf_count as usize, 0);

        unsafe {
            let mut bf_16 = transmute::<&mut [u8], &mut [u16]>(&mut self.buffer);

            let mut pos = 0usize;
            for i in 0..self.bf_count as usize {
                for j in 0..(BF_SIZE / 2) {
                    self.hamming[i] += config::BIT_COUNT_16[bf_16[pos] as usize] as u16;
                }
            }
        }
    }
}
