#![allow(unused)]

use crate::blooms::BloomFilter;
use crate::sdbf::sdbf::Sdbf;
use anyhow::bail;

#[derive(Clone, Debug)]
pub struct Set {
    /// index for this set
    pub index: Option<BloomFilter>,
    /// giant bloom filter vector for this set
    pub bf_vector: Vec<BloomFilter>,

    items: Vec<Sdbf>,
    set_name: String,
    sep: char,
}

impl Set {
    pub fn new() -> Self {
        Self {
            index: None,
            bf_vector: vec![],
            items: vec![],
            set_name: "default".to_string(),
            sep: '|',
        }
    }

    pub fn new_with_bloom_filters(index: BloomFilter) -> Self {
        Self {
            index: Some(index),
            bf_vector: vec![],
            items: vec![],
            set_name: "default".to_string(),
            sep: '|',
        }
    }

    /// Get an item from the Set via index
    pub fn at(&self, pos: usize) -> Option<&Sdbf> {
        self.items.get(pos)
    }

    /// Add an item to this Set
    pub fn add(&mut self, hash: Sdbf) {
        self.items.push(hash);
    }

    /// Adds all items in another set to this Set
    pub fn add_all(&mut self, other: &Self) {
        other.items.iter().map(|i| self.items.push(i.clone()));
    }

    /// Number of items in this Set
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Checks empty status of container
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl Default for Set {
    fn default() -> Self {
        Set::new()
    }
}
