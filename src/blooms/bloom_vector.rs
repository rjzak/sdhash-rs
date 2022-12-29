#![allow(unused)]

use super::BloomFilter;

#[derive(Clone, Debug)]
pub struct BloomVector {
    pub items: Vec<BloomFilter>,
    pub objname: String,
}

impl BloomVector {
    pub fn new(bloom: BloomFilter) -> Self {
        let mut bv = Self {
            items: vec![bloom],
            objname: "".to_string(),
        };

        bv.objname = bv.items[0].name().clone();

        bv
    }
}
