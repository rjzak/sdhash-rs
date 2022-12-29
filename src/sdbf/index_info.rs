#![allow(unused)]

use crate::blooms::BloomFilter;
use crate::sdbf::set::Set;

#[derive(Clone, Debug)]
pub struct IndexInfo {
    pub index: BloomFilter,
    pub index_list: Vec<BloomFilter>,
    pub set_list: Vec<Set>,
    pub search_deep: bool,
    pub search_first: bool,
    pub basename: bool,
}
