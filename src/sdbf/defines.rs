#![allow(unused)]

pub const MAX_ELEM_COUNT: u32 = 160;
pub const MAX_ELEM_COUNT_DD: u32 = 192;
pub const FP_THRESHOLD: u8 = 4;
pub const KB: u16 = 1024;

// Command-line related
pub const DELIM_CHAR: u8 = b':';
pub const DELIM_STRING: &str = ":";
pub const MAGIC_DD: &str = "sdbf-dd";
pub const MAGIC_STREAM: &str = "sdbf";
pub const MAX_MAGIC_HEADER: usize = 512;
pub const FLAG_OFF: u8 = 0x00;
pub const FLAG_ON: u8 = 0x01;

// System parameters
pub const BF_SIZE: u16 = 256;
pub const BINS: u32 = 1000;
pub const ENTR_POWER: u32 = 10;
pub const ENTR_SCALE: u32 = (BINS * (1 << ENTR_POWER));
pub const MAX_FILES: u32 = 1000000;
pub const MAX_THREADS: u32 = 512;
pub const MIN_FILE_SIZE: usize = 512;
// changing 6 to 16, 3/5/13
pub const MIN_ELEM_COUNT: usize = 16;
pub const MIN_REF_ELEM_COUNT: usize = 64;
pub const POP_WIN_SIZE: usize = 64;
pub const SD_SCORE_SCALE: f32 = 0.3;
pub const SYNC_SIZE: u16 = 16384;
pub const BIGFILTER: usize = 16384;
pub const BIGFILTER_ELEM: u64 = 8738;
