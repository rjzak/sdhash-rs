pub const MAX_ELEM_COUNT: u32 = 160;
pub const BF_SIZE: u16 = 256;
pub const MIN_FILE_SIZE: usize = 512;
pub const MIN_ELEM_COUNT: usize = 16;

pub const BINS: u32 = 1000;
pub const ENTR_POWER: u32 = 10;
pub const ENTR_SCALE: u32 = BINS * (1 << ENTR_POWER); // 1_024_000
