#![allow(unused)]

use super::defines;

use std::sync::RwLock;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref BIT_COUNT_16: [u8; 64 * defines::KB as usize] = init_bit_count_16();
    pub static ref ENTROPY_64_INT: [u64; 65] = entr64_table_init_int();
    pub static ref BF_EST_CACHE: RwLock<Vec<Vec<u16>>> = RwLock::new(vec![vec![0u16; 256]; 256]);
}

pub const ENTR64_RANKS: [u32; 1001] = [
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
    000, 000, 000, 000, 000, 101, 102, 106, 112, 108, 107, 103, 100, 109, 113, 128, 131, 141, 111,
    146, 153, 148, 134, 145, 110, 114, 116, 130, 124, 119, 105, 104, 118, 120, 132, 164, 180, 160,
    229, 257, 211, 189, 154, 127, 115, 129, 142, 138, 125, 136, 126, 155, 156, 172, 144, 158, 117,
    203, 214, 221, 207, 201, 123, 122, 121, 135, 140, 157, 150, 170, 387, 390, 365, 368, 341, 165,
    166, 194, 174, 184, 133, 139, 137, 149, 173, 162, 152, 159, 167, 190, 209, 238, 215, 222, 206,
    205, 181, 176, 168, 147, 143, 169, 161, 249, 258, 259, 254, 262, 217, 185, 186, 177, 183, 175,
    188, 192, 195, 182, 151, 163, 199, 239, 265, 268, 242, 204, 197, 193, 191, 218, 208, 171, 178,
    241, 200, 236, 293, 301, 256, 260, 290, 240, 216, 237, 255, 232, 233, 225, 210, 196, 179, 202,
    212, 420, 429, 425, 421, 427, 250, 224, 234, 219, 230, 220, 269, 247, 261, 235, 327, 332, 337,
    342, 340, 252, 187, 223, 198, 245, 243, 263, 228, 248, 231, 275, 264, 298, 310, 305, 309, 270,
    266, 251, 244, 213, 227, 273, 284, 281, 318, 317, 267, 291, 278, 279, 303, 452, 456, 453, 446,
    450, 253, 226, 246, 271, 277, 295, 302, 299, 274, 276, 285, 292, 289, 272, 300, 297, 286, 314,
    311, 287, 283, 288, 280, 296, 304, 308, 282, 402, 404, 401, 415, 418, 313, 320, 307, 315, 294,
    306, 326, 321, 331, 336, 334, 316, 328, 322, 324, 325, 330, 329, 312, 319, 323, 352, 345, 358,
    373, 333, 346, 338, 351, 343, 405, 389, 396, 392, 411, 378, 350, 388, 407, 423, 419, 409, 395,
    353, 355, 428, 441, 449, 474, 475, 432, 457, 448, 435, 462, 470, 467, 468, 473, 426, 494, 487,
    506, 504, 517, 465, 459, 439, 472, 522, 520, 541, 540, 527, 482, 483, 476, 480, 721, 752, 751,
    728, 730, 490, 493, 495, 512, 536, 535, 515, 528, 518, 507, 513, 514, 529, 516, 498, 492, 519,
    508, 544, 547, 550, 546, 545, 511, 532, 543, 610, 612, 619, 649, 691, 561, 574, 591, 572, 553,
    551, 565, 597, 593, 580, 581, 642, 578, 573, 626, 696, 584, 585, 595, 590, 576, 579, 583, 605,
    569, 560, 558, 570, 556, 571, 656, 657, 622, 624, 631, 555, 566, 564, 562, 557, 582, 589, 603,
    598, 604, 586, 577, 588, 613, 615, 632, 658, 625, 609, 614, 592, 600, 606, 646, 660, 666, 679,
    685, 640, 645, 675, 681, 672, 747, 723, 722, 697, 686, 601, 647, 677, 741, 753, 750, 715, 707,
    651, 638, 648, 662, 667, 670, 684, 674, 693, 678, 664, 652, 663, 639, 680, 682, 698, 695, 702,
    650, 676, 669, 665, 688, 687, 701, 700, 706, 683, 718, 703, 713, 720, 716, 735, 719, 737, 726,
    744, 736, 742, 740, 739, 731, 711, 725, 710, 704, 708, 689, 729, 727, 738, 724, 733, 692, 659,
    705, 654, 690, 655, 671, 628, 634, 621, 616, 630, 599, 629, 611, 620, 607, 623, 618, 617, 635,
    636, 641, 637, 633, 644, 653, 699, 694, 714, 734, 732, 746, 749, 755, 745, 757, 756, 758, 759,
    761, 763, 765, 767, 771, 773, 774, 775, 778, 782, 784, 786, 788, 793, 794, 797, 798, 803, 804,
    807, 809, 816, 818, 821, 823, 826, 828, 829, 834, 835, 839, 843, 846, 850, 859, 868, 880, 885,
    893, 898, 901, 904, 910, 911, 913, 916, 919, 922, 924, 930, 927, 931, 938, 940, 937, 939, 941,
    934, 936, 932, 933, 929, 928, 926, 925, 923, 921, 920, 918, 917, 915, 914, 912, 909, 908, 907,
    906, 900, 903, 902, 905, 896, 899, 897, 895, 891, 894, 892, 889, 883, 890, 888, 879, 887, 886,
    882, 878, 884, 877, 875, 872, 876, 870, 867, 874, 873, 871, 869, 881, 863, 865, 864, 860, 853,
    855, 852, 849, 857, 856, 862, 858, 861, 854, 851, 848, 847, 845, 844, 841, 840, 837, 836, 833,
    832, 831, 830, 827, 824, 825, 822, 820, 819, 817, 815, 812, 814, 810, 808, 806, 805, 799, 796,
    795, 790, 787, 785, 783, 781, 777, 776, 772, 770, 768, 769, 764, 762, 760, 754, 743, 717, 712,
    668, 661, 643, 627, 608, 594, 587, 568, 559, 552, 548, 542, 539, 537, 534, 533, 531, 525, 521,
    510, 505, 497, 496, 491, 486, 485, 478, 477, 466, 469, 463, 458, 460, 444, 440, 424, 433, 403,
    410, 394, 393, 385, 377, 379, 382, 383, 380, 384, 372, 370, 375, 366, 354, 363, 349, 357, 347,
    364, 367, 359, 369, 360, 374, 344, 376, 335, 371, 339, 361, 348, 356, 362, 381, 386, 391, 397,
    399, 398, 412, 408, 414, 422, 416, 430, 417, 434, 400, 436, 437, 438, 442, 443, 447, 406, 451,
    413, 454, 431, 455, 445, 461, 464, 471, 479, 481, 484, 489, 488, 499, 500, 509, 530, 523, 538,
    526, 549, 554, 563, 602, 596, 673, 567, 748, 575, 766, 709, 779, 780, 789, 813, 811, 838, 842,
    866, 942, 935, 944, 943, 947, 952, 951, 955, 954, 957, 960, 959, 967, 966, 969, 962, 968, 953,
    972, 961, 982, 979, 978, 981, 980, 990, 987, 988, 984, 983, 989, 985, 986, 977, 976, 975, 973,
    974, 970, 971, 965, 964, 963, 956, 958, 524, 950, 948, 949, 945, 946, 800, 801, 802, 791, 792,
    501, 502, 503, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
];

pub const CUTOFFS256: [u32; 149] = [
    1250, 1250, 1250, 1250, 1006, 806, 650, 534, 442, 374, 319, 273, 240, 210, 184, 166, 148, 132,
    121, 110, 100, 93, 85, 78, 72, 67, 63, 59, 55, 52, 48, 45, 43, 40, 38, 37, 35, 32, 31, 30, 28,
    27, 26, 25, 24, 23, 22, 21, 20, 19, 19, 18, 18, 17, 16, 15, 15, 15, 15, 14, 13, 13, 12, 12, 12,
    12, 12, 11, 11, 10, 10, 10, 10, 10, 10, 9, 9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7,
    7, 7, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2,
];

pub const CUTOFFS64: [u32; 149] = [
    354, 354, 354, 354, 277, 220, 178, 147, 123, 105, 90, 80, 70, 61, 57, 50, 46, 42, 37, 35, 33,
    29, 27, 26, 24, 23, 22, 21, 19, 19, 18, 17, 16, 15, 14, 14, 14, 14, 13, 13, 11, 11, 11, 11, 10,
    10, 10, 10, 9, 9, 9, 9, 8, 8, 8, 8, 8, 8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 2,
];

#[derive(Clone, Copy, Debug)]
pub struct SdbfConfig {
    /// number of threads available
    pub thread_count: u32,
    pub entr_win_size: u32,
    pub bf_size: u32,
    pub pop_win_size: u32,
    pub block_size: u32,
    /// maximum elements per bf
    pub max_elem: u32,
    /// maximum elements per bf - dd mode
    pub max_elem_dd: u32,

    /// whether to process warnings
    pub warnings: u8,
    pub threshold: u8,
    pub popcnt: bool,
}

impl SdbfConfig {
    pub fn new(mut thread_count: u32, warnings: u8, max_elem: u32, max_elem_dd: u32) -> Self {
        if thread_count > defines::MAX_THREADS {
            thread_count = defines::MAX_THREADS;
        }
        Self {
            thread_count,
            entr_win_size: 64,
            bf_size: 256,
            pop_win_size: 64,
            block_size: 4 * defines::KB as u32,
            max_elem,
            max_elem_dd,
            warnings,
            threshold: 16, // or 1
            popcnt: false,
        }
    }
}

impl Default for SdbfConfig {
    fn default() -> Self {
        SdbfConfig::new(
            1,
            defines::FLAG_OFF,
            defines::MAX_ELEM_COUNT,
            defines::MAX_ELEM_COUNT_DD,
        )
    }
}

fn init_bit_count_16() -> [u8; 64 * defines::KB as usize] {
    let mut array = [0u8; 64 * defines::KB as usize];

    for byte in 0..64 * defines::KB as usize {
        for bit in 0..16usize {
            if byte & 0x1usize << bit > 0 {
                array[byte] += 1;
            }
        }
    }

    array
}

/// Entropy lookup table setup--int64 version (to be called once)
fn entr64_table_init_int() -> [u64; 65] {
    let mut array = [0u64; 65];

    for i in 1..65usize {
        let mut p = i as f64 / 64.0;
        p = (-p * (p.log10() / 2.0f64.log10()) / 6.0) * defines::ENTR_SCALE as f64;
        array[i] = p as u64;
    }

    array
}

/// Baseline entropy computation for a 64-byte buffer--int64 version (to be called periodically)
fn entr64_u8(buffer: &Vec<u8>, ascii: &mut Vec<u8>) -> u64 {
    ascii.resize(258, 0);
    for i in 0..64usize {
        let bf = buffer[i];
        ascii[bf as usize] += 1;
    }

    let mut entr = 0;

    for i in 0..256usize {
        if ascii[i] != 0 {
            entr += ENTROPY_64_INT[ascii[i] as usize];
        }
    }

    entr
}

/// Incremental (rolling) update to entropy computation--int64 version
fn entr64_u64(prev_entropy: u64, buffer: &Vec<u8>, ascii: &mut Vec<u8>) -> u64 {
    if buffer[0] == buffer[64] {
        return prev_entropy;
    }

    let old_char_count = ascii[buffer[0] as usize];
    let new_char_count = ascii[buffer[64] as usize];

    ascii[buffer[0] as usize] -= 1;
    ascii[buffer[64] as usize] += 1;

    if old_char_count == new_char_count + 1 {
        return prev_entropy;
    }

    let old_diff = ENTROPY_64_INT[old_char_count as usize] as i64
        - ENTROPY_64_INT[(old_char_count - 1) as usize] as i64;

    let new_diff = ENTROPY_64_INT[(new_char_count + 1) as usize] as i64
        - ENTROPY_64_INT[new_char_count as usize] as i64;

    let mut entropy = prev_entropy as i64 - old_diff + new_diff;
    if entropy < 0 {
        entropy = 0;
    } else if entropy > defines::ENTR_SCALE as i64 {
        entropy = defines::ENTR_SCALE as i64
    }

    entropy as u64
}
