/// Number of bits to represent a byte.
pub const N_BITS_PER_BYTE: usize = 8;

/// Number of bytes used to specify block header.
pub const N_BLOCK_HEADER_BYTES: usize = 3;

/// Constants for zstd-compressed block
pub const N_MAX_LITERAL_HEADER_BYTES: usize = 3;

/// Number of bits used to represent the tag in binary form.
pub const N_BITS_ZSTD_TAG: usize = 4;

/// Number of bits in the repeat bits that follow value=1 in reconstructing FSE table.
pub const N_BITS_REPEAT_FLAG: usize = 2;

// /// re-export constants in zstd-encoder
//pub use zstd_encoder::{N_BLOCK_SIZE_TARGET, N_MAX_BLOCKS};
