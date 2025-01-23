pub(crate) mod fse;

pub(crate) mod util;

pub mod types;

pub mod params;

mod decoding;
pub use decoding::process;

/// Encode input bytes by using the default encoder.
pub fn zstd_encode(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use zstd_encoder::N_BLOCK_SIZE_TARGET;
    use zstd_encoder::{init_zstd_encoder as init_zstd_encoder_n, zstd};

    let mut encoder = init_zstd_encoder_n(N_BLOCK_SIZE_TARGET);
    encoder
        .set_pledged_src_size(Some(bytes.len() as u64))
        .expect("infallible");
    encoder.write_all(bytes).expect("infallible");
    encoder.finish().expect("infallible")
}
