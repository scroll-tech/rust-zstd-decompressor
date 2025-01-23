pub mod params;
pub mod types;

pub(crate) mod fse;
pub(crate) mod util;

mod decoding;
pub use decoding::process;

pub fn zstd_encode(raw_input_bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use zstd_encoder::init_zstd_encoder as init_zstd_encoder_n;
    use zstd_encoder::N_BLOCK_SIZE_TARGET;

    // compression level = 0 defaults to using level=3, which is zstd's default.
    let mut encoder = init_zstd_encoder_n(N_BLOCK_SIZE_TARGET);

    // set source length, which will be reflected in the frame header.
    encoder
        .set_pledged_src_size(Some(raw_input_bytes.len() as u64))
        .unwrap();

    encoder.write_all(raw_input_bytes).unwrap();
    encoder.finish().unwrap()
}
