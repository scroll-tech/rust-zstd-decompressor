use vm_zstd::process;
use openvm_sdk::{
    config::{AggConfig, AppConfig, SdkVmConfig},
    prover::AppProver,
    Sdk, StdIn,
};
use openvm::platform::memory::MEM_SIZE;
use openvm_transpiler::elf::Elf;
use anyhow::{anyhow, Result};
use std::fs;

#[allow(unused_variables, unused_doc_comments)]
fn calc_cycle(zstd_input: &[u8]) -> Result<()>{

    // ANCHOR: vm_config
    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();
    // ANCHOR_END: vm_config

    /// to import example guest code in crate replace `target_path` for:
    /// ```
    /// use std::path::PathBuf;
    ///
    /// let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    /// path.push("guest");
    /// let target_path = path.to_str().unwrap();
    /// ```
    // ANCHOR: build
    // 1. Build the VmConfig with the extensions needed.
    let sdk = Sdk;
    // 2a. Build the ELF with guest options and a target filter (skipped, simply read elf).


    let elf_bytes = fs::read("target/riscv32im-risc0-zkvm-elf/release/zstd-decompressor")?;
    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32).map_err(|err|anyhow!("{err}"))?;    
    // ANCHOR_END: build

    // ANCHOR: transpilation
    // 3. Transpile the ELF into a VmExe
    let exe = sdk.transpile(elf, vm_config.transpiler())?;

    // ANCHOR: execution
    // 4. Format your input into StdIn
    let mut stdin = StdIn::default();
    stdin.write_bytes(zstd_input);

    let output = sdk.execute(exe.clone(), vm_config.clone(), stdin.clone())?;
    println!("public values output: {:?}", output);

    //process(&data).unwrap();
    Ok(())
}

use std::io::Write;
use zstd_encoder::N_BLOCK_SIZE_TARGET;
use zstd_encoder::{init_zstd_encoder as init_zstd_encoder_n, zstd};

/// Zstd encoder configuration
fn init_zstd_encoder(
    target_block_size: Option<u32>,
) -> zstd::stream::Encoder<'static, Vec<u8>> {
    init_zstd_encoder_n(target_block_size.unwrap_or(N_BLOCK_SIZE_TARGET))
}

/// Encode input bytes by using the default encoder.
fn zstd_encode(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = init_zstd_encoder(None);
    encoder
        .set_pledged_src_size(Some(bytes.len() as u64))
        .expect("infallible");
    encoder.write_all(bytes).expect("infallible");
    encoder.finish().expect("infallible")
}

fn main() {

    let mut batch_files = fs::read_dir("./data/test_batches").unwrap()
    .map(|entry| entry.map(|e| e.path()))
    .collect::<Result<Vec<_>, std::io::Error>>().unwrap();
    batch_files.sort();

    let batches = batch_files
    .iter()
    .take(1)
    .map(fs::read_to_string)
    .filter_map(|data| data.ok())
    .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
    .collect::<Vec<Vec<u8>>>();

    for raw_input_bytes in batches.into_iter() {
        let compressed = {
            // compression level = 0 defaults to using level=3, which is zstd's default.
            let mut encoder = init_zstd_encoder(None);

            // set source length, which will be reflected in the frame header.
            encoder.set_pledged_src_size(Some(raw_input_bytes.len() as u64)).unwrap();

            encoder.write_all(&raw_input_bytes).unwrap();
            encoder.finish().unwrap()
        };

        calc_cycle(&compressed).unwrap();
    }
}