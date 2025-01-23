use std::fs;

use anyhow::{anyhow, Result};
use openvm::platform::memory::MEM_SIZE;
use openvm_sdk::{
    config::{AggConfig, AppConfig, SdkVmConfig},
    prover::AppProver,
    Sdk, StdIn,
};
use openvm_transpiler::elf::Elf;
use vm_zstd::{process, zstd_encode};

#[allow(unused_variables, unused_doc_comments)]
fn calc_cycle(zstd_input: &[u8]) -> Result<()> {
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
    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32).map_err(|err| anyhow!("{err}"))?;
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

fn main() {
    let mut batch_files = fs::read_dir("./data/test_batches")
        .unwrap()
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()
        .unwrap();
    batch_files.sort();

    let batches = batch_files
        .iter()
        .take(1)
        .map(fs::read_to_string)
        .filter_map(|data| data.ok())
        .map(|data| hex::decode(data.trim_end()).expect("Failed to decode hex data"))
        .collect::<Vec<Vec<u8>>>();

    for raw_input_bytes in batches.into_iter() {
        let compressed = zstd_encode(&raw_input_bytes);

        calc_cycle(&compressed).unwrap();
    }
}
