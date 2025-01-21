use openvm::io;
use vm_zstd::process;

openvm::entry!(main);
fn main() {
    let data = io::read_vec();
    println!("zstd input data len {}", data.len());
    let result = process(&data).unwrap();
    println!("zstd decompressed data len {}", result.decoded_data.len());
}
