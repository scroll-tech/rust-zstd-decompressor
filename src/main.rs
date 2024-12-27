
use vm_zstd::process;
use openvm::io;

openvm::entry!(main);
fn main() {
    let data = io::read_vec();
    println!("data len {}", data.len());
    process(&data).unwrap();
}
