pub mod types;
pub mod params;

pub(crate) mod fse;
pub(crate) mod util;

mod decoding;
pub use decoding::process;