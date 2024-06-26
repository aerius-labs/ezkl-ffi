extern crate cbindgen;

use std::env;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/");

    let out_dir = env::var("OUT_DIR").unwrap();
    let hdr_out = Path::new(&out_dir).join("include/ezkl-ffi.h");

    cbindgen::generate(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .expect("Could not generate header")
        .write_to_file(hdr_out);
}