extern crate bindgen;

use std::env;
use std::path::PathBuf;
use std::path::Path;

fn main() {
    // Tell cargo to tell rustc to link libsgx_bridge shared library.
    println!("cargo:rustc-link-lib=rust_sgx_bridge");
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}", Path::new(&dir).join("../../build/bin").display());

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("../rust_sgx_bridge/rust_sgx_bridge.h")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $CARGO_MANIFEST_DIR/src/bindings.rs file.
    let mut out_path_manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR")
                                              .unwrap());
    out_path_manifest.push("src");
    bindings.write_to_file(out_path_manifest.join("bindings.rs"))
            .expect("Couldn't write bindings!");
}
