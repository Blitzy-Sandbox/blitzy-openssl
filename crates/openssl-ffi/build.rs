//! Build script for the openssl-ffi crate.
//!
//! This stub will be replaced with the full cbindgen header generation
//! implementation. The build script invokes cbindgen to generate C headers
//! from the Rust FFI exports.

fn main() {
    // Stub: full cbindgen integration will be provided by the build.rs agent.
    // Re-run if source files change.
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
