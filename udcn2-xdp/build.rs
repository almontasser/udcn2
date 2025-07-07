// Build script for XDP loader
fn main() {
    println!("cargo:rerun-if-changed=../udcn2-ebpf/src/main.rs");
    println!("cargo:rerun-if-changed=../udcn2-ebpf/Cargo.toml");
}