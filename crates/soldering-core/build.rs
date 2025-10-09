fn main() {
    println!("cargo:rerun-if-changed=guest/Cargo.toml");
    println!("cargo:rerun-if-changed=guest/src/main.rs");
    println!("cargo:rerun-if-env-changed=SP1_DEV_MODE");

    sp1_build::build_program_with_args("guest", Default::default());
}
