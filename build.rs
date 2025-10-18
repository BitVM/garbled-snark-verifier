fn main() {
    // Example: checking if the "fast-math" feature is enabled
    if std::env::var("CARGO_FEATURE_SP1_SOLDERING").is_ok() {
        println!("cargo:rerun-if-changed=sp1-soldering-program/Cargo.toml");
        println!("cargo:rerun-if-changed=sp1-soldering-program/src/main.rs");
        println!("cargo:rerun-if-env-changed=SP1_DEV_MODE");

        sp1_build::build_program_with_args("sp1-soldering-program", Default::default());
    } else {
        println!("no soldering");
    }
}
