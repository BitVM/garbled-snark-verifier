fn main() {
    #[cfg(feature = "sp1-soldering")]
    {
        println!("cargo:rerun-if-changed=sp1-soldering-program/Cargo.toml");
        println!("cargo:rerun-if-changed=sp1-soldering-program/src/main.rs");
        println!("cargo:rerun-if-env-changed=SP1_DEV_MODE");
        sp1_build::build_program_with_args("sp1-soldering-program", Default::default());
        _ = sp1_sdk::install::try_install_circuit_artifacts("groth16");
    }
}
