pub mod ciphertext_hasher;
pub mod circuit;
mod core;
mod gadgets;
mod math;

// Re-export the procedural macro
pub use core::{
    DefaultHasher,
    delta::Delta,
    gate::{
        Gate, GateError,
        garbling::{AesNiHasher, Blake3Hasher, GateHasher},
    },
    gate_type::GateType,
    s::S,
    wire::{EvaluatedWire, GarbledWire, GarbledWires, WireError, WireId},
};

pub use ciphertext_hasher::CiphertextHasher;
pub use circuit::{CircuitContext, CircuitError};
pub use circuit_component_macro::component;
// Publicly re-export commonly used BN254 wire types for examples/binaries
pub use gadgets::bn254::fr::Fr as FrWire;
pub use gadgets::{
    bn254::{fq::Fq, g1::G1Projective as G1Wire},
    groth16_verify, groth16_verify_compressed,
};
pub use math::*;

pub mod storage;

#[cfg(test)]
pub mod test_utils {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub fn trng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0)
    }
}
