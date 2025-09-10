pub mod ciphertext_hasher;
pub mod circuit;
mod core;
pub mod gadgets;
mod hw;
mod math;
pub mod storage;

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
    wire::{EvaluatedWire, GarbledWire, WireError, WireId},
};

pub use ciphertext_hasher::CiphertextHashAcc;
pub use circuit::{CircuitContext, CircuitError};
pub use circuit_component_macro::component;
// Publicly re-export commonly used BN254 wire types for examples/binaries
pub use gadgets::{
    bits_from_biguint_with_len,
    bn254::{
        Fp254Impl, fq::Fq as FqWire, fq2::Fq2 as Fq2Wire, fr::Fr as FrWire,
        g1::G1Projective as G1Wire, g2::G2Projective as G2Wire,
    },
    groth16::{Groth16ExecInput, Groth16ExecInputWires},
    groth16_verify, groth16_verify_compressed,
};
pub use hw::{hardware_aes_available, warn_if_software_aes};
pub use math::*;

pub use crate::circuit::streaming::modes::GarbleMode;

#[cfg(test)]
pub mod test_utils {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub fn trng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0)
    }
}

pub mod groth16_proof_api;
pub use groth16_proof_api::*;

// Backwards-compatible module path for examples/imports
pub mod groth16_proof {
    pub use crate::groth16_proof_api::*;
}
