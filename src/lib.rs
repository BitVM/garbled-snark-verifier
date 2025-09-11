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

pub mod garbled_groth16;

// All ark-* related items live under this module for clarity
pub mod ark {
    // Field traits and RNG utilities
    // Curve types and configs used by examples
    pub use ark_bn254::{Bn254, Fq, Fq2, Fq12, Fr, G1Projective, G2Affine, G2Projective, g1, g2};
    // EC traits
    pub use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, short_weierstrass::SWCurveConfig};
    pub use ark_ff::{PrimeField, UniformRand, fields::Field};
    // SNARK traits and Groth16 scheme
    pub use ark_groth16::Groth16;
    // R1CS interfaces and lc! macro
    pub use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    pub use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
}
