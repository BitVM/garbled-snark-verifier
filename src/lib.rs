pub mod cac;
pub mod ciphertext_hasher;
pub mod circuit;
mod core;
pub mod gadgets;
pub mod hashers;
mod hw;
pub mod logging;
mod math;
pub mod storage;

// Re-export the procedural macro
pub use core::{delta::Delta, gate::Gate, gate_type::GateType, s::S, wire::WireId};

// Re-export EvaluatedWire from mode locality while keeping public path stable
pub use crate::circuit::modes::EvaluatedWire;
// Re-export GarbledWire from mode locality while keeping public path stable
pub use crate::circuit::modes::GarbledWire;
// Root-level hasher exports
pub use crate::hashers::{AesNiHasher, Blake3Hasher, GateHasher, HasherKind};
pub type DefaultHasher = crate::hashers::Blake3Hasher;

pub use ciphertext_hasher::CiphertextHashAcc;
pub use circuit::CircuitContext;
pub use circuit_component_macro::component;
// Publicly re-export commonly used BN254 wire types for examples/binaries
pub use gadgets::{
    bits_from_biguint_with_len,
    bn254::{
        Fp254Impl, fq::Fq as FqWire, fq2::Fq2 as Fq2Wire, fr::Fr as FrWire,
        g1::G1Projective as G1Wire, g2::G2Projective as G2Wire,
    },
    groth16::{Groth16VerifyInput, Groth16VerifyInputWires},
    groth16_verify, groth16_verify_compressed,
};
pub use hw::{hardware_aes_available, warn_if_software_aes};
pub use logging::init_tracing;
pub use math::*;

pub use crate::circuit::modes::GarbleMode;

#[cfg(test)]
pub mod test_utils {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub fn trng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0)
    }
}

pub mod cut_and_choose;
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
    pub use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
    // R1CS interfaces and lc! macro
    pub use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    pub use ark_serialize;
    pub use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
}

pub use cut_and_choose::groth16 as groth16_cut_and_choose;
pub use groth16_cut_and_choose::{GarbledInstanceCommit, Garbler, OpenForInstance};
