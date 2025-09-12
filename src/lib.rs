pub mod ciphertext_hasher;
pub mod circuit;
mod core;
pub mod gadgets;
pub mod hashers;
mod hw;
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
    groth16::{Groth16ExecInput, Groth16ExecInputWires},
    groth16_verify, groth16_verify_compressed,
};
pub use hw::{hardware_aes_available, warn_if_software_aes};
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

mod groth16_cut_and_choose {
    #![allow(dead_code)]

    use std::thread::{self, JoinHandle};

    use crossbeam::channel;
    use log::info;
    use rand::Rng;
    use rayon::{iter::IntoParallelRefIterator, prelude::*};

    use crate::{
        AesNiHasher, CiphertextHashAcc, GarbleMode, GarbledWire, S,
        circuit::{CircuitBuilder, CircuitInput, StreamingResult},
        garbled_groth16,
    };

    const CAPACITY: usize = 160_000;

    pub type Seed = u64;
    pub type Commit = u128;

    pub struct Config<I: CircuitInput> {
        total: usize,
        to_evaluate: usize,
        input: I,
    }

    pub type GarbledInstance<I> =
        StreamingResult<GarbleMode<AesNiHasher, CiphertextHashAcc>, I, GarbledWire>;

    pub struct GarbledInstanceCommit {
        ciphertext_commit: Commit,
        input_labels_commit: Commit,
        output_labels_commit: Commit,
        constant_commits: Commit,
    }

    impl GarbledInstanceCommit {
        fn new<I: CircuitInput>(instance: &GarbledInstance<I>) -> Self {
            Self {
                ciphertext_commit: instance.ciphertext_handler_result,
                input_labels_commit: Self::commit(instance.input_labels()),
                output_labels_commit: Self::commit(&[instance.output_labels().clone()]),
                constant_commits: {
                    let mut h = CiphertextHashAcc::default();
                    for GarbledWire { label0, label1 } in instance.input_labels() {
                        h.update(*label0);
                        h.update(*label1);
                    }
                    h.finalize()
                },
            }
        }

        pub fn commit(inputs: &[GarbledWire]) -> Commit {
            let mut h = CiphertextHashAcc::default();
            inputs.iter().for_each(|GarbledWire { label0, label1 }| {
                h.update(*label0);
                h.update(*label1);
            });
            h.finalize()
        }
    }

    pub enum OpenForInstance {
        Open(usize, Seed),
        Regarbling {
            index: usize,
            garbling_thread: JoinHandle<()>,
            receiver: channel::Receiver<(usize, S)>,
        },
    }

    pub struct Garbler {
        instances: Vec<GarbledInstance<garbled_groth16::GarblerInput>>,
        seeds: Box<[Seed]>,
        config: Config<garbled_groth16::GarblerInput>,
    }

    impl Garbler {
        pub fn create(mut rng: impl Rng, config: Config<garbled_groth16::GarblerInput>) -> Self {
            let seeds = (0..config.total)
                .map(|_| rng.r#gen())
                .collect::<Box<[Seed]>>();

            Self {
                instances: seeds
                    .par_iter()
                    .map(|garbling_seed| {
                        let inputs = config.input.clone();
                        let hasher = CiphertextHashAcc::default();

                        info!("Starting garbling of Groth16 verification circuit...");

                        CircuitBuilder::streaming_garbling(
                            inputs.clone(),
                            CAPACITY,
                            *garbling_seed,
                            hasher,
                            garbled_groth16::verify,
                        )
                    })
                    .collect(),
                seeds,
                config,
            }
        }

        pub fn commit(&self) -> Vec<GarbledInstanceCommit> {
            self.instances
                .iter()
                .map(GarbledInstanceCommit::new)
                .collect()
        }

        pub fn open_commit(&self, indexes_to_evaluate: &[usize]) -> Vec<OpenForInstance> {
            self.seeds
                .iter()
                .enumerate()
                .map(|(index, garbling_seed)| {
                    if indexes_to_evaluate.contains(&index) {
                        let inputs = self.config.input.clone();

                        info!("Starting garbling of Groth16 verification circuit...");

                        let (sender, receiver) = crossbeam::channel::unbounded();
                        let inputs = inputs.clone();
                        let garbling_seed = *garbling_seed;

                        let garbling_thread = thread::spawn(move || {
                            let _: StreamingResult<
                                GarbleMode<AesNiHasher, _>,
                                garbled_groth16::GarblerInput,
                                GarbledWire,
                            > = CircuitBuilder::streaming_garbling(
                                inputs,
                                CAPACITY,
                                garbling_seed,
                                sender,
                                garbled_groth16::verify,
                            );
                        });

                        OpenForInstance::Regarbling {
                            index,
                            garbling_thread,
                            receiver,
                        }
                    } else {
                        OpenForInstance::Open(index, *garbling_seed)
                    }
                })
                .collect()
        }
    }
}
