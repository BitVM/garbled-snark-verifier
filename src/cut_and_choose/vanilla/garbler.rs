//! Garbler-side orchestration for the cut-and-choose Setup phase.
//!
//! This is the feature-agnostic core garbler. Protocol-specific extensions
//! (soldering, VSSS) are implemented in their respective modules.

use std::thread;

use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::types::{
    ChosenInstances, CommitPhaseOne, CommitPhaseTwo, GarbledInstance, GarblerStage, OpenForInstance,
};
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, GarbleMode, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, EncodeInput, StreamingMode,
        StreamingResult,
    },
    cut_and_choose::{Config, LabelCommitHasher, Seed},
    hashers::GateHasher,
};

/// Core garbler for the cut-and-choose protocol.
///
/// This struct manages the generation and opening of garbled circuit instances
/// for the cut-and-choose protocol. It is feature-agnostic - protocol-specific
/// extensions are implemented in the `vanilla`, `soldering`, and `vsss` modules.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "I: Serialize + serde::de::DeserializeOwned, GH: GateHasher")]
pub struct Garbler<I: CircuitInput + Clone, GH: GateHasher = AesCcrGateHasher> {
    stage: GarblerStage,
    instances: Vec<GarbledInstance<GH>>,
    config: Config<I>,
    live_capacity: usize,
    /// Nonce received from evaluator, stored for internal use in `commit_phase_two`
    nonce: Option<S>,
}

impl<I, GH> Garbler<I, GH>
where
    I: CircuitInput + Clone + Send + Sync + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>,
    GH: GateHasher + 'static,
    <I as CircuitInput>::WireRepr: Send,
    I: 'static,
{
    /// Create garbled instances in parallel using the provided circuit builder function.
    pub fn create<F>(mut rng: impl Rng, config: Config<I>, live_capacity: usize, builder: F) -> Self
    where
        F: Fn(&mut StreamingMode<GarbleMode<GH, Blake3AccumulatingHash>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let seeds = (0..config.total)
            .map(|_| rng.r#gen())
            .collect::<Box<[Seed]>>();

        // Use optimized thread pool internally
        let instances: Vec<_> = crate::cut_and_choose::get_optimized_pool().install(|| {
            seeds
                .par_iter()
                .enumerate()
                .map(|(index, garbling_seed)| {
                    let inputs = config.input.clone();
                    let hasher = Blake3AccumulatingHash::default();

                    let span = tracing::info_span!("garble", instance = index);
                    let _enter = span.enter();

                    info!("Starting garbling of circuit (cut-and-choose)");

                    let res: StreamingResult<
                        GarbleMode<GH, Blake3AccumulatingHash>,
                        I,
                        GarbledWire,
                    > = CircuitBuilder::streaming_garbling(
                        inputs,
                        live_capacity,
                        *garbling_seed,
                        hasher,
                        builder,
                    );

                    // Derive gate hasher seed from garbling seed (same derivation as GarbleMode::new)
                    let gate_hasher_seed = {
                        use rand::SeedableRng;
                        use rand_chacha::ChaChaRng;
                        let mut rng = ChaChaRng::seed_from_u64(*garbling_seed);
                        GH::from_rng(&mut rng).seed().clone()
                    };
                    GarbledInstance::<GH>::from_streaming_result(res, gate_hasher_seed)
                })
                .collect()
        });

        Self {
            stage: GarblerStage::Generating { seeds },
            instances,
            live_capacity,
            config,
            nonce: None,
        }
    }

    /// Produce the `Commit₁` transcript for every garbled instance (spec Step 1.2).
    pub fn commit_phase_one<LH>(&self) -> Vec<CommitPhaseOne<GH, LH>>
    where
        LH: LabelCommitHasher,
    {
        self.instances
            .iter()
            .map(CommitPhaseOne::<GH, LH>::from_instance)
            .collect()
    }

    /// Produce the `Commit₂` transcript (nonce-injected input commitments; spec Step 1.4).
    /// Stores the nonce internally for use in derived operations.
    /// If called multiple times, the nonce must be the same; otherwise panics.
    pub fn commit_phase_two<LH>(&mut self, nonce: S) -> Vec<CommitPhaseTwo<LH>>
    where
        LH: LabelCommitHasher,
    {
        if let Some(existing_nonce) = self.nonce {
            if existing_nonce != nonce {
                panic!("Different nonce provided to commit_phase_two; nonce must be consistent");
            }
        } else {
            self.nonce = Some(nonce);
        }

        self.instances
            .iter()
            .map(|instance| CommitPhaseTwo::<LH>::from_instance(instance, self.nonce.unwrap()))
            .collect()
    }

    /// Get both phase one and phase two commitments.
    pub fn get_commitment<LH: LabelCommitHasher>(
        &self,
    ) -> Option<crate::cut_and_choose::Commitment<GH, LH>> {
        self.nonce.map(|nonce| {
            let phase_one = self
                .instances
                .iter()
                .map(CommitPhaseOne::<GH, LH>::from_instance)
                .collect();

            let phase_two = self
                .instances
                .iter()
                .map(|instance| CommitPhaseTwo::<LH>::from_instance(instance, nonce))
                .collect();

            (phase_one, phase_two)
        })
    }

    /// Get finalized indexes (available after `open_commit`).
    pub fn finalized_indexes(&self) -> Option<&[usize]> {
        match &self.stage {
            GarblerStage::Generating { .. } => None,
            GarblerStage::PreparedForEval { finalized_indexes } => Some(finalized_indexes),
        }
    }

    /// Open commitment without ciphertext handlers.
    pub fn open_commit_without_ciphertexts(
        &mut self,
        mut indexes_to_finalize: Vec<usize>,
    ) -> ChosenInstances {
        indexes_to_finalize.sort();
        indexes_to_finalize.dedup();

        assert_eq!(indexes_to_finalize.len(), self.config().finalized_count());

        let seeds = self
            .stage
            .next_stage(indexes_to_finalize.clone().into_boxed_slice());

        let mut result = ChosenInstances {
            revealed: vec![],
            finalized: vec![],
        };

        seeds
            .into_vec()
            .into_iter()
            .enumerate()
            .for_each(|(index, seed)| {
                if indexes_to_finalize.binary_search(&index).is_ok() {
                    result.finalized.push((index, seed));
                } else {
                    result.revealed.push((index, seed));
                }
            });

        result
    }

    /// Open commitments with ciphertext handlers for finalized instances.
    pub fn open_commit<F, CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        mut indexes_to_finalize: Vec<(usize, CTH)>,
        builder: F,
    ) -> Vec<OpenForInstance>
    where
        F: 'static
            + Fn(&mut StreamingMode<GarbleMode<GH, CTH>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
        I: EncodeInput<GarbleMode<GH, CTH>>,
    {
        let seeds = self
            .stage
            .next_stage(indexes_to_finalize.iter().map(|(i, _)| *i).collect());

        seeds
            .iter()
            .enumerate()
            .map(|(index, garbling_seed)| {
                let pos = indexes_to_finalize
                    .iter()
                    .position(|(index_to_eval, _sender)| index_to_eval.eq(&index));

                if let Some(pos) = pos {
                    let sender = indexes_to_finalize.remove(pos).1;

                    let inputs = self.config.input.clone();
                    let garbling_seed = *garbling_seed;

                    let live_capacity = self.live_capacity;

                    let garbling_thread = thread::spawn(move || {
                        let _span =
                            tracing::info_span!("regarble2send", instance = index).entered();

                        info!("Starting");

                        let _: StreamingResult<_, I, GarbledWire> =
                            CircuitBuilder::<GarbleMode<GH, _>>::streaming_garbling(
                                inputs,
                                live_capacity,
                                garbling_seed,
                                sender,
                                builder,
                            );
                    });

                    OpenForInstance::Closed {
                        index,
                        garbling_thread,
                    }
                } else {
                    OpenForInstance::Open(index, *garbling_seed)
                }
            })
            .collect()
    }

    /// Return the constant labels for true as u128 for a given instance.
    pub fn true_wire_constant_for(&self, index: usize) -> u128 {
        self.instances[index]
            .true_wire_constant
            .select(true)
            .to_u128()
    }

    /// Return the constant labels for false as u128 for a given instance.
    pub fn false_wire_constant_for(&self, index: usize) -> u128 {
        self.instances[index]
            .false_wire_constant
            .select(false)
            .to_u128()
    }

    /// Return a clone of the input garbled labels for a given instance.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.instances[index].input_wire_values.clone()
    }

    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    pub fn stage(&self) -> &GarblerStage {
        &self.stage
    }

    pub fn output_wire(&self, index: usize) -> Option<&GarbledWire> {
        self.instances.get(index).map(|gw| &gw.output_wire_values)
    }

    /// Get the stored nonce (set during `commit_phase_two`).
    pub fn nonce(&self) -> Option<S> {
        self.nonce
    }

    /// Get the live capacity used for garbling.
    pub fn live_capacity(&self) -> usize {
        self.live_capacity
    }

    /// Get reference to instances (for test-utils).
    #[cfg(feature = "test-utils")]
    pub fn instances(&self) -> &[GarbledInstance<GH>] {
        &self.instances
    }
}

#[cfg(feature = "test-utils")]
mod test_utils {
    use serde::{Deserialize, Serialize, de::DeserializeOwned};

    use super::*;

    impl<I, GH> Garbler<I, GH>
    where
        I: CircuitInput + Clone,
        GH: GateHasher,
    {
        pub fn from_raw_parts(
            stage: GarblerStage,
            instances: Vec<GarbledInstance<GH>>,
            config: Config<I>,
            live_capacity: usize,
            nonce: Option<S>,
        ) -> Self {
            Self {
                stage,
                instances,
                config,
                live_capacity,
                nonce,
            }
        }

        pub fn into_raw_parts(
            self,
        ) -> (
            GarblerStage,
            Vec<GarbledInstance<GH>>,
            Config<I>,
            usize,
            Option<S>,
        ) {
            (
                self.stage,
                self.instances,
                self.config,
                self.live_capacity,
                self.nonce,
            )
        }
    }

    /// Raw parts for constructing/deconstructing a Garbler.
    ///
    /// This is the wrapper-level API for test utilities to deconstruct
    /// and reconstruct Garbler instances.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(bound = "I: CircuitInput + Clone + Serialize + DeserializeOwned, GH: GateHasher")]
    pub struct GarblerRawParts<I, GH>
    where
        I: CircuitInput + Clone,
        GH: GateHasher,
    {
        pub stage: GarblerStage,
        pub instances: Vec<GarbledInstance<GH>>,
        pub config: Config<I>,
        pub live_capacity: usize,
        pub nonce: Option<S>,
    }

    impl<I, GH> From<GarblerRawParts<I, GH>> for Garbler<I, GH>
    where
        I: CircuitInput + Clone,
        GH: GateHasher,
    {
        fn from(parts: GarblerRawParts<I, GH>) -> Self {
            Self::from_raw_parts(
                parts.stage,
                parts.instances,
                parts.config,
                parts.live_capacity,
                parts.nonce,
            )
        }
    }

    impl<I, GH> From<Garbler<I, GH>> for GarblerRawParts<I, GH>
    where
        I: CircuitInput + Clone,
        GH: GateHasher,
    {
        fn from(garbler: Garbler<I, GH>) -> Self {
            let (stage, instances, config, live_capacity, nonce) = garbler.into_raw_parts();
            Self {
                stage,
                instances,
                config,
                live_capacity,
                nonce,
            }
        }
    }
}

#[cfg(feature = "test-utils")]
pub use test_utils::*;
