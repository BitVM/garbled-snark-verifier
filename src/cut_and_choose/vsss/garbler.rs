//! VSSS Garbler implementation for the cut-and-choose protocol.
//!
//! This module contains the VsssGarbler which uses Verifiable Secret Sharing Scheme
//! for the cut-and-choose protocol.

use std::thread;

use ark_secp256k1::Fr;
use itertools::Itertools;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::{
    Canonical, FinalizeChallenge, FinalizedVsssInstance, OpenVsssInstance, Polynomial, Secp256k1,
    VsssCommit, transpose, wide_garbling::GarbledWideLabelTable,
};
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, GarbleMode, GarbledWire, WireId,
    circuit::{
        CiphertextHandler, CircuitBuilder, CircuitInput, EncodeInput, StreamingMode,
        StreamingResult,
    },
    cut_and_choose::{
        Config, LabelCommitHasher, Seed,
        vanilla::{CommitPhaseOne, GarbledInstance, GarblerStage},
    },
    hashers::GateHasher,
};

pub type InstanceWideLabelLookup = Vec<GarbledWideLabelTable>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "I: Serialize + serde::de::DeserializeOwned, GH: GateHasher")]
pub struct Garbler<I: CircuitInput + Clone, GH: GateHasher = AesCcrGateHasher> {
    stage: GarblerStage,
    instances: Vec<GarbledInstance<GH>>,
    pub config: Config<I>,
    live_capacity: usize,
    polynomials: Vec<Polynomial<Canonical<Fr>>>,
    pub wide_label_tables: Vec<InstanceWideLabelLookup>,
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
        let mut x = 0;
        let allocated = config.input().allocate(|| {
            x += 1;
            WireId(x)
        });
        let num_inputs = <I as CircuitInput>::collect_wire_ids(&allocated).len();

        let polynomials = (0..num_inputs)
            .chunks(8)
            .into_iter()
            .flat_map(|chunk| {
                let num_bits = chunk.count();
                let num_labels = 2u32.pow(num_bits as u32);
                (0..num_labels)
                    .map(|_| Polynomial::rand(&mut rng, config.total - config.finalized_count()))
                    .collect_vec()
            })
            .collect_vec();

        let coeffs = polynomials
            .iter()
            .map(|polynomial| {
                polynomial
                    .shares(config.total)
                    .into_iter()
                    .map(|(_, share)| share)
                    .collect_vec()
            })
            .collect_vec();

        let instance_wide_labels = transpose(&coeffs);

        let seeds = (0..config.total)
            .map(|_| rng.r#gen())
            .collect::<Box<[Seed]>>();

        // Use optimized thread pool internally
        let ret: Vec<_> = crate::cut_and_choose::get_optimized_pool().install(|| {
            seeds
                .iter()
                .zip(instance_wide_labels.iter())
                .collect_vec()
                .par_iter()
                .enumerate()
                .map(|(index, (garbling_seed, wide_labels))| {
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
                        **garbling_seed,
                        hasher,
                        builder,
                    );

                    // Derive gate hasher seed from garbling seed (same derivation as GarbleMode::new)
                    let gate_hasher_seed = {
                        use rand::SeedableRng;
                        use rand_chacha::ChaChaRng;
                        let mut rng = ChaChaRng::seed_from_u64(**garbling_seed);
                        GH::from_rng(&mut rng).seed().clone()
                    };
                    let instance =
                        GarbledInstance::<GH>::from_streaming_result(res, gate_hasher_seed);
                    let tables =
                        GarbledWideLabelTable::build_all(wide_labels, &instance.input_wire_values);

                    (instance, tables)
                })
                .collect()
        });

        let (instances, wide_label_tables): (Vec<_>, Vec<_>) = ret.into_iter().unzip();

        Self {
            stage: GarblerStage::Generating { seeds },
            instances,
            live_capacity,
            config,
            polynomials: polynomials
                .into_iter()
                .map(Polynomial::to_canonical)
                .collect(),
            wide_label_tables,
        }
    }

    /// Produce the `Commit₁` transcript for every garbled instance (spec Step 1.2).
    pub fn commit<LH>(&self) -> VsssCommit<GH, LH>
    where
        LH: LabelCommitHasher,
    {
        let secp = Secp256k1::new();

        let polynomials = self
            .polynomials
            .iter()
            .map(Polynomial::from_canonical)
            .collect_vec();

        let (share_commits, polynomial_commits): (Vec<_>, Vec<_>) =
            crate::cut_and_choose::get_optimized_pool().install(|| {
                polynomials
                    .par_iter()
                    .map(|polynomial| {
                        let share_commits = polynomial
                            .share_commits(&secp, self.config.total)
                            .to_canonical();
                        let polynomial_commits =
                            polynomial.coefficient_commits(&secp).to_canonical();
                        (share_commits, polynomial_commits)
                    })
                    .unzip()
            });

        let circuit_commits = self
            .instances
            .iter()
            .map(|x| CommitPhaseOne::<GH, LH>::from_instance(x))
            .collect_vec();

        let garbling_table_commits = self
            .wide_label_tables
            .iter()
            .map(|x| GarbledWideLabelTable::aggregate_hash(x))
            .collect();
        VsssCommit {
            circuit_commits,
            share_commits,
            polynomial_commits,
            garbling_table_commits,
        }
    }

    pub fn open_commit<F, CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        mut indexes_to_finalize: Vec<FinalizeChallenge<CTH>>,
        builder: F,
    ) -> (Vec<OpenVsssInstance>, Vec<FinalizedVsssInstance>)
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
            .next_stage(indexes_to_finalize.iter().map(|x| x.index).collect());

        let shares = self
            .polynomials
            .iter()
            .map(|x| x.from_canonical().shares(self.config.total))
            .collect_vec();

        let mut finalized_instance_data = Vec::new();
        let mut opened_instance_data = Vec::new();

        // TODO #37 Since at this point the number but finalization is no more than 7, we just run
        // threads here, without rayon
        seeds
            .iter()
            .enumerate()
            .map(|(index, garbling_seed)| {
                let pos = indexes_to_finalize.iter().position(|x| x.index == index);

                if let Some(pos) = pos {
                    let finalization_info = indexes_to_finalize.remove(pos);
                    // not revealed.
                    let ciphertext_handler = finalization_info.ciphertext_handler;

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
                                ciphertext_handler,
                                builder,
                            );
                    });

                    finalized_instance_data.push(FinalizedVsssInstance {
                        index,
                        wide_label_lookup: self.wide_label_tables[index].clone(),
                        garbling_thread,
                    });
                } else {
                    // reveal share
                    let shares = shares
                        .iter()
                        .map(|x| {
                            let share = x[index];
                            assert_eq!(index, share.0); // sanity check
                            Canonical(share.1)
                        })
                        .collect_vec();
                    opened_instance_data.push(OpenVsssInstance {
                        index,
                        seed: *garbling_seed,
                        shares,
                    });
                }
            })
            .collect_vec();
        (opened_instance_data, finalized_instance_data)
    }

    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    /// Return a clone of the input garbled labels for a given instance.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.instances[index].input_wire_values.clone()
    }

    pub fn wide_labels_for(&self, index: usize) -> Vec<Fr> {
        self.polynomials
            .iter()
            .map(|x| x.from_canonical().shares(self.config.total)[index].1)
            .collect_vec()
    }
}
