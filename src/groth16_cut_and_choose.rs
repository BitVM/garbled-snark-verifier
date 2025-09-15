#![allow(dead_code)]

use std::{
    collections::HashMap,
    mem,
    path::Path,
    thread::{self, JoinHandle},
};

use crossbeam::channel;
use itertools::Itertools;
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
    to_finalize: usize,
    input: I,
}

impl<I: CircuitInput> Config<I> {
    pub fn new(total: usize, to_finalize: usize, input: I) -> Self {
        Self {
            total,
            to_finalize,
            input,
        }
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn to_finalize(&self) -> usize {
        self.to_finalize
    }

    pub fn input(&self) -> &I {
        &self.input
    }
}

pub type GarbledInstance<I> =
    StreamingResult<GarbleMode<AesNiHasher, CiphertextHashAcc>, I, GarbledWire>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GarbledInstanceCommit {
    ciphertext_commit: Commit,
    input_labels_commit: Commit,
    // Separate commits for output labels: one for label1 and one for label0
    output_label1_commit: Commit,
    output_label0_commit: Commit,
    constant_commits: Commit,
}

impl GarbledInstanceCommit {
    fn new<I: CircuitInput>(instance: &GarbledInstance<I>) -> Self {
        Self {
            ciphertext_commit: instance.ciphertext_handler_result,
            input_labels_commit: Self::commit(instance.input_labels()),
            // Commit output labels separately for 1 and 0 selections
            output_label1_commit: Self::commit_label1(&[instance.output_labels().clone()]),
            output_label0_commit: Self::commit_label0(&[instance.output_labels().clone()]),
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

    fn commit_label1(inputs: &[GarbledWire]) -> Commit {
        let mut h = CiphertextHashAcc::default();
        for GarbledWire { label1, .. } in inputs.iter() {
            h.update(*label1);
        }
        h.finalize()
    }

    fn commit_label0(inputs: &[GarbledWire]) -> Commit {
        let mut h = CiphertextHashAcc::default();
        for GarbledWire { label0, .. } in inputs.iter() {
            h.update(*label0);
        }
        h.finalize()
    }

    pub fn output_commit_label1(&self) -> Commit {
        self.output_label1_commit
    }

    pub fn output_commit_label0(&self) -> Commit {
        self.output_label0_commit
    }
}

pub enum OpenForInstance {
    Open(usize, Seed),
    Closed {
        index: usize,
        garbling_thread: JoinHandle<()>,
    },
}

pub struct Garbler {
    instances: Vec<GarbledInstance<garbled_groth16::GarblerCompressedInput>>,
    seeds: Box<[Seed]>,
    config: Config<garbled_groth16::GarblerCompressedInput>,
}

impl Garbler {
    pub fn create(
        mut rng: impl Rng,
        config: Config<garbled_groth16::GarblerCompressedInput>,
    ) -> Self {
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
                        garbled_groth16::verify_compressed,
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

    pub fn open_commit(
        &self,
        mut indexes_to_finalize: Vec<(usize, channel::Sender<(usize, S)>)>,
    ) -> Vec<OpenForInstance> {
        self.seeds
            .iter()
            .enumerate()
            .map(|(index, garbling_seed)| {
                let pos = indexes_to_finalize
                    .iter()
                    .position(|(index_to_eval, _sender)| index_to_eval.eq(&index));

                if let Some(pos) = pos {
                    let (_, sender) = indexes_to_finalize.remove(pos);
                    let inputs = self.config.input.clone();

                    let inputs = inputs.clone();
                    let garbling_seed = *garbling_seed;

                    let garbling_thread = thread::spawn(move || {
                        let _: StreamingResult<
                            GarbleMode<AesNiHasher, _>,
                            garbled_groth16::GarblerCompressedInput,
                            GarbledWire,
                        > = CircuitBuilder::streaming_garbling(
                            inputs,
                            CAPACITY,
                            garbling_seed,
                            sender,
                            garbled_groth16::verify_compressed,
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

    /// Return the constant labels for true/false as u128 words for a given instance.
    /// These must be provided to the evaluator for correct decryption.
    pub fn constants_for(&self, index: usize) -> (u128, u128) {
        let inst = &self.instances[index];
        let t = inst.true_wire_constant.select(true).to_u128();
        let f = inst.false_wire_constant.select(false).to_u128();
        (t, f)
    }

    /// Return a clone of the input garbled labels for a given instance.
    /// The evaluator combines these with the SNARK proof to build EvaluatorInput.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.instances[index].input_wire_values.clone()
    }
}

pub struct Evaluator {
    commits: Vec<GarbledInstanceCommit>,
    to_finalize: Box<[usize]>,
    config: Config<garbled_groth16::GarblerCompressedInput>,
    /// Receivers for ciphertext streams keyed by instance index (filled when building senders)
    receivers: HashMap<usize, channel::Receiver<(usize, S)>>,
}

impl Evaluator {
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(
        mut rng: impl Rng,
        config: Config<garbled_groth16::GarblerCompressedInput>,
        commits: Vec<GarbledInstanceCommit>,
        receivers: Vec<channel::Receiver<(usize, S)>>,
    ) -> Self {
        assert!(
            config.to_finalize <= config.total,
            "to_finalize must be <= total"
        );

        // Sample without replacement: shuffle 0..total and take first `to_finalize`
        let mut idxs: Vec<usize> = (0..config.total).collect();
        // Fisher-Yates with unbiased rng
        for i in (1..idxs.len()).rev() {
            let j = rng.gen_range(0..=i);
            idxs.swap(i, j);
        }
        idxs.truncate(config.to_finalize);
        idxs.sort_unstable();

        Self {
            commits,
            receivers: idxs.iter().copied().zip_eq(receivers).collect(),
            to_finalize: idxs.into_boxed_slice(),
            config,
        }
    }

    pub fn get_indexes_to_finalize(&self) -> &[usize] {
        &self.to_finalize
    }

    // 1. Check that `OpenForInstance` matches the ones stored in `self.to_finalize`.
    // 2. For `Open` run `streaming_garbling` via rayon, where at the end it checks for a match with saved commits
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling(
        mut self,
        seeds: Vec<(usize, Seed)>,
        folder_for_ciphertexts: &Path,
    ) -> Result<(), ()> {
        let receivers = mem::take(&mut self.receivers);

        rayon::spawn(|| {
            todo!("
                Get a ciphertext sequentially from all receivers and save it to files as efficiently as possible
                Considering that each one of them loads 3 billion ciphertexts
            ")
        });

        seeds.par_iter().all(|(index, garbling_seed)| {
            let inputs = self.config.input.clone();
            let hasher = CiphertextHashAcc::default();

            info!("Starting garbling of Groth16 verification circuit...");

            let res: StreamingResult<
                GarbleMode<AesNiHasher, _>,
                garbled_groth16::GarblerCompressedInput,
                GarbledWire,
            > = CircuitBuilder::streaming_garbling(
                inputs.clone(),
                CAPACITY,
                *garbling_seed,
                hasher,
                garbled_groth16::verify_compressed,
            );

            let regarbling_commit = GarbledInstanceCommit::new(&res);
            let received_commit = &self.commits[*index];

            &regarbling_commit == received_commit
        });

        todo!()
    }
}
