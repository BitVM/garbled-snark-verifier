#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
    thread::{self, JoinHandle},
};

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

#[derive(Clone, Debug)]
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
    config: Config<garbled_groth16::GarblerInput>,
    /// Receivers for ciphertext streams keyed by instance index (filled when building senders)
    receivers: HashMap<usize, channel::Receiver<(usize, S)>>,
}

impl Evaluator {
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(
        mut rng: impl Rng,
        config: Config<garbled_groth16::GarblerInput>,
        commits: Vec<GarbledInstanceCommit>,
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
            to_finalize: idxs.into_boxed_slice(),
            config,
            receivers: HashMap::new(),
        }
    }

    pub fn get_indexes_to_finalize(&self) -> &[usize] {
        &self.to_finalize
    }

    /// Create channels for all indices selected to finalize.
    /// Returns the list of (index, sender) pairs to pass to Garbler::open_commit.
    /// Stores matching receivers internally for later ciphertext collection.
    pub fn make_finalize_senders(&mut self) -> Vec<(usize, channel::Sender<(usize, S)>)> {
        let mut out = Vec::with_capacity(self.to_finalize.len());
        for &idx in self.to_finalize.iter() {
            let (tx, rx) = channel::unbounded::<(usize, S)>();
            self.receivers.insert(idx, rx);
            out.push((idx, tx));
        }
        out
    }

    // 1. Check that `OpenForInstance` matches the ones stored in `self.to_finalize`.
    // 2. For `Open` run `streaming_garbling` via rayon, where at the end it checks for a match with saved commits
    // 3. For `Closed` - receive ciphertexts and save them into folder in separate files with name `gc_{index}.bin`
    #[allow(clippy::result_unit_err)]
    pub fn regarbling(
        &self,
        input: Vec<OpenForInstance>,
        folder_for_ciphertexts: &Path,
    ) -> Result<(), ()> {
        // Basic shape checks
        if input.len() != self.config.total {
            return Err(());
        }

        // Validate closed set matches to_finalize (both elements and count)
        let mut closed_count = 0usize;
        let selected_closed: HashSet<usize> = input
            .iter()
            .filter_map(|e| match e {
                OpenForInstance::Closed { index, .. } => {
                    closed_count += 1;
                    Some(*index)
                }
                _ => None,
            })
            .collect();

        let expected_closed: HashSet<usize> = self.to_finalize.iter().copied().collect();
        if selected_closed != expected_closed || closed_count != self.to_finalize.len() {
            return Err(());
        }

        // Ensure output folder exists
        if let Err(_e) = fs::create_dir_all(folder_for_ciphertexts) {
            return Err(());
        }

        // Determine open set now (we will consume `input` below for writers)
        let open_items: Vec<(usize, Seed)> = input
            .iter()
            .filter_map(|e| match e {
                OpenForInstance::Open(index, seed) => Some((*index, *seed)),
                _ => None,
            })
            .collect();

        // 1) For closed instances, start receiving/saving immediately (large streams)
        // This runs concurrently with re-garbling open instances below.
        let mut writer_threads: Vec<(usize, JoinHandle<Result<u128, ()>>)> = Vec::new();
        let mut garble_threads: Vec<(usize, JoinHandle<()>)> = Vec::new();

        for entry in input.into_iter() {
            if let OpenForInstance::Closed {
                index,
                garbling_thread,
            } = entry
            {
                // Lookup receiver; if missing, protocol misuse
                let recv = match self.receivers.get(&index) {
                    Some(r) => r.clone(),
                    None => return Err(()),
                };
                garble_threads.push((index, garbling_thread));

                let path = folder_for_ciphertexts.join(format!("gc_{}.bin", index));
                // Use rayon
                // Make check of commit internally
                let handle = thread::spawn(move || -> Result<u128, ()> {
                    let file = File::create(&path).map_err(|_| ())?;
                    // Larger buffer to reduce syscall overhead while keeping memory bounded
                    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
                    let mut hasher = CiphertextHashAcc::default();

                    let mut rec_buf = [0u8; 8 + 16];
                    // Stream until sender closes
                    while let Ok((gate_id, ct)) = recv.recv() {
                        hasher.update(ct);
                        // Pack gate_id (LE u64) + ciphertext bytes into a single write
                        rec_buf[..8].copy_from_slice(&(gate_id as u64).to_le_bytes());
                        rec_buf[8..].copy_from_slice(&ct.to_bytes());
                        writer.write_all(&rec_buf).map_err(|_| ())?;
                    }

                    writer.flush().map_err(|_| ())?;
                    Ok(hasher.finalize())
                });

                writer_threads.push((index, handle));
            }
        }

        // 2) Re-garble open instances concurrently while writers are flushing to disk
        let inputs = self.config.input.clone();
        let garble_ok = open_items.par_iter().all(|(index, seed)| {
            let hasher = CiphertextHashAcc::default();
            let res: GarbledInstance<garbled_groth16::GarblerInput> =
                CircuitBuilder::streaming_garbling(
                    inputs.clone(),
                    CAPACITY,
                    *seed,
                    hasher,
                    garbled_groth16::verify,
                );
            let actual = GarbledInstanceCommit::new(&res);
            let expected = &self.commits[*index];

            actual.ciphertext_commit == expected.ciphertext_commit
                && actual.input_labels_commit == expected.input_labels_commit
                && actual.output_label1_commit == expected.output_label1_commit
                && actual.output_label0_commit == expected.output_label0_commit
                && actual.constant_commits == expected.constant_commits
        });

        if !garble_ok {
            return Err(());
        }

        // 3) Verify hashes and join IO writers
        for (index, handle) in writer_threads.into_iter() {
            let computed = handle.join().map_err(|_| ())??;
            if computed != self.commits[index].ciphertext_commit {
                return Err(());
            }
        }

        // 4) Join garbling threads to ensure they finished cleanly
        for (_index, handle) in garble_threads.into_iter() {
            handle.join().map_err(|_| ())?;
        }

        Ok(())
    }
}
