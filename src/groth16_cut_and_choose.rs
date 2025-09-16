#![allow(dead_code)]

use std::{
    collections::HashMap,
    fs,
    fs::File,
    io::{BufWriter, Write},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
    thread::{self, JoinHandle},
};

use crossbeam::channel;
use itertools::Itertools;
use rand::Rng;
use rayon::{ThreadPool, ThreadPoolBuilder, iter::IntoParallelRefIterator, prelude::*};
use tracing::{error, info};

use crate::{
    AesNiHasher, CiphertextHashAcc, EvaluatedWire, GarbleMode, GarbledWire, S,
    circuit::{
        CircuitBuilder, CircuitInput, StreamingResult, ciphertext_source, modes::EvaluateMode,
    },
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

        // Use optimized thread pool internally
        let pool = get_optimized_pool();
        let instances = pool.install(|| {
            seeds
                .par_iter()
                .enumerate()
                .map(|(index, garbling_seed)| {
                    let inputs = config.input.clone();
                    let hasher = CiphertextHashAcc::default();

                    let span = tracing::info_span!("garble", instance = index);
                    let _enter = span.enter();

                    info!("Starting garbling of Groth16 verification circuit");

                    CircuitBuilder::streaming_garbling(
                        inputs,
                        CAPACITY,
                        *garbling_seed,
                        hasher,
                        garbled_groth16::verify_compressed,
                    )
                })
                .collect()
        });

        Self {
            instances,
            seeds,
            config,
        }
    }

    pub fn commit(&self) -> Vec<GarbledInstanceCommit> {
        // Build commits in parallel; independent per instance
        self.instances
            .par_iter()
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
                        // Tag this second garbling stream to appear in logs as part of regarbling phase
                        let span = tracing::info_span!("garble2evaluation", instance = index);
                        let _enter = span.enter();
                        info!("Starting garble2evaluation of Groth16 verification circuit");
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

        // Ensure output directory exists
        if let Err(e) = fs::create_dir_all(folder_for_ciphertexts) {
            error!(
                "failed to create output dir {:?}: {e}",
                folder_for_ciphertexts
            );
            return Err(());
        }

        for (index, rx) in receivers {
            let path: PathBuf = folder_for_ciphertexts.join(format!("gc_{}.bin", index));
            rayon::spawn(move || {
                let file = File::create(&path).expect("create ciphertext file");
                // Larger buffer to reduce syscalls
                let mut w = BufWriter::with_capacity(1 << 20, file);
                while let Ok((gate_id, s)) = rx.recv() {
                    let gid = gate_id as u64;
                    let _ = w.write_all(&gid.to_le_bytes());
                    let _ = w.write_all(&s.to_bytes());
                }
                let _ = w.flush();
            });
        }

        // Use optimized thread pool for parallel regarbling
        let pool = get_optimized_pool();
        let all_ok = pool.install(|| {
            seeds.par_iter().all(|(index, garbling_seed)| {
                let inputs = self.config.input.clone();
                let hasher = CiphertextHashAcc::default();

                let span = tracing::info_span!("regarble", instance = index);
                let _enter = span.enter();

                info!("Starting regarbling of Groth16 verification circuit");

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
            })
        });

        if all_ok { Ok(()) } else { Err(()) }
    }
}

impl Evaluator {
    /// Evaluate all finalized instances from saved ciphertext files in `folder`.
    /// Returns `(index, EvaluatedWire)` pairs.
    pub fn evaluate_from_saved_all(
        cases: Vec<(
            usize,
            garbled_groth16::EvaluatorCompressedInput,
            (u128, u128),
        )>,
        capacity: usize,
        folder: &Path,
    ) -> Vec<(usize, EvaluatedWire)> {
        // Use optimized thread pool for parallel evaluation
        let pool = get_optimized_pool();
        pool.install(|| {
            cases
                .into_par_iter()
                .map(|(index, eval_input, (true_const, false_const))| {
                    let file_path = folder.join(format!("gc_{}.bin", index));
                    let source = ciphertext_source::FileSource::from_path(file_path)
                        .expect("open ciphertext file");

                    let result =
                        CircuitBuilder::<EvaluateMode<AesNiHasher, _>>::streaming_evaluation(
                            eval_input,
                            capacity,
                            true_const,
                            false_const,
                            source,
                            garbled_groth16::verify_compressed,
                        );

                    (index, result.output_value)
                })
                .collect()
        })
    }
}

// ============================================================================
// Threading utilities - isolated CPU affinity optimization (internal use only)
// ============================================================================

use std::sync::OnceLock;

static OPTIMIZED_POOL: OnceLock<Arc<ThreadPool>> = OnceLock::new();

/// Get the singleton optimized thread pool, creating it if necessary.
/// This is for internal use only - not exposed in the public API.
fn get_optimized_pool() -> &'static Arc<ThreadPool> {
    OPTIMIZED_POOL.get_or_init(|| {
        let n_threads = num_cpus::get_physical().max(1);
        Arc::new(build_pinned_pool(n_threads))
    })
}

/// Build a thread pool with threads pinned to specific CPU cores.
/// This reduces thread migrations and can improve performance for CPU-intensive tasks.
fn build_pinned_pool(n_threads: usize) -> ThreadPool {
    let chosen_cores = select_cores_for_affinity(n_threads);

    ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .start_handler(move |thread_idx| {
            // Try to pin this thread to its assigned core
            if let Some(core_id) = chosen_cores.get(thread_idx).cloned() {
                // Silently ignore affinity errors (may not be supported on all systems)
                let _ = core_affinity::set_for_current(core_id);
            }
        })
        .build()
        .unwrap_or_else(|_| {
            // Fallback to default thread pool if pinned pool creation fails
            ThreadPoolBuilder::new()
                .num_threads(n_threads)
                .build()
                .expect("failed to create fallback thread pool")
        })
}

/// Select CPU cores for thread affinity.
/// Strategy:
/// - If we have at least 2x cores as threads, use every other core (avoid hyperthreads)
/// - Otherwise, use the first N cores available
/// - Returns empty vector if core detection fails (affinity will be skipped)
fn select_cores_for_affinity(n: usize) -> Vec<core_affinity::CoreId> {
    match core_affinity::get_core_ids() {
        Some(cores) if cores.len() >= 2 * n => {
            // Skip hyperthreads by taking every other core
            cores.into_iter().step_by(2).take(n).collect()
        }
        Some(cores) => {
            // Use first N cores available
            cores.into_iter().take(n).collect()
        }
        None => {
            // Core detection failed - affinity will not be set
            Vec::new()
        }
    }
}
