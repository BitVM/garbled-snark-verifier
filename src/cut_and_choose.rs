#![allow(dead_code)]

use std::{
    collections::HashMap,
    fs::{self, File},
    io::{BufWriter, Write},
    mem,
    path::{Path, PathBuf},
    sync::Arc,
    thread::{self, JoinHandle},
};

use rand::Rng;
use rayon::{ThreadPool, ThreadPoolBuilder, iter::IntoParallelRefIterator, prelude::*};
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{
    AesNiHasher, CiphertextHashAcc, EvaluatedWire, GarbleMode, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, EncodeInput,
        StreamingMode, StreamingResult, ciphertext_source, modes::EvaluateMode,
    },
};

/// Default live wires capacity used for streaming garbling/evaluation.
pub const DEFAULT_CAPACITY: usize = 150_000;

pub type Seed = u64;
pub type Commit = u128;

/// Protocol configuration shared by Garbler/Evaluator.
#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct GarbledInstance {
    /// Constant to represent false wire constant
    ///
    /// Necessary to restart the scheme and consistency
    pub false_wire_constant: GarbledWire,

    /// Constant to represent true wire constant
    ///
    /// Necessary to restart the scheme and consistency
    pub true_wire_constant: GarbledWire,

    /// Output `WireId` in return order
    pub output_wire_values: GarbledWire,

    /// Values of the input Wires, which were fed to the circuit input
    pub input_wire_values: Vec<GarbledWire>,

    pub ciphertext_handler_result: u128,
}

impl<I: CircuitInput>
    From<StreamingResult<GarbleMode<AesNiHasher, CiphertextHashAcc>, I, GarbledWire>>
    for GarbledInstance
{
    fn from(
        res: StreamingResult<GarbleMode<AesNiHasher, CiphertextHashAcc>, I, GarbledWire>,
    ) -> Self {
        GarbledInstance {
            false_wire_constant: res.false_wire_constant,
            true_wire_constant: res.true_wire_constant,
            output_wire_values: res.output_value,
            input_wire_values: res.input_wire_values,
            ciphertext_handler_result: res.ciphertext_handler_result,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GarbledInstanceCommit {
    ciphertext_commit: Commit,
    input_labels_commit: Commit,
    // Separate commits for output labels: one for label1 and one for label0
    output_label1_commit: Commit,
    output_label0_commit: Commit,
    true_constant_commit: Commit,
    false_constant_commit: Commit,
}

impl GarbledInstanceCommit {
    pub fn new(instance: &GarbledInstance) -> Self {
        Self {
            ciphertext_commit: instance.ciphertext_handler_result,
            input_labels_commit: Self::commit_garbled_wires(&instance.input_wire_values),

            output_label1_commit: Self::commit_label1(&instance.output_wire_values),

            output_label0_commit: Self::commit_label0(&instance.output_wire_values),

            true_constant_commit: CiphertextHashAcc::digest(
                instance.true_wire_constant.select(true),
            ),
            false_constant_commit: CiphertextHashAcc::digest(
                instance.false_wire_constant.select(false),
            ),
        }
    }

    pub fn commit_garbled_wires(inputs: &[GarbledWire]) -> Commit {
        let mut h = CiphertextHashAcc::default();
        inputs.iter().for_each(|GarbledWire { label0, label1 }| {
            h.update(*label0);
            h.update(*label1);
        });
        h.finalize()
    }

    fn commit_label1(input: &GarbledWire) -> Commit {
        CiphertextHashAcc::digest(input.label1)
    }

    fn commit_label0(input: &GarbledWire) -> Commit {
        CiphertextHashAcc::digest(input.label0)
    }

    pub fn output_commit_label1(&self) -> Commit {
        self.output_label1_commit
    }

    pub fn output_commit_label0(&self) -> Commit {
        self.output_label0_commit
    }

    pub fn true_consatnt_wire_commit(&self) -> Commit {
        self.true_constant_commit
    }

    pub fn false_consatnt_wire_commit(&self) -> Commit {
        self.false_constant_commit
    }
}

pub enum OpenForInstance {
    Open(usize, Seed),
    Closed {
        index: usize,
        garbling_thread: JoinHandle<()>,
    },
}

#[derive(Serialize, Deserialize)]
pub enum GarblerStage {
    Generating { seeds: Box<[Seed]> },
    PreparedForEval { indexes_to_eval: Box<[usize]> },
}

impl GarblerStage {
    fn next_stage(&mut self, indexes_to_eval: Box<[usize]>) -> Box<[Seed]> {
        assert!(matches!(self, Self::Generating { .. }));

        let mut n = GarblerStage::PreparedForEval { indexes_to_eval };

        mem::swap(self, &mut n);

        match n {
            Self::Generating { seeds } => seeds,
            _ => unreachable!(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Garbler<I: CircuitInput + Clone> {
    stage: GarblerStage,
    instances: Vec<GarbledInstance>,
    config: Config<I>,
}

impl<I> Garbler<I>
where
    I: CircuitInput + Clone + Send + Sync + EncodeInput<GarbleMode<AesNiHasher, CiphertextHashAcc>>,
    <I as CircuitInput>::WireRepr: Send,
    I: 'static,
{
    /// Create garbled instances in parallel using the provided circuit builder function.
    pub fn create<F>(mut rng: impl Rng, config: Config<I>, builder: F) -> Self
    where
        F: Fn(
                &mut StreamingMode<GarbleMode<AesNiHasher, CiphertextHashAcc>>,
                &I::WireRepr,
            ) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let seeds = (0..config.total)
            .map(|_| rng.r#gen())
            .collect::<Box<[Seed]>>();

        // Use optimized thread pool internally
        let instances: Vec<_> = get_optimized_pool().install(|| {
            seeds
                .par_iter()
                .enumerate()
                .map(|(index, garbling_seed)| {
                    let inputs = config.input.clone();
                    let hasher = CiphertextHashAcc::default();

                    let span = tracing::info_span!("garble", instance = index);
                    let _enter = span.enter();

                    info!("Starting garbling of circuit (cut-and-choose)");

                    let res: StreamingResult<
                        GarbleMode<AesNiHasher, CiphertextHashAcc>,
                        I,
                        GarbledWire,
                    > = CircuitBuilder::streaming_garbling(
                        inputs,
                        DEFAULT_CAPACITY,
                        *garbling_seed,
                        hasher,
                        builder,
                    );

                    GarbledInstance::from(res)
                })
                .collect()
        });

        Self {
            stage: GarblerStage::Generating { seeds },
            instances,
            config,
        }
    }

    pub fn commit(&self) -> Vec<GarbledInstanceCommit> {
        // Build commits in parallel; independent per instance
        self.instances
            .iter()
            .map(GarbledInstanceCommit::new)
            .collect()
    }

    pub fn open_commit<F, CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        mut indexes_to_finalize: Vec<(usize, CTH)>,
        builder: F,
    ) -> Vec<OpenForInstance>
    where
        F: 'static
            + Fn(&mut StreamingMode<GarbleMode<AesNiHasher, CTH>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
        I: EncodeInput<GarbleMode<AesNiHasher, CTH>>,
    {
        let seeds = self
            .stage
            .next_stage(indexes_to_finalize.iter().map(|(i, _)| *i).collect());

        // TODO #37 Since at this point the number but finalization is no more than 7, we just run
        // threads here, without rayon
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

                    let garbling_thread = thread::spawn(move || {
                        let _span =
                            tracing::info_span!("regarble2send", instance = index).entered();

                        info!("Starting");

                        let _: StreamingResult<_, I, GarbledWire> =
                            CircuitBuilder::<GarbleMode<AesNiHasher, _>>::streaming_garbling(
                                inputs,
                                DEFAULT_CAPACITY,
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

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn true_wire_constant_for(&self, index: usize) -> u128 {
        self.instances[index]
            .true_wire_constant
            .select(true)
            .to_u128()
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
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
}

pub struct Evaluator<I: CircuitInput + Clone, CTS: CiphertextSource> {
    config: Config<I>,
    commits: Vec<GarbledInstanceCommit>,
    to_finalize: Box<[usize]>,
    /// Receivers for ciphertext streams keyed by instance index
    receivers: HashMap<usize, CTS>,
}

impl<I, CTS: CiphertextSource> Evaluator<I, CTS>
where
    I: CircuitInput + Clone + Send + Sync + EncodeInput<GarbleMode<AesNiHasher, CiphertextHashAcc>>,
    <I as CircuitInput>::WireRepr: Send + Sync,
{
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(
        mut rng: impl Rng,
        config: Config<I>,
        commits: Vec<GarbledInstanceCommit>,
        receiver_fn: &mut impl FnMut(usize) -> CTS,
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
            receivers: idxs
                .iter()
                .copied()
                .map(|index| (index, receiver_fn(index)))
                .collect(),
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
    pub fn run_regarbling<F>(
        mut self,
        seeds: Vec<(usize, Seed)>,
        folder_for_ciphertexts: &Path,
        pre_alloc_size: Option<u64>,
        builder: F,
    ) -> Result<(), ()>
    where
        F: Fn(
                &mut StreamingMode<GarbleMode<AesNiHasher, CiphertextHashAcc>>,
                &I::WireRepr,
            ) -> WireId
            + Send
            + Sync
            + Copy,
        CTS: 'static,
    {
        let receivers = mem::take(&mut self.receivers);

        // Ensure output directory exists
        if let Err(e) = fs::create_dir_all(folder_for_ciphertexts) {
            error!(
                "failed to create output dir {:?}: {e}",
                folder_for_ciphertexts
            );
            return Err(());
        }

        // Use optimized thread pool for parallel regarbling
        let pool = get_optimized_pool();

        for (index, mut rx) in receivers.into_iter() {
            let path: PathBuf = folder_for_ciphertexts.join(format!("gc_{}.bin", index));
            let commit_path = folder_for_ciphertexts.join(format!("gc_{}_commit.json", index));

            serde_json::to_writer(
                File::create(commit_path).expect("failed to create commit file"),
                &self.commits[index],
            )
            .unwrap();

            let ciphertext_commit = self.commits[index].ciphertext_commit;

            let pre_alloc = pre_alloc_size;

            pool.spawn(move || {
                let file = File::create(&path).expect("create ciphertext file");
                let mut hasher = CiphertextHashAcc::default();

                // Pre-allocate file size if specified
                if let Some(size) = pre_alloc
                    && let Err(e) = file.set_len(size)
                {
                    error!("Failed to pre-allocate file size: {e}");
                }

                // Use larger buffer for large files (32MB for 48GB workloads)
                let buffer_size = if pre_alloc.unwrap_or(0) > 10 * (1 << 30) {
                    1 << 25 // 32MB buffer for files > 10GB
                } else {
                    1 << 20 // 1MB buffer for smaller files
                };
                let mut w = BufWriter::with_capacity(buffer_size, file);

                while let Some(s) = rx.recv() {
                    hasher.update(s);
                    // Persist compact record: only the 16-byte ciphertext label
                    w.write_all(&s.to_bytes()).unwrap();
                }

                if hasher.finalize() == ciphertext_commit {
                    w.flush().unwrap();
                } else {
                    todo!("ciphertext corrupted: delete file & delete commit file");
                }
            });
        }

        let all_ok = pool.install(|| {
            seeds.par_iter().all(|(index, garbling_seed)| {
                let inputs = self.config.input.clone();
                let hasher = CiphertextHashAcc::default();

                let span = tracing::info_span!("regarble", instance = index);
                let _enter = span.enter();

                info!("Starting regarbling of circuit (cut-and-choose)");

                let res: StreamingResult<
                    GarbleMode<AesNiHasher, CiphertextHashAcc>,
                    I,
                    GarbledWire,
                > = CircuitBuilder::streaming_garbling(
                    inputs.clone(),
                    DEFAULT_CAPACITY,
                    *garbling_seed,
                    hasher,
                    builder,
                );

                let regarbling_commit = GarbledInstanceCommit::new(&res.into());
                let received_commit = &self.commits[*index];

                &regarbling_commit == received_commit
            })
        });

        if all_ok { Ok(()) } else { Err(()) }
    }
}

pub struct EvaluatorCaseInput<I> {
    pub index: usize,
    pub input: I,
    pub true_constant_wire: u128,
    pub false_constant_wire: u128,
}

/// Errors that can occur during consistency checking.
#[derive(Debug)]
pub enum ConsistencyError {
    CommitFileNotFound(usize),
    CommitFileInvalid(usize, String),
    TrueConstantMismatch {
        index: usize,
        expected: u128,
        actual: u128,
    },
    FalseConstantMismatch {
        index: usize,
        expected: u128,
        actual: u128,
    },
    CiphertextMismatch {
        index: usize,
        expected: u128,
        actual: u128,
    },
    InputLabelsMismatch {
        index: usize,
        expected: u128,
        actual: u128,
    },
    OutputLabelMismatch {
        index: usize,
        expected: u128,
        actual: u128,
    },
    MissingCiphertextHash(usize),
}

impl std::fmt::Display for ConsistencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CommitFileNotFound(idx) => {
                write!(f, "Commit file not found for instance {}", idx)
            }
            Self::CommitFileInvalid(idx, err) => {
                write!(f, "Invalid commit file for instance {}: {}", idx, err)
            }
            Self::TrueConstantMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "True constant hash mismatch for instance {}: expected {:#x}, got {:#x}",
                index, expected, actual
            ),
            Self::FalseConstantMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "False constant hash mismatch for instance {}: expected {:#x}, got {:#x}",
                index, expected, actual
            ),
            Self::CiphertextMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "Ciphertext hash mismatch for instance {}: expected {:#x}, got {:#x}",
                index, expected, actual
            ),
            Self::InputLabelsMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "Input labels hash mismatch for instance {}: expected {:#x}, got {:#x}",
                index, expected, actual
            ),
            Self::OutputLabelMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "Output label hash mismatch for instance {}: expected {:#x}, got {:#x}",
                index, expected, actual
            ),
            Self::MissingCiphertextHash(idx) => {
                write!(f, "Missing ciphertext hash for instance {}", idx)
            }
        }
    }
}

impl std::error::Error for ConsistencyError {}

impl<I, CTS: CiphertextSource> Evaluator<I, CTS>
where
    I: CircuitInput + Clone + Send + Sync,
{
    /// Evaluate all finalized instances from saved ciphertext files in `folder`.
    /// Returns `(index, EvaluatedWire)` pairs.
    ///
    /// **Note**: This method does NOT perform consistency checking. Use `evaluate_from_saved_all_with_consistency`
    /// for evaluation with commit verification.
    pub fn evaluate_from<E, F>(
        folder: &Path,
        input_cases: Vec<EvaluatorCaseInput<E>>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError>
    where
        E: CircuitInput
            + Send
            + EncodeInput<EvaluateMode<AesNiHasher, ciphertext_source::FileSource>>,
        F: Fn(
                &mut StreamingMode<EvaluateMode<AesNiHasher, ciphertext_source::FileSource>>,
                &E::WireRepr,
            ) -> WireId
            + Send
            + Sync
            + Copy,
    {
        get_optimized_pool().install(|| {
            input_cases
                .into_par_iter()
                .map(|case| {
                    let EvaluatorCaseInput {
                        index,
                        input: eval_input,
                        true_constant_wire,
                        false_constant_wire,
                    } = case;

                    // Load the commit file
                    let commit_path = folder.join(format!("gc_{}_commit.json", index));

                    let commit_file = File::open(&commit_path)
                        .map_err(|_| ConsistencyError::CommitFileNotFound(index))?;

                    let commit: GarbledInstanceCommit = serde_json::from_reader(commit_file)
                        .map_err(|e| ConsistencyError::CommitFileInvalid(index, e.to_string()))?;

                    let true_consatnt_wire_hash =
                        CiphertextHashAcc::digest(S::from_u128(true_constant_wire));

                    if true_consatnt_wire_hash != commit.true_consatnt_wire_commit() {
                        return Err(ConsistencyError::TrueConstantMismatch {
                            index,
                            expected: commit.true_consatnt_wire_commit(),
                            actual: true_consatnt_wire_hash,
                        });
                    }

                    let false_consatnt_wire_hash =
                        CiphertextHashAcc::digest(S::from_u128(false_constant_wire));

                    if false_consatnt_wire_hash != commit.false_consatnt_wire_commit() {
                        return Err(ConsistencyError::FalseConstantMismatch {
                            index,
                            expected: commit.false_consatnt_wire_commit(),
                            actual: false_consatnt_wire_hash,
                        });
                    }

                    // TODO #37 Check input labels consistency [soldering]

                    // Use FileSource with tracked hashing
                    let file_path = folder.join(format!("gc_{}.bin", index));
                    let source = ciphertext_source::FileSource::from_path(file_path)
                        .expect("open ciphertext file");

                    let result =
                        CircuitBuilder::<EvaluateMode<AesNiHasher, _>>::streaming_evaluation::<
                            _,
                            _,
                            EvaluatedWire,
                        >(
                            eval_input,
                            capacity,
                            true_constant_wire,
                            false_constant_wire,
                            source,
                            builder,
                        );

                    if result.ciphertext_handler_result != commit.ciphertext_commit {
                        return Err(ConsistencyError::CiphertextMismatch {
                            index,
                            expected: commit.ciphertext_commit,
                            actual: result.ciphertext_handler_result,
                        });
                    }

                    let output_hash = CiphertextHashAcc::digest(result.output_value.active_label);

                    let expected_output_hash = if result.output_value.value {
                        commit.output_label1_commit
                    } else {
                        commit.output_label0_commit
                    };

                    if output_hash != expected_output_hash {
                        return Err(ConsistencyError::OutputLabelMismatch {
                            index,
                            expected: expected_output_hash,
                            actual: output_hash,
                        });
                    }

                    Ok((index, result.output_value))
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

// ============================================================================
// Tests: simple one-bit circuit exercising cut-and-choose end-to-end
// ============================================================================

#[cfg(test)]
mod tests {
    use crossbeam::channel;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        CiphertextHashAcc, Gate, WireId, ark,
        circuit::{
            CiphertextHandler, CircuitContext, EncodeInput, FALSE_WIRE, TRUE_WIRE,
            modes::CircuitMode,
        },
        gadgets::bn254::fq6::Fq6,
        hashers::GateHasher,
    };

    // Garbler-side input: single boolean wire, just allocate a fresh garbled label
    #[derive(Clone)]
    struct OneBitGarblerInput;

    impl CircuitInput for OneBitGarblerInput {
        type WireRepr = crate::WireId;

        fn allocate(&self, mut issue: impl FnMut() -> crate::WireId) -> Self::WireRepr {
            (issue)()
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
            vec![*repr]
        }
    }

    impl<H: GateHasher, CTH> EncodeInput<GarbleMode<H, CTH>> for OneBitGarblerInput
    where
        CTH: CiphertextHandler,
    {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(*repr, gw);
        }
    }

    // Evaluator-side input: single boolean with its garbled label
    #[derive(Clone)]
    struct OneBitEvaluatorInput {
        bit: bool,
        label: GarbledWire,
    }

    impl CircuitInput for OneBitEvaluatorInput {
        type WireRepr = WireId;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            (issue)()
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            vec![*repr]
        }
    }

    impl<H: GateHasher, SRC: ciphertext_source::CiphertextSource> EncodeInput<EvaluateMode<H, SRC>>
        for OneBitEvaluatorInput
    {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H, SRC>) {
            let ew = EvaluatedWire::new_from_garbled(&self.label, self.bit);
            cache.feed_wire(*repr, ew);
        }
    }

    // Very small circuit: out = (in AND true) OR false; this is logically identity
    fn one_bit_circuit<C: CircuitContext>(ctx: &mut C, input: &WireId) -> WireId {
        let t = *input;
        let tmp = ctx.issue_wire();
        ctx.add_gate(Gate::and(t, TRUE_WIRE, tmp));
        let out = ctx.issue_wire();
        ctx.add_gate(Gate::or(tmp, FALSE_WIRE, out));
        out
    }

    /// End-to-end cut-and-choose over a 1-bit identity circuit.
    ///
    /// Flow overview:
    /// - Garbler: creates `total` independent instances by streaming-garbling the circuit,
    ///   derives commits for ciphertext hash, input labels, output labels (0/1), and constants.
    /// - Evaluator: samples `finalize` indices, constructs per-index ciphertext channels
    ///   (receiver on Evaluator, sender provided to Garbler), and sends the selection to Garbler.
    /// - Open/Close: Garbler returns seeds for opened instances and spawns regarble-to-evaluation
    ///   threads for closed (finalized) instances which stream ciphertexts to files.
    /// - Regarbling check: Evaluator re-garbles each opened instance from its seed and checks that
    ///   the derived commit matches the Garbler’s commit (soundness against selective cheating).
    /// - Evaluation: Using constants (true/false wire values) plus the Evaluator’s semantic inputs
    ///   encoded against the provided input labels, Evaluator runs streaming evaluation from the
    ///   saved ciphertext files and obtains the output bit and active label. We verify that the
    ///   active output label’s commit equals the appropriate committed output label (0 or 1).
    #[test_log::test]
    fn cut_and_choose_one_bit_e2e() {
        // Deterministic RNG for reproducibility
        let mut rng = ChaCha20Rng::seed_from_u64(1234);

        let total = 5usize;
        let finalize = 2usize;

        // Garbler creates all instances
        let cfg_g = Config::new(total, finalize, OneBitGarblerInput);
        let mut garbler = Garbler::create(&mut rng, cfg_g, one_bit_circuit);
        let commits = garbler.commit();

        // Evaluator prepares receivers for ciphertexts of finalized instances
        let mut senders = Vec::with_capacity(finalize);

        // Evaluator chooses which instances to finalize
        let cfg_e = Config::new(total, finalize, OneBitGarblerInput);
        let evaluator = Evaluator::create(&mut rng, cfg_e, commits.clone(), &mut |index| {
            let (tx, rx) = channel::unbounded::<S>();
            senders.push((index, tx));
            rx
        });
        let finalize_indices: Vec<usize> = evaluator.get_indexes_to_finalize().to_vec();

        let open_info = garbler.open_commit(senders, one_bit_circuit);

        // Extract seeds for open instances
        let mut seeds = Vec::new();
        let mut join_handles = Vec::new();
        for item in open_info {
            match item {
                OpenForInstance::Open(i, s) => seeds.push((i, s)),
                OpenForInstance::Closed {
                    garbling_thread, ..
                } => join_handles.push(garbling_thread),
            }
        }

        // Run regarbling checks and persist ciphertexts
        let out_dir = PathBuf::from("target/cut_and_choose_test_simple");
        evaluator
            .run_regarbling(seeds, &out_dir, None, one_bit_circuit)
            .expect("regarbling ok");

        for j in join_handles {
            j.join().unwrap();
        }

        // Gather constants + input labels for finalized instances
        let mut cases_true = Vec::new();
        let mut cases_false = Vec::new();

        for idx in finalize_indices {
            let t = garbler.true_wire_constant_for(idx);
            let f = garbler.false_wire_constant_for(idx);

            let labels = garbler.input_labels_for(idx);

            assert_eq!(labels.len(), 1);

            // Build both true and false evaluator inputs
            let e_true = OneBitEvaluatorInput {
                bit: true,
                label: labels[0].clone(),
            };
            let e_false = OneBitEvaluatorInput {
                bit: false,
                label: labels[0].clone(),
            };

            cases_true.push(EvaluatorCaseInput {
                index: idx,
                input: e_true,
                true_constant_wire: t,
                false_constant_wire: f,
            });

            cases_false.push(EvaluatorCaseInput {
                index: idx,
                input: e_false,
                true_constant_wire: t,
                false_constant_wire: f,
            });
        }

        let results_true = Evaluator::<OneBitGarblerInput, channel::Receiver<S>>::evaluate_from(
            &out_dir,
            cases_true,
            64,
            one_bit_circuit,
        )
        .expect("consistency checks should pass for true inputs");

        for (_idx, out) in results_true {
            assert!(out.value, "output should equal input (true)");
        }

        let results_false = Evaluator::<OneBitGarblerInput, channel::Receiver<S>>::evaluate_from(
            &out_dir,
            cases_false,
            64,
            one_bit_circuit,
        )
        .expect("consistency checks should pass for false inputs");

        for (_idx, out) in results_false {
            assert!(!out.value, "output should equal input (false)");
            // Output label consistency is already checked in evaluate_from_saved_all_with_consistency
        }
    }

    // Fq12 multiplication-based cut-and-choose with equality-to-constant output.
    // Uses two Fq12 inputs (a, b), multiplies them in-circuit, compares against
    // precomputed constant a*b (Montgomery). Evaluates both true and false cases.
    /// End-to-end cut-and-choose over Fq12 multiplication in Montgomery form.
    ///
    /// Flow overview:
    /// - Circuit: computes `prod = Fq12::mul_montgomery(a, b)` and then a boolean `ok` by
    ///   checking `prod == prod_m`, where `prod_m` is a precomputed constant of `as_montgomery(a*b)`.
    /// - Garbling: the Garbler deterministically allocates labels for all input wires of `(a,b)`
    ///   and builds commits. It also prepares constants for true/false wires.
    /// - Selection: the Evaluator chooses indices to finalize, builds channels for ciphertexts
    ///   of these instances, and sends them to the Garbler.
    /// - Open/Close: Garbler returns seeds for opened instances; for finalized instances it spawns
    ///   a streaming garble->evaluation thread that writes ciphertexts to `gc_{idx}.bin`.
    /// - Regarbling check: Evaluator re-garbles opened instances from seeds and verifies commits.
    /// - Evaluation: For each finalized instance, Evaluator constructs its inputs by pairing the
    ///   Garbler’s input labels with semantic bits (flattened as `a.c0 || a.c1 || b.c0 || b.c1`)
    ///   to yield `EvaluatedWire`s, then runs streaming evaluation from the saved ciphertext file,
    ///   producing `ok` and the active output label. We assert both value and output-label commit:
    ///   - True case: `(a, b)` against `prod_m` → `ok = true` and commit equals committed label1.
    ///   - False case: `(a, b_alt)` vs `prod_m` → `ok = false` and commit equals committed label0.
    ///
    /// The test keeps `total=1` and `to_finalize=1` to minimize runtime while exercising the full flow.
    #[test_log::test]
    fn cut_and_choose_fq12_mul_e2e() {
        use crate::{circuit::WiresObject, gadgets::bn254::fq12::Fq12 as Fq12Wire};

        // Garbler-side input: two Fq12 operands
        #[derive(Clone)]
        struct Fq12MulGInput;

        #[derive(Clone)]
        struct Fq12MulWires {
            a: Fq12Wire,
            b: Fq12Wire,
        }

        impl CircuitInput for Fq12MulGInput {
            type WireRepr = Fq12MulWires;

            fn allocate(&self, mut issue: impl FnMut() -> crate::WireId) -> Self::WireRepr {
                Fq12MulWires {
                    a: Fq12Wire::new(&mut issue),
                    b: Fq12Wire::new(issue),
                }
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                let mut v = repr.a.to_wires_vec();
                v.extend(repr.b.to_wires_vec());
                v
            }
        }

        impl<H: GateHasher, CTH> EncodeInput<GarbleMode<H, CTH>> for Fq12MulGInput
        where
            CTH: CiphertextHandler,
        {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
                for &w in repr
                    .a
                    .to_wires_vec()
                    .iter()
                    .chain(repr.b.to_wires_vec().iter())
                {
                    let gw = cache.issue_garbled_wire();
                    cache.feed_wire(w, gw);
                }
            }
        }

        // Evaluator-side input: bit values for (a, b) + corresponding garbled labels
        #[derive(Clone)]
        struct Fq12MulEInput {
            a_m: ark_bn254::Fq12,
            b_m: ark_bn254::Fq12,
            labels: Vec<GarbledWire>,
        }

        impl CircuitInput for Fq12MulEInput {
            type WireRepr = Fq12MulWires;

            fn allocate(&self, mut issue: impl FnMut() -> crate::WireId) -> Self::WireRepr {
                Fq12MulWires {
                    a: Fq12Wire::new(&mut issue),
                    b: Fq12Wire::new(issue),
                }
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                let mut v = repr.a.to_wires_vec();
                v.extend(repr.b.to_wires_vec());
                v
            }
        }

        impl<H: GateHasher, SRC: ciphertext_source::CiphertextSource>
            EncodeInput<EvaluateMode<H, SRC>> for Fq12MulEInput
        {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H, SRC>) {
                // Flatten Fq12 bits in allocation order: a.c0 || a.c1 || b.c0 || b.c1
                let mut bits: Vec<bool> = Vec::with_capacity(Fq12Wire::N_BITS * 2);
                let (a_c0_bits, a_c1_bits) = Fq12Wire::to_bits(self.a_m);
                for (v0, v1) in a_c0_bits.into_iter() {
                    bits.extend(v0);
                    bits.extend(v1);
                }
                for (v0, v1) in a_c1_bits.into_iter() {
                    bits.extend(v0);
                    bits.extend(v1);
                }
                let (b_c0_bits, b_c1_bits) = Fq12Wire::to_bits(self.b_m);
                for (v0, v1) in b_c0_bits.into_iter() {
                    bits.extend(v0);
                    bits.extend(v1);
                }
                for (v0, v1) in b_c1_bits.into_iter() {
                    bits.extend(v0);
                    bits.extend(v1);
                }

                assert_eq!(bits.len(), self.labels.len());

                for ((wire_id, bit), gw) in repr
                    .a
                    .to_wires_vec()
                    .into_iter()
                    .chain(repr.b.to_wires_vec().into_iter())
                    .zip(bits.into_iter())
                    .zip(self.labels.iter())
                {
                    let ew = EvaluatedWire::new_from_garbled(gw, bit);
                    cache.feed_wire(wire_id, ew);
                }
            }
        }

        // Deterministic inputs
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        let a12_std = ark::Fq12::new(Fq6::random(&mut rng), Fq6::random(&mut rng));
        let b12_std = ark::Fq12::new(Fq6::random(&mut rng), Fq6::random(&mut rng));

        let a_m = Fq12Wire::as_montgomery(a12_std);
        let b_m = Fq12Wire::as_montgomery(b12_std);
        let prod_m = Fq12Wire::as_montgomery(a12_std * b12_std);

        // Circuit builder: multiply (a, b) then check equality to prod_m.
        // Provide three typed closures for the different modes we use.
        fn build_fq12_mul_eq_const<C: CircuitContext>(
            ctx: &mut C,
            inputs: &Fq12MulWires,
            prod_m: &ark_bn254::Fq12,
        ) -> WireId {
            let prod = Fq12Wire::mul_montgomery(ctx, &inputs.a, &inputs.b);
            Fq12Wire::equal_constant(ctx, &prod, prod_m)
        }

        let builder_garble_hash =
            move |ctx: &mut StreamingMode<GarbleMode<AesNiHasher, CiphertextHashAcc>>,
                  inputs: &Fq12MulWires| {
                build_fq12_mul_eq_const(ctx, inputs, &prod_m)
            };

        let builder_garble_send = move |ctx: &mut crate::circuit::StreamingMode<
            crate::circuit::modes::GarbleMode<
                crate::hashers::AesNiHasher,
                crate::circuit::CiphertextSender,
            >,
        >,
                                        inputs: &Fq12MulWires| {
            build_fq12_mul_eq_const(ctx, inputs, &prod_m)
        };

        let builder_eval = move |ctx: &mut StreamingMode<
            EvaluateMode<AesNiHasher, ciphertext_source::FileSource>,
        >,
                                 inputs: &Fq12MulWires| {
            build_fq12_mul_eq_const(ctx, inputs, &prod_m)
        };

        let total = 5usize;
        let finalize = 2usize;

        // Garbler flow
        let cfg_g = Config::new(total, finalize, Fq12MulGInput);
        let mut garbler = Garbler::create(&mut rng, cfg_g, builder_garble_hash);
        let commits = garbler.commit();

        // Evaluator prepares channels for finalized instances
        let mut senders = Vec::with_capacity(finalize);

        // Evaluator chooses to finalize 1 instance
        let cfg_e = Config::new(total, finalize, Fq12MulGInput);
        let evaluator = Evaluator::create(&mut rng, cfg_e, commits.clone(), &mut |index| {
            let (tx, rx) = channel::unbounded::<S>();
            senders.push((index, tx));
            rx
        });
        let to_finalize = evaluator.to_finalize.clone();

        let open_info = garbler.open_commit(senders, builder_garble_send);

        // Seeds + join handles
        let mut seeds = Vec::new();
        let mut join_handles = Vec::new();
        for item in open_info {
            match item {
                OpenForInstance::Open(i, s) => seeds.push((i, s)),
                OpenForInstance::Closed {
                    garbling_thread, ..
                } => join_handles.push(garbling_thread),
            }
        }

        let out_dir = PathBuf::from("target/cut_and_choose_test_fq12_mul");

        evaluator
            .run_regarbling(seeds, &out_dir, None, builder_garble_hash)
            .expect("regarbling ok");

        for j in join_handles {
            j.join().unwrap();
        }

        // Build true cases (a,b)
        let mut cases_true = Vec::new();

        for idx in to_finalize.iter().copied() {
            let t = garbler.true_wire_constant_for(idx);
            let f = garbler.false_wire_constant_for(idx);

            let labels = garbler.input_labels_for(idx);

            cases_true.push(EvaluatorCaseInput {
                index: idx,
                input: Fq12MulEInput {
                    a_m,
                    b_m,
                    labels: labels.clone(),
                },
                true_constant_wire: t,
                false_constant_wire: f,
            });
        }

        // Evaluate true cases
        let results_true = Evaluator::<Fq12MulGInput, channel::Receiver<S>>::evaluate_from(
            &out_dir,
            cases_true,
            10_000,
            builder_eval,
        )
        .unwrap();

        for (idx, out) in results_true {
            assert!(out.value, "a*b == prod_m should be true");
            let mut h = CiphertextHashAcc::default();
            h.update(out.active_label);
            assert_eq!(h.finalize(), commits[idx].output_commit_label1());
        }

        // False cases: flip b to a different value
        let b_alt_std = ark_bn254::Fq12::new(
            crate::gadgets::bn254::fq6::Fq6::random(&mut rng),
            crate::gadgets::bn254::fq6::Fq6::random(&mut rng),
        );

        let b_alt_m = Fq12Wire::as_montgomery(b_alt_std);

        let mut cases_false = Vec::new();

        for idx in to_finalize.iter().copied() {
            cases_false.push(EvaluatorCaseInput {
                index: idx,
                input: Fq12MulEInput {
                    a_m,
                    b_m: b_alt_m,
                    labels: garbler.input_labels_for(idx),
                },
                true_constant_wire: garbler.true_wire_constant_for(idx),
                false_constant_wire: garbler.false_wire_constant_for(idx),
            });
        }

        let results_false = Evaluator::<Fq12MulGInput, channel::Receiver<S>>::evaluate_from(
            &out_dir,
            cases_false,
            10_000,
            builder_eval,
        )
        .unwrap();

        for (idx, out) in results_false {
            assert!(!out.value, "a*b_alt == prod_m should be false");
            let mut h = CiphertextHashAcc::default();
            h.update(out.active_label);
            assert_eq!(h.finalize(), commits[idx].output_commit_label0());
        }
    }
}
