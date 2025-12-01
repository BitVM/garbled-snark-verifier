//! Evaluator-side state machine for the cut-and-choose Setup phase.
//!
//! This is the feature-agnostic core evaluator. Protocol-specific extensions
//! (soldering, VSSS) are implemented in their respective modules.

use std::{error, fmt};

use itertools::*;
use rand::Rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{error, info};

use super::types::{CommitPhaseOne, CommitPhaseTwo, GarbledInstance};
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, EvaluatedWire, GarbleMode, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, EncodeInput,
        StreamingMode, StreamingResult, modes::EvaluateMode,
    },
    cut_and_choose::{
        CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider, Config,
        DefaultLabelCommitHasher, LabelCommit, LabelCommitHasher, Seed, commit_label_with,
        write_commit_hex,
    },
    hashers::GateHasher,
};

/// Evaluator stage (feature-agnostic).
#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub enum Stage<GH: GateHasher, LH: LabelCommitHasher> {
    #[default]
    Empty,
    Created(Vec<CommitPhaseOne<GH, LH>>),
    Filled {
        first: Vec<CommitPhaseOne<GH, LH>>,
        second: Vec<CommitPhaseTwo<LH>>,
    },
}

impl<GH: GateHasher, LH: LabelCommitHasher> Stage<GH, LH> {
    pub(crate) fn get_commit_if_ready(&self, regarbled: bool) -> Option<&[CommitPhaseOne<GH, LH>]> {
        if !regarbled {
            return None;
        }
        match self {
            Stage::Empty => None,
            Stage::Created(_) => None,
            Stage::Filled { first, .. } => Some(first),
        }
    }
}

/// Core evaluator for the cut-and-choose protocol.
///
/// This struct manages the verification and evaluation of garbled circuit instances.
/// It is feature-agnostic - protocol-specific extensions are implemented in the
/// `vanilla`, `soldering`, and `vsss` modules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "I: Serialize + DeserializeOwned, GH: GateHasher, LH: LabelCommitHasher")]
pub struct Evaluator<
    I: CircuitInput + Clone + Serialize + DeserializeOwned,
    GH: GateHasher = AesCcrGateHasher,
    LH: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    config: Config<I>,
    /// To protect against the second-preimage of input-label hash, this nonce supplements the
    /// commit from `Garbler`
    nonce: S,
    finalized_indexes: Box<[usize]>,
    /// Tracks whether opened instances have been successfully regarbled and verified
    regarbled: bool,
    stage: Stage<GH, LH>,
}

impl<I, GH, LH> Evaluator<I, GH, LH>
where
    I: CircuitInput + Clone + Send + Sync + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>,
    <I as CircuitInput>::WireRepr: Send + Sync,
    I: Serialize + DeserializeOwned,
    GH: GateHasher + 'static,
    LH: LabelCommitHasher,
{
    /// Create an evaluator from phase-one commitments.
    pub fn create(
        mut rng: impl Rng,
        config: Config<I>,
        commits: Vec<CommitPhaseOne<GH, LH>>,
    ) -> Self {
        assert!(
            config.finalized_count() <= config.total,
            "finalized_count must be <= total"
        );

        assert_eq!(commits.len(), config.total);

        // Sample without replacement: shuffle 0..total and take first `finalized_count`
        let mut idxs: Vec<usize> = (0..config.total).collect();
        // Fisher-Yates with unbiased rng
        for i in (1..idxs.len()).rev() {
            let j = rng.gen_range(0..=i);
            idxs.swap(i, j);
        }
        idxs.truncate(config.finalized_count());
        idxs.sort_unstable();

        Self {
            stage: Stage::Created(commits),
            finalized_indexes: idxs.into_boxed_slice(),
            config,
            nonce: S::from_u128(rng.r#gen()),
            regarbled: false,
        }
    }

    pub fn fill_second_commit(&mut self, commits: Vec<CommitPhaseTwo<LH>>) {
        let first = match &mut self.stage {
            Stage::Created(first) => std::mem::take(first),
            _ => panic!("fill_second_commit can only be called once"),
        };

        self.stage = Stage::Filled {
            first,
            second: commits,
        };
    }

    /// Get both phase one and phase two commitments if available.
    pub fn get_commitment(&self) -> Option<crate::cut_and_choose::Commitment<GH, LH>>
    where
        CommitPhaseOne<GH, LH>: Clone,
        CommitPhaseTwo<LH>: Clone,
    {
        match &self.stage {
            Stage::Filled { first, second } => Some((first.clone(), second.clone())),
            _ => None,
        }
    }

    /// Performs comprehensive verification of all commitments across finalized and opened instances.
    ///
    /// This method verifies:
    /// 1. For finalized instances: checks ciphertext hash matches the committed value
    /// 2. For opened instances: re-garbles the circuit and verifies both phase one and phase two commits
    #[allow(clippy::result_unit_err)]
    pub fn full_check_commit<CSourceProvider, CHandlerProvider, F>(
        &mut self,
        seeds: Vec<(usize, Seed)>,
        ciphertext_sources_provider: &CSourceProvider,
        ciphertext_handler_provider: &CHandlerProvider,
        live_capacity: usize,
        builder: F,
    ) -> Result<(), ()>
    where
        CSourceProvider: CiphertextSourceProvider + Send + Sync,
        CHandlerProvider: CiphertextHandlerProvider + Send + Sync,
        CHandlerProvider::Handler: 'static,
        <CHandlerProvider::Handler as CiphertextHandler>::Result: 'static + Into<CiphertextCommit>,
        F: Fn(&mut StreamingMode<GarbleMode<GH, Blake3AccumulatingHash>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let (first, second) = match &mut self.stage {
            Stage::Filled { first, second } => (first, second),
            _ => {
                panic!("Can't run full commit check for Evaluator not in Filled stage")
            }
        };

        let iter = first.iter().zip_eq(second.iter()).enumerate();

        let inputs = self.config.input.clone();
        let finalized_indexes = &self.finalized_indexes;
        let nonce = self.nonce;

        crate::cut_and_choose::get_optimized_pool().install(|| {
            iter.par_bridge()
                .map(|(index, (first_commit, second_commit))| {
                    if finalized_indexes.contains(&index) {
                        let mut source = match ciphertext_sources_provider.source_for(index) {
                            Ok(source) => source,
                            Err(err) => {
                                error!(index, ?err, "failed to get ciphertext source");
                                return Err(());
                            }
                        };

                        let mut handler = match ciphertext_handler_provider.handler_for(index) {
                            Ok(sink) => sink,
                            Err(err) => {
                                error!(index, ?err, "failed to create ciphertext sink");
                                return Err(());
                            }
                        };

                        while let Some(s) = source.recv() {
                            handler.handle(s);
                        }

                        let computed_commit: CiphertextCommit = handler.finalize().into();

                        if computed_commit != first_commit.ciphertext_hash() {
                            error!("ciphertext corrupted");
                            return Err(());
                        }

                        Ok(())
                    } else {
                        let Some(garbling_seed) = seeds
                            .iter()
                            .find_map(|(i, seed)| (i == &index).then_some(seed))
                        else {
                            error!("failed to find seed");
                            return Err(());
                        };

                        let inputs = inputs.clone();
                        let hasher = Blake3AccumulatingHash::default();

                        let span = tracing::info_span!("regarble", instance = index);
                        let _enter = span.enter();

                        info!("Starting regarbling of circuit (cut-and-choose)");

                        let res: StreamingResult<
                            GarbleMode<GH, Blake3AccumulatingHash>,
                            I,
                            GarbledWire,
                        > = CircuitBuilder::streaming_garbling(
                            inputs.clone(),
                            live_capacity,
                            *garbling_seed,
                            hasher,
                            builder,
                        );

                        let res = GarbledInstance::from_streaming_result(
                            res,
                            first_commit.gate_hasher_seed().clone(),
                        );
                        let regarbling_first_commit = CommitPhaseOne::<GH, LH>::from_instance(&res);

                        if &regarbling_first_commit != first_commit {
                            error!("regarbling failed, first commit not equal");
                            return Err(());
                        }

                        let regarbling_second_commit =
                            CommitPhaseTwo::<LH>::from_instance(&res, nonce);

                        if regarbling_second_commit.input_commitments()
                            != second_commit.input_commitments()
                        {
                            error!("regarbling failed, second commit not equal");
                            return Err(());
                        }

                        Ok(())
                    }
                })
                .collect::<Result<Vec<()>, ()>>()
        })?;

        self.regarbled = true;

        Ok(())
    }

    /// Performs regarbling verification for all opened instances.
    ///
    /// Unlike `full_check_commit`, this method does NOT verify ciphertext commits for
    /// finalized instances, making it faster when you only need to verify the opened instances.
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<F>(
        &mut self,
        seeds: Vec<(usize, Seed)>,
        live_capacity: usize,
        builder: F,
    ) -> Result<(), ()>
    where
        F: Fn(&mut StreamingMode<GarbleMode<GH, Blake3AccumulatingHash>>, &I::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let (first, second) = match &mut self.stage {
            Stage::Filled { first, second } => (first, second),
            _ => panic!("Can't run regarbling for Evaluator not in Filled stage"),
        };

        let iter = first.iter().zip_eq(second.iter()).enumerate();

        let inputs = self.config.input.clone();
        let finalized_indexes = &self.finalized_indexes;
        let nonce = self.nonce;

        crate::cut_and_choose::get_optimized_pool().install(|| {
            iter.par_bridge()
                .map(|(index, (first_commit, second_commit))| {
                    // Only process opened instances (not in finalized_indexes)
                    if finalized_indexes.contains(&index) {
                        return Ok(());
                    }

                    let Some(garbling_seed) = seeds
                        .iter()
                        .find_map(|(i, seed)| (i == &index).then_some(seed))
                    else {
                        error!("failed to find seed for instance {}", index);
                        return Err(());
                    };

                    let inputs = inputs.clone();
                    let hasher = Blake3AccumulatingHash::default();

                    let span = tracing::info_span!("regarble", instance = index);
                    let _enter = span.enter();

                    info!("Starting regarbling of circuit (cut-and-choose)");

                    let res: StreamingResult<
                        GarbleMode<GH, Blake3AccumulatingHash>,
                        I,
                        GarbledWire,
                    > = CircuitBuilder::streaming_garbling(
                        inputs.clone(),
                        live_capacity,
                        *garbling_seed,
                        hasher,
                        builder,
                    );

                    let res = GarbledInstance::from_streaming_result(
                        res,
                        first_commit.gate_hasher_seed().clone(),
                    );
                    let regarbling_first_commit = CommitPhaseOne::<GH, LH>::from_instance(&res);

                    if &regarbling_first_commit != first_commit {
                        error!("regarbling failed, first commit not equal");
                        return Err(());
                    }

                    let regarbling_second_commit = CommitPhaseTwo::<LH>::from_instance(&res, nonce);

                    if regarbling_second_commit.input_commitments()
                        != second_commit.input_commitments()
                    {
                        error!("regarbling failed, second commit not equal");
                        return Err(());
                    }

                    Ok(())
                })
                .collect::<Result<Vec<()>, ()>>()
        })?;

        self.regarbled = true;

        Ok(())
    }
}

// Minimal trait bounds for accessor methods
impl<I, GH, LH> Evaluator<I, GH, LH>
where
    I: CircuitInput + Clone + Serialize + DeserializeOwned,
    GH: GateHasher,
    LH: LabelCommitHasher,
{
    /// Get the stage (for derived implementations with minimal bounds).
    pub fn stage(&self) -> &Stage<GH, LH> {
        &self.stage
    }

    /// Get mutable stage (for test-utils).
    #[cfg(feature = "test-utils")]
    pub fn stage_mut(&mut self) -> &mut Stage<GH, LH> {
        &mut self.stage
    }

    /// Get finalized indexes (for derived implementations with minimal bounds).
    pub fn finalized_indexes(&self) -> &[usize] {
        &self.finalized_indexes
    }

    /// Get the nonce (for derived implementations with minimal bounds).
    pub fn get_nonce(&self) -> S {
        self.nonce
    }

    /// Returns whether opened instances have been successfully regarbled and verified.
    pub fn is_regarbled(&self) -> bool {
        self.regarbled
    }

    /// Manually sets the `regarbled` flag to `true`.
    pub fn mark_regarbled(&mut self) {
        self.regarbled = true;
    }

    /// Get the config.
    pub fn config(&self) -> &Config<I> {
        &self.config
    }

    /// Get a specific commit from phase one by index.
    pub fn get_commit_phase_one(&self, index: usize) -> Option<&CommitPhaseOne<GH, LH>> {
        match &self.stage {
            Stage::Empty => None,
            Stage::Created(first) => first.get(index),
            Stage::Filled { first, .. } => first.get(index),
        }
    }
}

/// Input for evaluating a single finalized instance.
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatorCaseInput<I> {
    pub index: usize,
    pub input: I,
}

/// Errors that can occur during consistency checking.
#[derive(Debug)]
pub enum ConsistencyError<H: LabelCommitHasher = DefaultLabelCommitHasher> {
    CommitFileNotFound(usize),
    CommitFileInvalid(usize, String),
    TrueConstantMismatch {
        index: usize,
        expected: H::Output,
        actual: H::Output,
    },
    FalseConstantMismatch {
        index: usize,
        expected: H::Output,
        actual: H::Output,
    },
    CiphertextMismatch {
        index: usize,
        expected: CiphertextCommit,
        actual: CiphertextCommit,
    },
    InputLabelsMismatch {
        index: usize,
        label_index: usize,
        expected: LabelCommit<H::Output>,
        actual: LabelCommit<H::Output>,
    },
    InputLabelsCountMismatch {
        index: usize,
        expected: usize,
        actual: usize,
    },
    OutputLabelMismatch {
        index: usize,
        expected: H::Output,
        actual: H::Output,
    },
    MissingCiphertextHash(usize),
}

impl<H: LabelCommitHasher> error::Error for ConsistencyError<H> {}

impl<H: LabelCommitHasher> fmt::Display for ConsistencyError<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
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
            } => {
                write!(
                    f,
                    "True constant hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::FalseConstantMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "False constant hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::CiphertextMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Ciphertext hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::InputLabelsMismatch {
                index,
                label_index,
                expected,
                actual,
            } => write!(
                f,
                "Input label commit mismatch for instance {}, label {}: expected {}, got {}",
                index, label_index, expected, actual
            ),
            Self::InputLabelsCountMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "Input labels count mismatch for instance {}: expected {}, got {}",
                index, expected, actual
            ),
            Self::OutputLabelMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Output label hash mismatch for instance {}: expected 0x",
                    index
                )?;
                write_commit_hex(f, expected.as_ref())?;
                write!(f, ", got 0x")?;
                write_commit_hex(f, actual.as_ref())
            }
            Self::MissingCiphertextHash(idx) => {
                write!(f, "Missing ciphertext hash for instance {}", idx)
            }
        }
    }
}

impl<I, GH, LH> Evaluator<I, GH, LH>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    GH: GateHasher,
    LH: LabelCommitHasher,
{
    /// Evaluate all finalized instances from saved ciphertext files.
    /// Returns `(index, EvaluatedWire)` pairs.
    pub fn evaluate_from<E, F, CR>(
        &self,
        ciphertext_repo: &CR,
        input_cases: Vec<EvaluatorCaseInput<E>>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<LH>>
    where
        CR: 'static + CiphertextSourceProvider + Sync,
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
        E: CircuitInput + Send + EncodeInput<EvaluateMode<GH, CR::Source>>,
        F: Fn(&mut StreamingMode<EvaluateMode<GH, CR::Source>>, &E::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let commits = self.stage.get_commit_if_ready(self.regarbled).unwrap();

        crate::cut_and_choose::get_optimized_pool().install(|| {
            input_cases
                .into_par_iter()
                .map(|case| {
                    let EvaluatorCaseInput {
                        index,
                        input: eval_input,
                    } = case;

                    let commit = &commits[index];

                    let expected_input_commits = commit.input_commitments();

                    let source = match ciphertext_repo.source_for(index) {
                        Ok(src) => src,
                        Err(_) => {
                            return Err(ConsistencyError::MissingCiphertextHash(index));
                        }
                    };

                    let _span = tracing::info_span!("evaluate", instance = index).entered();

                    let gate_hasher = GH::from_seed(commit.gate_hasher_seed().clone());
                    let result =
                        CircuitBuilder::<EvaluateMode<GH, CR::Source>>::streaming_evaluation::<
                            _,
                            _,
                            EvaluatedWire,
                        >(
                            eval_input,
                            capacity,
                            commit.true_constant(),
                            commit.false_constant(),
                            gate_hasher,
                            source,
                            builder,
                        );

                    if expected_input_commits.len() != result.input_wire_values.len() {
                        return Err(ConsistencyError::InputLabelsCountMismatch {
                            index,
                            expected: expected_input_commits.len(),
                            actual: result.input_wire_values.len(),
                        });
                    }

                    for (label_index, (expected_commit, evaluated_wire)) in expected_input_commits
                        .iter()
                        .zip(result.input_wire_values)
                        .enumerate()
                    {
                        let expected_hash = expected_commit.commit_for_value(evaluated_wire.value);
                        let actual_hash = commit_label_with::<LH>(evaluated_wire.active_label);

                        if actual_hash != expected_hash {
                            let mut actual_commit = expected_commit.clone();

                            if evaluated_wire.value {
                                actual_commit.commit_true = actual_hash;
                            } else {
                                actual_commit.commit_false = actual_hash;
                            }

                            return Err(ConsistencyError::InputLabelsMismatch {
                                index,
                                label_index,
                                expected: expected_commit.clone(),
                                actual: actual_commit,
                            });
                        }
                    }

                    let new_ciphertext_commit: CiphertextCommit =
                        result.ciphertext_handler_result.into();
                    if new_ciphertext_commit != commit.ciphertext_hash() {
                        return Err(ConsistencyError::CiphertextMismatch {
                            index,
                            expected: commit.ciphertext_hash(),
                            actual: new_ciphertext_commit,
                        });
                    }

                    let output_hash = commit_label_with::<LH>(result.output_value.active_label);

                    let expected_output_hash = if result.output_value.value {
                        commit.output_commit_true()
                    } else {
                        commit.output_commit_false()
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

#[cfg(feature = "test-utils")]
mod test_utils {
    use serde::{Deserialize, Serialize};

    use super::*;

    impl<I, GH, LH> Evaluator<I, GH, LH>
    where
        I: CircuitInput + Clone + Serialize + DeserializeOwned,
        GH: GateHasher,
        LH: LabelCommitHasher,
    {
        pub fn from_raw_parts(
            config: Config<I>,
            nonce: u128,
            finalized_indexes: Box<[usize]>,
            regarbled: bool,
            stage: Stage<GH, LH>,
        ) -> Self {
            Self {
                config,
                nonce: S::from_u128(nonce),
                finalized_indexes,
                regarbled,
                stage,
            }
        }

        #[allow(clippy::type_complexity)]
        pub fn into_raw_parts(self) -> (Config<I>, S, Box<[usize]>, bool, Stage<GH, LH>) {
            (
                self.config,
                self.nonce,
                self.finalized_indexes,
                self.regarbled,
                self.stage,
            )
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(
        bound = "I: CircuitInput + Clone + Serialize + DeserializeOwned, GH: GateHasher, LH: LabelCommitHasher"
    )]
    pub struct EvaluatorRawParts<I, GH, LH>
    where
        I: CircuitInput + Clone + Serialize + DeserializeOwned,
        GH: GateHasher,
        LH: LabelCommitHasher,
    {
        pub config: Config<I>,
        pub nonce: S,
        pub finalized_indexes: Box<[usize]>,
        pub regarbled: bool,
        pub stage: Stage<GH, LH>,
    }

    impl<I, GH, LH> From<EvaluatorRawParts<I, GH, LH>> for Evaluator<I, GH, LH>
    where
        I: CircuitInput
            + Clone
            + Send
            + Sync
            + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>
            + Serialize
            + DeserializeOwned,
        <I as CircuitInput>::WireRepr: Send + Sync,
        GH: GateHasher + 'static,
        LH: LabelCommitHasher,
    {
        fn from(parts: EvaluatorRawParts<I, GH, LH>) -> Self {
            Self::from_raw_parts(
                parts.config,
                parts.nonce.to_u128(),
                parts.finalized_indexes,
                parts.regarbled,
                parts.stage,
            )
        }
    }

    impl<I, GH, LH> From<Evaluator<I, GH, LH>> for EvaluatorRawParts<I, GH, LH>
    where
        I: CircuitInput + Clone + Serialize + DeserializeOwned,
        GH: GateHasher,
        LH: LabelCommitHasher,
    {
        fn from(value: Evaluator<I, GH, LH>) -> Self {
            let (config, nonce, finalized_indexes, regarbled, stage) = value.into_raw_parts();
            Self {
                config,
                nonce,
                finalized_indexes,
                regarbled,
                stage,
            }
        }
    }
}

#[cfg(feature = "test-utils")]
#[allow(unused_imports)]
pub use test_utils::*;
