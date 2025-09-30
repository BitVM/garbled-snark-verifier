use std::{error, fmt};

use rand::Rng;
use rayon::{iter::IntoParallelRefIterator, prelude::*};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{error, info};

use super::{Config, garbler::GarbledInstanceCommit};
use crate::{
    AESAccumulatingHash, AesNiHasher, EvaluatedWire, GarbleMode, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitBuilder, CircuitInput, EncodeInput,
        StreamingMode, StreamingResult, modes::EvaluateMode,
    },
    cut_and_choose::{
        CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider,
        DefaultLabelCommitHasher, LabelCommit, LabelCommitHasher, Seed, commit_label_with,
        write_commit_hex,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "H: LabelCommitHasher")]
pub struct Evaluator<
    I: CircuitInput + Clone + Serialize + DeserializeOwned,
    H: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    config: Config<I>,
    commits: Vec<GarbledInstanceCommit<H>>,
    to_finalize: Box<[usize]>,
}

impl<I, H> Evaluator<I, H>
where
    I: CircuitInput
        + Clone
        + Send
        + Sync
        + EncodeInput<GarbleMode<AesNiHasher, AESAccumulatingHash>>,
    <I as CircuitInput>::WireRepr: Send + Sync,
    I: Serialize + DeserializeOwned,
    H: LabelCommitHasher,
{
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(
        mut rng: impl Rng,
        config: Config<I>,
        commits: Vec<GarbledInstanceCommit<H>>,
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
        }
    }

    pub fn get_indexes_to_finalize(&self) -> &[usize] {
        &self.to_finalize
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        &self.to_finalize
    }

    // 1. Check that `OpenForInstance` matches the ones stored in `self.to_finalize`.
    // 2. For `Open` run `streaming_garbling` via rayon, where at the end it checks for a match with saved commits
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<CSourceProvider, CHandlerProvider, F>(
        &self,
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
        F: Fn(
                &mut StreamingMode<GarbleMode<AesNiHasher, AESAccumulatingHash>>,
                &I::WireRepr,
            ) -> WireId
            + Send
            + Sync
            + Copy,
    {
        super::get_optimized_pool().install(|| {
            self.commits
                .par_iter()
                .enumerate()
                .map(|(index, commit)| {
                    if self.to_finalize.contains(&index) {
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

                        if computed_commit != commit.ciphertext_commit() {
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

                        let inputs = self.config.input.clone();
                        let hasher = AESAccumulatingHash::default();

                        let span = tracing::info_span!("regarble", instance = index);
                        let _enter = span.enter();

                        info!("Starting regarbling of circuit (cut-and-choose)");

                        let res: StreamingResult<
                            GarbleMode<AesNiHasher, AESAccumulatingHash>,
                            I,
                            GarbledWire,
                        > = CircuitBuilder::streaming_garbling(
                            inputs.clone(),
                            live_capacity,
                            *garbling_seed,
                            hasher,
                            builder,
                        );

                        let regarbling_commit = GarbledInstanceCommit::<H>::new(&res.into());

                        if &regarbling_commit != commit {
                            error!("regarbling failed");
                            return Err(());
                        }

                        Ok(())
                    }
                })
                .collect::<Result<Vec<()>, ()>>()
        })?;

        Ok(())
    }

    pub fn commits(&self) -> &[GarbledInstanceCommit<H>] {
        &self.commits
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluatorCaseInput<I> {
    pub index: usize,
    pub input: I,
    pub true_constant_wire: u128,
    pub false_constant_wire: u128,
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

impl<I, H> Evaluator<I, H>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    H: LabelCommitHasher,
{
    /// Evaluate all finalized instances from saved ciphertext files in `folder`.
    /// Returns `(index, EvaluatedWire)` pairs.
    ///
    /// **Note**: This method does NOT perform consistency checking. Use `evaluate_from_saved_all_with_consistency`
    /// for evaluation with commit verification.
    pub fn evaluate_from<E, F, CR>(
        &self,
        ciphertext_repo: &CR,
        input_cases: Vec<EvaluatorCaseInput<E>>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<H>>
    where
        CR: 'static + CiphertextSourceProvider + Sync,
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
        E: CircuitInput + Send + EncodeInput<EvaluateMode<AesNiHasher, CR::Source>>,
        F: Fn(&mut StreamingMode<EvaluateMode<AesNiHasher, CR::Source>>, &E::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        super::get_optimized_pool().install(|| {
            input_cases
                .into_par_iter()
                .map(|case| {
                    let EvaluatorCaseInput {
                        index,
                        input: eval_input,
                        true_constant_wire,
                        false_constant_wire,
                    } = case;

                    let commit = &self.commits[index];

                    let true_consatnt_wire_hash =
                        commit_label_with::<H>(S::from_u128(true_constant_wire));

                    if true_consatnt_wire_hash != commit.true_consatnt_wire_commit() {
                        return Err(ConsistencyError::TrueConstantMismatch {
                            index,
                            expected: commit.true_consatnt_wire_commit(),
                            actual: true_consatnt_wire_hash,
                        });
                    }

                    let false_consatnt_wire_hash =
                        commit_label_with::<H>(S::from_u128(false_constant_wire));

                    if false_consatnt_wire_hash != commit.false_consatnt_wire_commit() {
                        return Err(ConsistencyError::FalseConstantMismatch {
                            index,
                            expected: commit.false_consatnt_wire_commit(),
                            actual: false_consatnt_wire_hash,
                        });
                    }

                    let expected_input_commits = commit.input_labels_commit();

                    let source = match ciphertext_repo.source_for(index) {
                        Ok(src) => src,
                        Err(_) => {
                            return Err(ConsistencyError::MissingCiphertextHash(index));
                        }
                    };

                    let _span = tracing::info_span!("evaluate", instance = index).entered();

                    let result = CircuitBuilder::<EvaluateMode<AesNiHasher, CR::Source>>::streaming_evaluation::<
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
                        let actual_hash = commit_label_with::<H>(evaluated_wire.active_label);

                        if actual_hash != expected_hash {
                            let mut actual_commit = expected_commit.clone();

                            if evaluated_wire.value {
                                actual_commit.commit_label1 = actual_hash;
                            } else {
                                actual_commit.commit_label0 = actual_hash;
                            }

                            return Err(ConsistencyError::InputLabelsMismatch {
                                index,
                                label_index,
                                expected: expected_commit.clone(),
                                actual: actual_commit,
                            });
                        }
                    }

                    let new_ciphertext_commit: CiphertextCommit = result.ciphertext_handler_result.into();
                    if new_ciphertext_commit != commit.ciphertext_commit() {
                        return Err(ConsistencyError::CiphertextMismatch {
                            index,
                            expected: commit.ciphertext_commit(),
                            actual: new_ciphertext_commit,
                        });
                    }

                    let output_hash = commit_label_with::<H>(result.output_value.active_label);

                    let expected_output_hash = if result.output_value.value {
                        commit.output_label1_commit()
                    } else {
                        commit.output_label0_commit()
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
