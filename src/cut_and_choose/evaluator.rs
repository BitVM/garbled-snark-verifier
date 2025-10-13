use std::{error, fmt, mem};

use itertools::*;
use rand::Rng;
use rayon::prelude::*;
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
#[cfg(feature = "sp1-soldering")]
use crate::{
    cut_and_choose::Sha256LabelCommitHasher,
    soldering::{SolderInput, SolderedLabels, SolderingProof},
};

#[derive(Default, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "H: LabelCommitHasher")]
enum Stage<H: LabelCommitHasher> {
    #[default]
    Empty,
    Created(Vec<GarbledInstanceCommit<H>>),
    Filled {
        first: Vec<GarbledInstanceCommit<H>>,
        second: Vec<Vec<LabelCommit<H::Output>>>,
        regarbled: bool,
    },
    #[cfg(feature = "sp1-soldering")]
    Soldered {
        first: Vec<GarbledInstanceCommit<H>>,
        second: Vec<Vec<LabelCommit<H::Output>>>,
        soldering_deltas: Vec<Vec<(S, S)>>,
    },
}

impl<H: LabelCommitHasher> Stage<H> {
    fn get_commit_if_ready(&self) -> Option<&[GarbledInstanceCommit<H>]> {
        match self {
            Stage::Empty => None,
            Stage::Created(_) => None,
            Stage::Filled {
                first,
                regarbled: true,
                ..
            } => Some(first),
            #[cfg(feature = "sp1-soldering")]
            Stage::Soldered { first, .. } => Some(first),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "H: LabelCommitHasher")]
pub struct Evaluator<
    I: CircuitInput + Clone + Serialize + DeserializeOwned,
    H: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    config: Config<I>,

    /// To protect against the second-preimage of input-label hash, this nonce supplements the
    /// commit from `Garbler`
    nonce: S,
    to_finalize: Box<[usize]>,
    stage: Stage<H>,
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
            stage: Stage::Created(commits),
            to_finalize: idxs.into_boxed_slice(),
            config,
            nonce: S::from_u128(rng.r#gen()),
        }
    }

    pub fn fill_second_commit(&mut self, commits: Vec<Vec<LabelCommit<H::Output>>>) {
        let first = match &mut self.stage {
            Stage::Created(first) => mem::take(first),
            _ => panic!("Can't fill second commit for filled `Evaluator`"),
        };

        self.stage = Stage::Filled {
            first,
            second: commits,
            regarbled: false,
        };
    }

    pub fn get_nonce(&self) -> S {
        self.nonce
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        &self.to_finalize
    }

    // 1. Check that `OpenForInstance` matches the ones stored in `self.to_finalize`.
    // 2. For `Open` run `streaming_garbling` via rayon, where at the end it checks for a match with saved commits
    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<CSourceProvider, CHandlerProvider, F>(
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
        F: Fn(
                &mut StreamingMode<GarbleMode<AesNiHasher, AESAccumulatingHash>>,
                &I::WireRepr,
            ) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let Stage::Filled {
            first,
            second,
            regarbled,
        } = &mut self.stage
        else {
            panic!("Can't run regarbling for not filled Evaluator");
        };

        let iter = first.iter().zip_eq(second.iter()).enumerate();

        let inputs = self.config.input.clone();
        let to_finalize = &self.to_finalize;
        let nonce = self.nonce;

        super::get_optimized_pool().install(|| {
            iter.par_bridge()
                .map(|(index, (first_commit, second_commit))| {
                    if to_finalize.contains(&index) {
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

                        if computed_commit != first_commit.ciphertext_commit() {
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

                        let res = res.into();
                        let regarbling_first_commit = GarbledInstanceCommit::<H>::new(&res, &None);

                        if &regarbling_first_commit != first_commit {
                            error!("regarbling failed, first commit not equal");
                            return Err(());
                        }

                        if GarbledInstanceCommit::<H>::new(&res, &Some(nonce)).input_labels_commit()
                            != second_commit
                        {
                            error!("regarbling failed, second commit not equal");
                            return Err(());
                        }

                        Ok(())
                    }
                })
                .collect::<Result<Vec<()>, ()>>()
        })?;

        *regarbled = true;

        Ok(())
    }
}

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
        let commits = self.stage.get_commit_if_ready().unwrap();

        super::get_optimized_pool().install(|| {
            input_cases
                .into_par_iter()
                .map(|case| {
                    let EvaluatorCaseInput {
                        index,
                        input: eval_input,
                    } = case;

                    let commit = &commits[index];

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
                        commit.true_constant(),
                        commit.false_constant(),
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

/// Errors that can occur when verifying soldering data against local commits.
#[cfg(feature = "sp1-soldering")]
#[derive(Debug)]
pub enum SolderingCheckError {
    /// Unexpected size/layout of soldering data compared to local state
    ShapeMismatch(&'static str),
    /// Base instance per-wire commit mismatch
    BaseCommitMismatch {
        wire_index: usize,
        which: &'static str,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Base instance per-wire nonce commit mismatch
    BaseNonceCommitMismatch {
        wire_index: usize,
        which: &'static str,
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Additional instance per-wire commit mismatch
    InstanceCommitMismatch {
        instance_index: usize,
        wire_index: usize,
        which: &'static str,
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

#[cfg(feature = "sp1-soldering")]
impl error::Error for SolderingCheckError {}

#[cfg(feature = "sp1-soldering")]
impl fmt::Display for SolderingCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShapeMismatch(msg) => write!(f, "soldering data shape mismatch: {}", msg),
            Self::BaseCommitMismatch {
                wire_index,
                which,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "base commit mismatch at wire {} ({}): expected 0x",
                    wire_index, which
                )?;
                super::write_commit_hex(f, expected)?;
                write!(f, ", got 0x")?;
                super::write_commit_hex(f, actual)
            }
            Self::BaseNonceCommitMismatch {
                wire_index,
                which,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "base nonce commit mismatch at wire {} ({}): expected 0x",
                    wire_index, which
                )?;
                super::write_commit_hex(f, expected)?;
                write!(f, ", got 0x")?;
                super::write_commit_hex(f, actual)
            }
            Self::InstanceCommitMismatch {
                instance_index,
                wire_index,
                which,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "instance {} commit mismatch at wire {} ({}): expected 0x",
                    instance_index, wire_index, which
                )?;
                super::write_commit_hex(f, expected)?;
                write!(f, ", got 0x")?;
                super::write_commit_hex(f, actual)
            }
        }
    }
}

impl<I> Evaluator<I, super::Sha256LabelCommitHasher>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
{
    /// Verify the garbler-provided soldering proof and compare its bound commitments
    /// against local commits for the finalized instances. Returns the verified
    /// soldering data (`SolderedLabels`) on success.
    ///
    /// Requirements:
    /// - Local commits must be produced with a hasher that outputs 32 bytes
    ///   (e.g., `Sha256LabelCommitHasher`) to compare with soldering commitments.
    /// - The garbler must build the proof using the same `to_finalize` ordering,
    ///   with the base at `to_finalize[0]` and additional instances following.
    #[cfg(feature = "sp1-soldering")]
    pub fn verify_soldering_against_commits(
        &mut self,
        proof: SolderingProof,
    ) -> Result<SolderedLabels, SolderingCheckError> {
        let Stage::Filled {
            first: first_commits,
            second: second_commits,
            regarbled: true,
        } = mem::take(&mut self.stage)
        else {
            panic!()
        };

        let verified_public_params = crate::soldering::verify_soldering(proof);

        let Some(&base_idx) = self.to_finalize.first() else {
            return Err(SolderingCheckError::ShapeMismatch(
                "to_finalize must contain at least one index",
            ));
        };

        let soldered_instances_indexes = &self.to_finalize[1..];

        // Shape checks
        let expected_wires = first_commits[base_idx].input_labels_commit().len();
        if verified_public_params.base_commitment.len() != expected_wires {
            return Err(SolderingCheckError::ShapeMismatch(
                "base commitment wire count",
            ));
        }
        if verified_public_params.deltas.len() != soldered_instances_indexes.len() {
            return Err(SolderingCheckError::ShapeMismatch(
                "deltas count vs additional instances",
            ));
        }
        if verified_public_params.commitments.len() != soldered_instances_indexes.len() {
            return Err(SolderingCheckError::ShapeMismatch(
                "commitments count vs additional instances",
            ));
        }
        for (j, &inst_idx) in soldered_instances_indexes.iter().enumerate() {
            if first_commits[inst_idx].input_labels_commit().len() != expected_wires
                || verified_public_params.commitments[j].len() != expected_wires
                || verified_public_params.deltas[j].len() != expected_wires
            {
                return Err(SolderingCheckError::ShapeMismatch(
                    "per-instance wire count",
                ));
            }
        }

        info!(
            base = base_idx,
            extra = soldered_instances_indexes.len(),
            wires = expected_wires,
            "verifying soldering commits against local commits"
        );

        // Compare base instance per-wire commitments
        let base_local = &first_commits[base_idx];
        for (wire_idx, base_pair) in base_local.input_labels_commit().iter().enumerate() {
            let [exp0, exp1] = verified_public_params.base_commitment[wire_idx];

            if base_pair.commit_label0 != exp0 {
                return Err(SolderingCheckError::BaseCommitMismatch {
                    wire_index: wire_idx,
                    which: "label0",
                    expected: exp0,
                    actual: base_pair.commit_label0,
                });
            }

            if base_pair.commit_label1 != exp1 {
                return Err(SolderingCheckError::BaseCommitMismatch {
                    wire_index: wire_idx,
                    which: "label1",
                    expected: exp1,
                    actual: base_pair.commit_label1,
                });
            }
        }

        // Verify nonce commitments for base instance
        // The second commit for base instance should have the nonce applied
        let base_second = &second_commits[base_idx];

        for (wire_idx, (nonce_commit, nonce_local_commit)) in verified_public_params
            .base_nonce_commitment
            .iter()
            .zip(base_second.iter())
            .enumerate()
        {
            // Verify label0 with nonce
            if nonce_commit[0] != nonce_local_commit.commit_label0 {
                return Err(SolderingCheckError::BaseNonceCommitMismatch {
                    wire_index: wire_idx,
                    which: "label0_with_nonce",
                    expected: nonce_local_commit.commit_label0,
                    actual: nonce_commit[0],
                });
            }

            // Verify label1 with nonce
            if nonce_commit[1] != nonce_local_commit.commit_label1 {
                return Err(SolderingCheckError::BaseNonceCommitMismatch {
                    wire_index: wire_idx,
                    which: "label1_with_nonce",
                    expected: nonce_local_commit.commit_label1,
                    actual: nonce_commit[1],
                });
            }
        }

        // Compare additional instances per-wire commitments
        for (j, &inst_idx) in soldered_instances_indexes.iter().enumerate() {
            let local = &first_commits[inst_idx];

            for (wire_idx, local_pair) in local.input_labels_commit().iter().enumerate() {
                let (exp0, exp1) = verified_public_params.commitments[j][wire_idx];

                if local_pair.commit_label0 != exp0 {
                    return Err(SolderingCheckError::InstanceCommitMismatch {
                        instance_index: inst_idx,
                        wire_index: wire_idx,
                        which: "label0",
                        expected: exp0,
                        actual: local_pair.commit_label0,
                    });
                }

                if local_pair.commit_label1 != exp1 {
                    return Err(SolderingCheckError::InstanceCommitMismatch {
                        instance_index: inst_idx,
                        wire_index: wire_idx,
                        which: "label1",
                        expected: exp1,
                        actual: local_pair.commit_label1,
                    });
                }
            }
        }

        // Persist deltas for later evaluate step
        self.stage = Stage::Soldered {
            first: first_commits,
            second: second_commits,
            soldering_deltas: verified_public_params.deltas.clone(),
        };

        Ok(verified_public_params)
    }
}

#[cfg(feature = "sp1-soldering")]
impl<I> Evaluator<I, Sha256LabelCommitHasher>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
{
    #[allow(clippy::result_large_err)]
    pub fn evaluate_with_soldered_instances_from<E, F, CR>(
        &self,
        ciphertext_repo: &CR,
        base_case: EvaluatorCaseInput<E>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<Sha256LabelCommitHasher>>
    where
        E: CircuitInput + Send + EncodeInput<EvaluateMode<AesNiHasher, CR::Source>> + SolderInput,
        CR: 'static + CiphertextSourceProvider + Send + Sync,
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
        F: Fn(&mut StreamingMode<EvaluateMode<AesNiHasher, CR::Source>>, &E::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let finalized = self.to_finalize.clone();
        assert!(
            !finalized.is_empty(),
            "no finalized instances; evaluator not initialized?"
        );

        // Ensure base case index matches our base finalized index
        let base_index = finalized[0];
        assert_eq!(
            base_case.index, base_index,
            "base_case.index must equal first finalized index"
        );

        let Stage::Soldered {
            soldering_deltas: deltas,
            ..
        } = &self.stage
        else {
            panic!()
        };

        // Build input cases: base + derived for each additional finalized index
        let mut cases: Vec<EvaluatorCaseInput<E>> = Vec::with_capacity(finalized.len());
        cases.push(base_case);

        for (j, &inst_idx) in finalized.iter().enumerate().skip(1) {
            let per_wire = &deltas[j - 1];
            let derived_input = cases[0].input.solder(per_wire);

            cases.push(EvaluatorCaseInput {
                index: inst_idx,
                input: derived_input,
            });
        }

        self.evaluate_from(ciphertext_repo, cases, capacity, builder)
    }
}
