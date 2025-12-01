//! Soldering Evaluator wrapper for the cut-and-choose protocol.
//!
//! This wrapper extends vanilla Evaluator with soldering-specific methods
//! and manages the additional Soldered stage state.

use rand::Rng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::info;

use super::SolderingCheckError;
use crate::{
    AesCcrGateHasher, Blake3AccumulatingHash, EvaluatedWire, GarbleMode, S, WireId,
    circuit::{
        CiphertextHandler, CiphertextSource, CircuitInput, EncodeInput, StreamingMode,
        modes::EvaluateMode,
    },
    cut_and_choose::{
        CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider, Config,
        DefaultLabelCommitHasher, LabelCommit, LabelCommitHasher, Seed, Sha256LabelCommitHasher,
        vanilla::{
            self, CommitPhaseOne, CommitPhaseTwo, ConsistencyError, EvaluatorCaseInput, Stage,
        },
    },
    hashers::GateHasher,
    sp1_soldering::{Sha256Commit, SolderInput, SolderedLabels, SolderingProof},
};

/// Soldering stage that extends the vanilla Stage with soldered state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub enum SolderingStage<GH: GateHasher, LH: LabelCommitHasher> {
    /// Standard vanilla stages (delegated to inner evaluator)
    Vanilla,
    /// Soldered stage after verify_soldering_against_commits
    Soldered {
        first: Vec<CommitPhaseOne<GH, LH>>,
        second: Vec<CommitPhaseTwo<LH>>,
        soldering_deltas: Vec<Vec<(S, S)>>,
    },
}

/// Soldering Evaluator for the cut-and-choose protocol.
///
/// This struct wraps the vanilla Evaluator and adds soldering-specific methods
/// with the additional Soldered stage.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "I: Serialize + DeserializeOwned, GH: GateHasher, LH: LabelCommitHasher")]
pub struct Evaluator<
    I: CircuitInput + Clone + Serialize + DeserializeOwned,
    GH: GateHasher = AesCcrGateHasher,
    LH: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    inner: vanilla::Evaluator<I, GH, LH>,
    /// Additional soldering-specific stage state
    soldering_stage: SolderingStage<GH, LH>,
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
    pub fn create(rng: impl Rng, config: Config<I>, commits: Vec<CommitPhaseOne<GH, LH>>) -> Self {
        Self {
            inner: vanilla::Evaluator::create(rng, config, commits),
            soldering_stage: SolderingStage::Vanilla,
        }
    }

    pub fn config(&self) -> &Config<I> {
        self.inner.config()
    }

    pub fn fill_second_commit(&mut self, commits: Vec<CommitPhaseTwo<LH>>) {
        self.inner.fill_second_commit(commits);
    }

    pub fn get_nonce(&self) -> S {
        self.inner.get_nonce()
    }

    pub fn get_commitment(&self) -> Option<crate::cut_and_choose::Commitment<GH, LH>>
    where
        CommitPhaseOne<GH, LH>: Clone,
        CommitPhaseTwo<LH>: Clone,
    {
        self.inner.get_commitment()
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        self.inner.finalized_indexes()
    }

    pub fn is_regarbled(&self) -> bool {
        self.inner.is_regarbled()
    }

    pub fn mark_regarbled(&mut self) {
        self.inner.mark_regarbled();
    }

    /// Performs comprehensive verification of all commitments.
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
        self.inner.full_check_commit(
            seeds,
            ciphertext_sources_provider,
            ciphertext_handler_provider,
            live_capacity,
            builder,
        )
    }

    /// Performs regarbling verification for all opened instances.
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
        self.inner.run_regarbling(seeds, live_capacity, builder)
    }

    /// Evaluate all finalized instances from saved ciphertext files.
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
        self.inner
            .evaluate_from(ciphertext_repo, input_cases, capacity, builder)
    }

    /// Get a specific commit from phase one by index.
    pub fn get_commit_phase_one(&self, index: usize) -> Option<&CommitPhaseOne<GH, LH>> {
        if let SolderingStage::Soldered { first, .. } = &self.soldering_stage {
            return first.get(index);
        }
        self.inner.get_commit_phase_one(index)
    }
}

// ========== SOLDERING-SPECIFIC METHODS ==========

impl<I, GH> Evaluator<I, GH, Sha256LabelCommitHasher>
where
    I: CircuitInput + Clone + Send + Sync + Serialize + DeserializeOwned,
    GH: GateHasher,
{
    /// Verify the garbler-provided soldering proof and compare its bound commitments
    /// against local commits for the finalized instances.
    ///
    /// This transitions the evaluator to the Soldered stage.
    pub fn verify_soldering_against_commits(
        &mut self,
        proof: SolderingProof,
    ) -> Result<SolderedLabels, SolderingCheckError> {
        // Get commitments from inner stage
        let inner_stage = self.inner.stage();
        let Stage::Filled {
            first: first_commits,
            second: second_commits,
        } = inner_stage
        else {
            panic!("verify_soldering_against_commits requires Filled stage");
        };

        let finalized_indexes = self.inner.finalized_indexes();
        let nonce = self.inner.get_nonce();

        // First, get the base index to prepare commitments
        let Some(&base_idx) = finalized_indexes.first() else {
            return Err(SolderingCheckError::ShapeMismatch(
                "finalized_indexes must contain at least one index",
            ));
        };

        // Prepare base commitments
        let base_commitment: Vec<(Sha256Commit, Sha256Commit)> = first_commits[base_idx]
            .input_commitments()
            .iter()
            .map(|lc| (lc.commit_false, lc.commit_true))
            .collect();

        // Prepare base nonce commitments (from second commit which has nonce applied)
        let base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)> = second_commits[base_idx]
            .input_commitments()
            .iter()
            .map(|lc| (lc.commit_false, lc.commit_true))
            .collect();

        // Prepare commitments for additional instances
        let additional_indexes = &finalized_indexes[1..];
        let commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>> = additional_indexes
            .iter()
            .map(|&idx| {
                first_commits[idx]
                    .input_commitments()
                    .iter()
                    .map(|lc| (lc.commit_false, lc.commit_true))
                    .collect()
            })
            .collect();

        // Extract proof and deltas
        let SolderingProof {
            proof: groth16_proof,
            deltas,
        } = proof;

        // Verify using the soldering API
        if !crate::sp1_soldering::verify_soldering(
            SolderingProof {
                proof: groth16_proof,
                deltas: deltas.clone(),
            },
            base_commitment.clone(),
            base_nonce_commitment.clone(),
            nonce.to_u128(),
            commitments.clone(),
        ) {
            return Err(SolderingCheckError::SolderingFailed(
                "Soldering verification failed".to_string(),
            ));
        }

        // Reconstruct the verified public params
        let verified_public_params = SolderedLabels {
            deltas: deltas.clone(),
            base_commitment,
            base_nonce_commitment,
            nonce: nonce.to_u128(),
            commitments,
        };

        let soldered_instances_indexes = &finalized_indexes[1..];

        // Shape checks
        let expected_wires = first_commits[base_idx].input_commitments().len();
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
            if first_commits[inst_idx].input_commitments().len() != expected_wires
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
        for (wire_idx, base_pair) in base_local.input_commitments().iter().enumerate() {
            let (exp0, exp1) = verified_public_params.base_commitment[wire_idx];

            if base_pair.commit_false != exp0 {
                return Err(SolderingCheckError::BaseCommitMismatch {
                    wire_index: wire_idx,
                    which: "label0",
                    expected: exp0,
                    actual: base_pair.commit_false,
                });
            }

            if base_pair.commit_true != exp1 {
                return Err(SolderingCheckError::BaseCommitMismatch {
                    wire_index: wire_idx,
                    which: "label1",
                    expected: exp1,
                    actual: base_pair.commit_true,
                });
            }
        }

        // Verify nonce commitments for base instance
        let base_second = &second_commits[base_idx];
        for (wire_idx, (nonce_commit, nonce_local_commit)) in verified_public_params
            .base_nonce_commitment
            .iter()
            .zip(base_second.input_commitments().iter())
            .enumerate()
        {
            if nonce_commit.0 != nonce_local_commit.commit_false {
                return Err(SolderingCheckError::BaseNonceCommitMismatch {
                    wire_index: wire_idx,
                    which: "label0_with_nonce",
                    expected: nonce_local_commit.commit_false,
                    actual: nonce_commit.0,
                });
            }

            if nonce_commit.1 != nonce_local_commit.commit_true {
                return Err(SolderingCheckError::BaseNonceCommitMismatch {
                    wire_index: wire_idx,
                    which: "label1_with_nonce",
                    expected: nonce_local_commit.commit_true,
                    actual: nonce_commit.1,
                });
            }
        }

        // Compare additional instances per-wire commitments
        for (j, &inst_idx) in soldered_instances_indexes.iter().enumerate() {
            let local = &first_commits[inst_idx];

            for (wire_idx, local_pair) in local.input_commitments().iter().enumerate() {
                let (exp0, exp1) = verified_public_params.commitments[j][wire_idx];

                if local_pair.commit_false != exp0 {
                    return Err(SolderingCheckError::InstanceCommitMismatch {
                        instance_index: inst_idx,
                        wire_index: wire_idx,
                        which: "label0",
                        expected: exp0,
                        actual: local_pair.commit_false,
                    });
                }

                if local_pair.commit_true != exp1 {
                    return Err(SolderingCheckError::InstanceCommitMismatch {
                        instance_index: inst_idx,
                        wire_index: wire_idx,
                        which: "label1",
                        expected: exp1,
                        actual: local_pair.commit_true,
                    });
                }
            }
        }

        // Convert deltas from u128 to S and persist for later evaluate step
        let soldering_deltas_s: Vec<Vec<(S, S)>> = verified_public_params
            .deltas
            .iter()
            .map(|instance_deltas| {
                instance_deltas
                    .iter()
                    .map(|(d0, d1)| (S::from_u128(*d0), S::from_u128(*d1)))
                    .collect()
            })
            .collect();

        // Transition to Soldered stage
        self.soldering_stage = SolderingStage::Soldered {
            first: first_commits.clone(),
            second: second_commits.clone(),
            soldering_deltas: soldering_deltas_s,
        };

        Ok(verified_public_params)
    }

    /// Returns verified base instance input commitments after successful soldering verification.
    ///
    /// Only available in Soldered stage after `verify_soldering_against_commits` has been called.
    pub fn verified_soldered_base_commitment(&self) -> Option<Vec<LabelCommit<Sha256Commit>>> {
        let SolderingStage::Soldered { first, .. } = &self.soldering_stage else {
            return None;
        };

        let base_idx = *self.inner.finalized_indexes().first()?;
        Some(first[base_idx].input_commitments().to_vec())
    }

    /// Returns output label commitments (true, false) for all finalized instances.
    ///
    /// Available after Filled stage (with regarbled=true) or Soldered stage.
    pub fn finalized_output_label_commitment(&self) -> Option<Vec<(Sha256Commit, Sha256Commit)>> {
        let first_commits = match &self.soldering_stage {
            SolderingStage::Soldered { first, .. } => first,
            SolderingStage::Vanilla => {
                if !self.inner.is_regarbled() {
                    return None;
                }
                let Stage::Filled { first, .. } = self.inner.stage() else {
                    return None;
                };
                first
            }
        };

        Some(
            self.inner
                .finalized_indexes()
                .iter()
                .map(|&idx| {
                    let commit = &first_commits[idx];
                    (commit.output_commit_true(), commit.output_commit_false())
                })
                .collect(),
        )
    }

    /// Evaluate with soldered instances, deriving additional inputs from base + deltas.
    #[allow(clippy::result_large_err)]
    pub fn evaluate_with_soldered_instances_from<E, F, CR>(
        &self,
        ciphertext_repo: &CR,
        base_case: EvaluatorCaseInput<E>,
        capacity: usize,
        builder: F,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<Sha256LabelCommitHasher>>
    where
        E: CircuitInput + Send + EncodeInput<EvaluateMode<GH, CR::Source>> + SolderInput,
        CR: 'static + CiphertextSourceProvider + Send + Sync,
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
        F: Fn(&mut StreamingMode<EvaluateMode<GH, CR::Source>>, &E::WireRepr) -> WireId
            + Send
            + Sync
            + Copy,
    {
        let finalized = self.inner.finalized_indexes();
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

        let SolderingStage::Soldered {
            soldering_deltas: deltas,
            ..
        } = &self.soldering_stage
        else {
            panic!("evaluate_with_soldered_instances requires Soldered stage")
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

        self.inner
            .evaluate_from(ciphertext_repo, cases, capacity, builder)
    }
}

#[cfg(feature = "test-utils")]
mod test_utils {
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
            soldering_stage: SolderingStage<GH, LH>,
        ) -> Self {
            Self {
                inner: vanilla::Evaluator::from_raw_parts(
                    config,
                    nonce,
                    finalized_indexes,
                    regarbled,
                    stage,
                ),
                soldering_stage,
            }
        }

        #[allow(clippy::type_complexity)]
        pub fn into_raw_parts(
            self,
        ) -> (
            Config<I>,
            S,
            Box<[usize]>,
            bool,
            Stage<GH, LH>,
            SolderingStage<GH, LH>,
        ) {
            let (config, nonce, finalized_indexes, regarbled, stage) = self.inner.into_raw_parts();
            (
                config,
                nonce,
                finalized_indexes,
                regarbled,
                stage,
                self.soldering_stage,
            )
        }
    }
}

#[cfg(feature = "test-utils")]
#[allow(unused_imports)]
pub use test_utils::*;
