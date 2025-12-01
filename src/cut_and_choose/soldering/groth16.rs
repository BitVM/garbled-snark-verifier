//! Groth16-specific wrappers around the soldering cut-and-choose API.
//!
//! This module provides convenient wrappers that hard-code Groth16 circuit parameters
//! with soldering support.

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::{SolderingCheckError, SolderingGarblerExt};
pub use crate::cut_and_choose::{
    LabelCommitHasher, Seed,
    vanilla::{CommitPhaseOne, CommitPhaseTwo, GarblerStage},
};
use crate::{
    AesCcrGateHasher, EvaluatedWire, GarbledWire, S,
    circuit::{CiphertextHandler, CiphertextSource},
    cut_and_choose::{
        self, CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider,
        ConsistencyError, DefaultLabelCommitHasher, LabelCommit, Sha256LabelCommitHasher,
        soldering,
    },
    garbled_groth16::{self, EvaluatorCompressedInput, GarblerCompressedInput, PublicParams},
    hashers::GateHasher,
    sp1_soldering::{Sha256Commit, SolderedLabels, SolderingProof},
};

pub const DEFAULT_CAPACITY: usize = 150_000;

pub type Config = cut_and_choose::Config<GarblerCompressedInput>;

pub type EvaluatorCaseInput = cut_and_choose::vanilla::EvaluatorCaseInput<EvaluatorCompressedInput>;

/// Groth16-specific Garbler for the soldering cut-and-choose protocol.
#[derive(Debug)]
pub struct Garbler {
    inner: soldering::Garbler<GarblerCompressedInput>,
}

impl Garbler {
    pub fn create(rng: impl Rng, config: Config) -> Self {
        let inner = soldering::Garbler::create(
            rng,
            config,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        );
        Self { inner }
    }

    pub fn commit_phase_one<LH>(&self) -> Vec<CommitPhaseOne<AesCcrGateHasher, LH>>
    where
        LH: LabelCommitHasher,
    {
        self.inner.commit_phase_one::<LH>()
    }

    pub fn commit_phase_two<LH>(&mut self, nonce: S) -> Vec<CommitPhaseTwo<LH>>
    where
        LH: LabelCommitHasher,
    {
        self.inner.commit_phase_two::<LH>(nonce)
    }

    pub fn get_commitment<LH: LabelCommitHasher>(
        &self,
    ) -> Option<cut_and_choose::Commitment<AesCcrGateHasher, LH>> {
        self.inner.get_commitment::<LH>()
    }

    pub fn finalized_indexes(&self) -> Option<&[usize]> {
        self.inner.finalized_indexes()
    }

    pub fn open_commit_without_ciphertexts(
        &mut self,
        indexes_to_finalize: Vec<usize>,
    ) -> cut_and_choose::vanilla::ChosenInstances {
        self.inner
            .open_commit_without_ciphertexts(indexes_to_finalize)
    }

    pub fn open_commit<CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        indexes_to_finalize: Vec<(usize, CTH)>,
    ) -> Vec<cut_and_choose::vanilla::OpenForInstance> {
        self.inner
            .open_commit(indexes_to_finalize, garbled_groth16::verify_compressed)
    }

    pub fn true_wire_constant_for(&self, index: usize) -> u128 {
        self.inner.true_wire_constant_for(index)
    }

    pub fn false_wire_constant_for(&self, index: usize) -> u128 {
        self.inner.false_wire_constant_for(index)
    }

    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.inner.input_labels_for(index)
    }

    pub fn prepare_input_labels(
        &self,
        public_params: PublicParams,
        challenge_proof: garbled_groth16::SnarkProof,
    ) -> Vec<EvaluatorCaseInput> {
        let finalized_indices = match self.inner.stage() {
            GarblerStage::Generating { .. } => {
                panic!("You can't prepare `input labels` for not finalized garbler")
            }
            GarblerStage::PreparedForEval { finalized_indexes } => finalized_indexes,
        };

        finalized_indices
            .iter()
            .map(|idx| {
                let input = EvaluatorCompressedInput::new(
                    public_params.clone(),
                    challenge_proof.clone(),
                    self.inner.config().input().vk.clone(),
                    self.inner.input_labels_for(*idx),
                );

                EvaluatorCaseInput { index: *idx, input }
            })
            .collect()
    }

    pub fn output_wire(&self, index: usize) -> Option<&GarbledWire> {
        self.inner.output_wire(index)
    }

    pub fn config(&self) -> &Config {
        self.inner.config()
    }

    pub fn stage(&self) -> &GarblerStage {
        self.inner.stage()
    }

    pub fn nonce(&self) -> Option<S> {
        self.inner.nonce()
    }

    // ========== SOLDERING-SPECIFIC METHODS ==========

    /// Produces a soldering proof that binds instance inputs together.
    pub fn do_soldering(&self) -> SolderingProof {
        self.inner.do_soldering()
    }

    /// Returns input wire label commitments for the base instance.
    pub fn soldered_base_commitment<LH: LabelCommitHasher>(
        &self,
    ) -> Option<Vec<LabelCommit<LH::Output>>> {
        self.inner.soldered_base_commitment::<LH>()
    }

    /// Returns output label commitments for all finalized instances.
    pub fn finalized_output_label_commitment<LH: LabelCommitHasher>(
        &self,
    ) -> Option<Vec<(LH::Output, LH::Output)>> {
        self.inner.finalized_output_label_commitment::<LH>()
    }
}

/// Groth16-specific Evaluator for the soldering cut-and-choose protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub struct Evaluator<
    GH: GateHasher = AesCcrGateHasher,
    LH: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    inner: soldering::Evaluator<GarblerCompressedInput, GH, LH>,
}

impl<GH: GateHasher + 'static, LH: LabelCommitHasher> Evaluator<GH, LH> {
    pub fn create(rng: impl Rng, config: Config, commits: Vec<CommitPhaseOne<GH, LH>>) -> Self {
        let inner =
            soldering::Evaluator::<GarblerCompressedInput, GH, LH>::create(rng, config, commits);
        Self { inner }
    }

    pub fn config(&self) -> &Config {
        self.inner.config()
    }

    pub fn fill_second_commit(&mut self, commits: Vec<CommitPhaseTwo<LH>>) {
        self.inner.fill_second_commit(commits);
    }

    pub fn get_nonce(&self) -> S {
        self.inner.get_nonce()
    }

    pub fn get_commitment(&self) -> Option<cut_and_choose::Commitment<GH, LH>>
    where
        CommitPhaseOne<GH, LH>: Clone,
        CommitPhaseTwo<LH>: Clone,
    {
        self.inner.get_commitment()
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        self.inner.finalized_indexes()
    }

    pub fn get_commit_phase_one(&self, index: usize) -> Option<&CommitPhaseOne<GH, LH>> {
        self.inner.get_commit_phase_one(index)
    }

    #[allow(clippy::result_unit_err)]
    pub fn full_check_commit<CSourceProvider, CHandlerProvider>(
        &mut self,
        seeds: Vec<(usize, Seed)>,
        ciphertext_sources_provider: &CSourceProvider,
        ciphertext_sink_provider: &CHandlerProvider,
    ) -> Result<(), ()>
    where
        CSourceProvider: CiphertextSourceProvider + Send + Sync,
        CHandlerProvider: CiphertextHandlerProvider + Send + Sync,
        CHandlerProvider::Handler: 'static,
        <CHandlerProvider::Handler as CiphertextHandler>::Result: 'static + Into<CiphertextCommit>,
    {
        self.inner.full_check_commit(
            seeds,
            ciphertext_sources_provider,
            ciphertext_sink_provider,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }

    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling(&mut self, seeds: Vec<(usize, Seed)>) -> Result<(), ()> {
        self.inner
            .run_regarbling(seeds, DEFAULT_CAPACITY, garbled_groth16::verify_compressed)
    }

    pub fn mark_regarbled(&mut self) {
        self.inner.mark_regarbled();
    }

    pub fn is_regarbled(&self) -> bool {
        self.inner.is_regarbled()
    }
}

impl<GH: GateHasher + 'static, LH: LabelCommitHasher> Evaluator<GH, LH> {
    pub fn evaluate_from<CR: 'static + CiphertextSourceProvider + Send + Sync>(
        &self,
        ciphertext_repo: &CR,
        input_cases: Vec<EvaluatorCaseInput>,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<LH>>
    where
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
    {
        self.inner.evaluate_from(
            ciphertext_repo,
            input_cases,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }
}

// ========== SOLDERING-SPECIFIC METHODS ==========

impl<GH: GateHasher> Evaluator<GH, Sha256LabelCommitHasher> {
    /// Verify the garbler-provided soldering proof.
    pub fn verify_soldering_against_commits(
        &mut self,
        proof: SolderingProof,
    ) -> Result<SolderedLabels, SolderingCheckError> {
        self.inner.verify_soldering_against_commits(proof)
    }

    /// Returns verified base instance input commitments after successful soldering verification.
    pub fn verified_soldered_base_commitment(&self) -> Option<Vec<LabelCommit<Sha256Commit>>> {
        self.inner.verified_soldered_base_commitment()
    }

    /// Returns output label commitments for all finalized instances.
    pub fn finalized_output_label_commitment(&self) -> Option<Vec<(Sha256Commit, Sha256Commit)>> {
        self.inner.finalized_output_label_commitment()
    }

    /// Evaluate with soldered instances, deriving additional inputs from base + deltas.
    #[allow(clippy::result_large_err)]
    pub fn run_evaluate_with_soldered_instances<
        CR: 'static + CiphertextSourceProvider + Send + Sync,
    >(
        &self,
        ciphertext_repo: &CR,
        base_case: EvaluatorCaseInput,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<Sha256LabelCommitHasher>>
    where
        <CR::Source as CiphertextSource>::Result: Into<CiphertextCommit>,
    {
        self.inner.evaluate_with_soldered_instances_from(
            ciphertext_repo,
            base_case,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }
}

// Implement SolderInput to allow deriving additional inputs from deltas.
impl crate::sp1_soldering::SolderInput for EvaluatorCompressedInput {
    fn solder(&self, per_wire: &[(crate::S, crate::S)]) -> EvaluatorCompressedInput {
        use garbled_groth16::{
            EvaluatedCompressedG1Wires, EvaluatedCompressedG2Wires, EvaluatedFrWires,
        };

        use crate::EvaluatedWire;

        let mut it = per_wire.iter();

        let mut map_wire = |ew: &EvaluatedWire| -> EvaluatedWire {
            let (d0, d1) = *it.next().expect("delta length matches input wires");
            let delta = if ew.value { d1 } else { d0 };
            EvaluatedWire::new(ew.active_label ^ &delta, ew.value)
        };

        let map_fr =
            |fr: &EvaluatedFrWires, map_wire: &mut dyn FnMut(&EvaluatedWire) -> EvaluatedWire| {
                EvaluatedFrWires(fr.0.iter().map(map_wire).collect())
            };

        let public = self
            .public
            .iter()
            .map(|fr| map_fr(fr, &mut map_wire))
            .collect();

        let a_x = map_fr(&self.a.x, &mut map_wire);
        let a_y_flag = map_wire(&self.a.y_flag);

        let b_x0 = map_fr(&self.b.x[0], &mut map_wire);
        let b_x1 = map_fr(&self.b.x[1], &mut map_wire);
        let b_y_flag = map_wire(&self.b.y_flag);

        let c_x = map_fr(&self.c.x, &mut map_wire);
        let c_y_flag = map_wire(&self.c.y_flag);

        EvaluatorCompressedInput {
            public,
            a: EvaluatedCompressedG1Wires {
                x: a_x,
                y_flag: a_y_flag,
            },
            b: EvaluatedCompressedG2Wires {
                x: [b_x0, b_x1],
                y_flag: b_y_flag,
            },
            c: EvaluatedCompressedG1Wires {
                x: c_x,
                y_flag: c_y_flag,
            },
            vk: self.vk.clone(),
        }
    }
}
