//! Groth16-specific wrappers around the vanilla cut-and-choose API.
//!
//! This module provides convenient wrappers that hard-code Groth16 circuit parameters
//! so callers can mirror the protocol described in `docs/gsv_spec.md` with minimal glue.

use rand::Rng;
use serde::{Deserialize, Serialize};

pub use crate::cut_and_choose::{
    LabelCommitHasher, Seed,
    vanilla::{CommitPhaseOne, CommitPhaseTwo, GarblerStage},
};
use crate::{
    AesCcrGateHasher, EvaluatedWire, GarbledWire, S,
    circuit::{CiphertextHandler, CiphertextSource},
    cut_and_choose::{
        self, CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider,
        ConsistencyError, DefaultLabelCommitHasher, vanilla,
    },
    garbled_groth16::{self, EvaluatorCompressedInput, GarblerCompressedInput, PublicParams},
    hashers::GateHasher,
};

pub const DEFAULT_CAPACITY: usize = 150_000;

pub type Config = cut_and_choose::Config<GarblerCompressedInput>;

pub type EvaluatorCaseInput = cut_and_choose::vanilla::EvaluatorCaseInput<EvaluatorCompressedInput>;

/// Groth16-specific Garbler for the vanilla cut-and-choose protocol.
#[derive(Debug)]
pub struct Garbler {
    inner: vanilla::Garbler<GarblerCompressedInput>,
}

impl Garbler {
    pub fn create(rng: impl Rng, config: Config) -> Self {
        let inner = vanilla::Garbler::create(
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
}

/// Groth16-specific Evaluator for the vanilla cut-and-choose protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub struct Evaluator<
    GH: GateHasher = AesCcrGateHasher,
    LH: LabelCommitHasher = DefaultLabelCommitHasher,
> {
    inner: vanilla::Evaluator<GarblerCompressedInput, GH, LH>,
}

impl<GH: GateHasher + 'static, LH: LabelCommitHasher> Evaluator<GH, LH> {
    pub fn create(rng: impl Rng, config: Config, commits: Vec<CommitPhaseOne<GH, LH>>) -> Self {
        let inner =
            vanilla::Evaluator::<GarblerCompressedInput, GH, LH>::create(rng, config, commits);
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

impl<GH: GateHasher, LH: LabelCommitHasher> Evaluator<GH, LH> {
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
