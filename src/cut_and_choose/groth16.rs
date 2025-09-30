use rand::Rng;
use serde::{Deserialize, Serialize};

pub use crate::cut_and_choose::{GarbledInstanceCommit, LabelCommitHasher, OpenForInstance, Seed};
use crate::{
    EvaluatedWire, GarbledWire,
    circuit::{CiphertextHandler, CiphertextSource},
    cut_and_choose::{
        self as generic, CiphertextCommit, CiphertextHandlerProvider, CiphertextSourceProvider,
        ConsistencyError, DefaultLabelCommitHasher, GarblerStage,
    },
    garbled_groth16::{self, PublicParams},
};

pub type Config = generic::Config<garbled_groth16::GarblerCompressedInput>;

pub const DEFAULT_CAPACITY: usize = 150_000;

/// Groth16-specific wrapper preserving the existing API while delegating
/// to the generic cut-and-choose implementation.
#[derive(Debug, Serialize, Deserialize)]
pub struct Garbler {
    inner: generic::Garbler<garbled_groth16::GarblerCompressedInput>,
}

impl Garbler {
    pub fn create(rng: impl Rng, config: Config) -> Self {
        let inner = generic::Garbler::create(
            rng,
            config,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        );
        Self { inner }
    }

    pub fn commit(&self) -> Vec<GarbledInstanceCommit> {
        self.inner.commit()
    }

    pub fn commit_with_hasher<HHasher>(&self) -> Vec<GarbledInstanceCommit<HHasher>>
    where
        HHasher: LabelCommitHasher,
    {
        self.inner.commit_with_hasher::<HHasher>()
    }

    pub fn open_commit<CTH: 'static + Send + CiphertextHandler>(
        &mut self,
        indexes_to_finalize: Vec<(usize, CTH)>,
    ) -> Vec<OpenForInstance> {
        self.inner
            .open_commit(indexes_to_finalize, garbled_groth16::verify_compressed)
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn true_wire_constant_for(&self, index: usize) -> u128 {
        self.inner.true_wire_constant_for(index)
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn false_wire_constant_for(&self, index: usize) -> u128 {
        self.inner.false_wire_constant_for(index)
    }

    /// Return a clone of the input garbled labels for a given instance.
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
            GarblerStage::PreparedForEval { indexes_to_eval } => indexes_to_eval,
        };

        finalized_indices
            .iter()
            .map(|idx| {
                let input = garbled_groth16::EvaluatorCompressedInput::new(
                    public_params.clone(),
                    challenge_proof.clone(),
                    self.inner.config().input().vk.clone(),
                    self.input_labels_for(*idx),
                );

                EvaluatorCaseInput {
                    index: *idx,
                    input,
                    true_constant_wire: self.true_wire_constant_for(*idx),
                    false_constant_wire: self.false_wire_constant_for(*idx),
                }
            })
            .collect()
    }

    pub fn output_wire(&self, index: usize) -> Option<&GarbledWire> {
        self.inner.output_wire(index)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "HHasher: LabelCommitHasher")]
pub struct Evaluator<HHasher: LabelCommitHasher = DefaultLabelCommitHasher> {
    inner: generic::Evaluator<garbled_groth16::GarblerCompressedInput, HHasher>,
}

impl<H: LabelCommitHasher> Evaluator<H> {
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(rng: impl Rng, config: Config, commits: Vec<GarbledInstanceCommit<H>>) -> Self {
        let inner = generic::Evaluator::<garbled_groth16::GarblerCompressedInput, H>::create(
            rng, config, commits,
        );
        Self { inner }
    }

    pub fn get_indexes_to_finalize(&self) -> &[usize] {
        self.inner.get_indexes_to_finalize()
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        self.inner.finalized_indexes()
    }

    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<CSourceProvider, CHandlerProvider>(
        &self,
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
        self.inner.run_regarbling(
            seeds,
            ciphertext_sources_provider,
            ciphertext_sink_provider,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
    }

    pub fn commits(&self) -> &[GarbledInstanceCommit<H>] {
        self.inner.commits()
    }
}

pub type EvaluatorCaseInput =
    generic::EvaluatorCaseInput<garbled_groth16::EvaluatorCompressedInput>;

impl<H: LabelCommitHasher> Evaluator<H> {
    /// Evaluate all finalized instances from saved ciphertext files with consistency checking.
    ///
    /// This method performs three consistency checks:
    /// 1. Verifies input labels match the commit
    /// 2. Verifies ciphertext stream matches the commit
    /// 3. Verifies output label matches the appropriate commit (label0/label1)
    ///
    /// Returns `Ok(Vec<(index, EvaluatedWire)>)` if all checks pass, or an error describing the failure.
    pub fn evaluate_from<CR: 'static + CiphertextSourceProvider + Send + Sync>(
        &self,
        ciphertext_repo: &CR,
        input_cases: Vec<EvaluatorCaseInput>,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<H>>
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
