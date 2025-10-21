//! Groth16-specific wrappers around the generic cut-and-choose API so callers
//! can mirror the protocol described in `docs/gsv_spec.md` with minimal glue.
#[cfg(feature = "sp1-soldering")]
use garbled_groth16::{EvaluatedCompressedG1Wires, EvaluatedCompressedG2Wires, EvaluatedFrWires};
use rand::Rng;
use serde::{Deserialize, Serialize};

pub use crate::cut_and_choose::{
    CommitPhaseOne, CommitPhaseTwo, LabelCommitHasher, OpenForInstance, Seed,
};
use crate::{
    EvaluatedWire, GarbledWire, S,
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

    pub fn commit_phase_one<HHasher>(&self) -> Vec<CommitPhaseOne<HHasher>>
    where
        HHasher: LabelCommitHasher,
    {
        self.inner.commit_phase_one::<HHasher>()
    }

    pub fn commit_phase_two<HHasher>(&mut self, nonce: S) -> Vec<CommitPhaseTwo<HHasher>>
    where
        HHasher: LabelCommitHasher,
    {
        self.inner.commit_phase_two::<HHasher>(nonce)
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

                EvaluatorCaseInput { index: *idx, input }
            })
            .collect()
    }

    pub fn output_wire(&self, index: usize) -> Option<&GarbledWire> {
        self.inner.output_wire(index)
    }

    #[cfg(feature = "sp1-soldering")]
    pub fn do_soldering(&self) -> crate::sp1_soldering::SolderingProof {
        self.inner.do_soldering()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "HHasher: LabelCommitHasher")]
pub struct Evaluator<HHasher: LabelCommitHasher = DefaultLabelCommitHasher> {
    inner: generic::Evaluator<garbled_groth16::GarblerCompressedInput, HHasher>,
}

impl<H: LabelCommitHasher> Evaluator<H> {
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(rng: impl Rng, config: Config, commits: Vec<CommitPhaseOne<H>>) -> Self {
        let inner = generic::Evaluator::<garbled_groth16::GarblerCompressedInput, H>::create(
            rng, config, commits,
        );
        Self { inner }
    }

    pub fn fill_second_commit(&mut self, commits: Vec<CommitPhaseTwo<H>>) {
        self.inner.fill_second_commit(commits);
    }

    pub fn get_nonce(&self) -> S {
        self.inner.get_nonce()
    }

    pub fn finalized_indexes(&self) -> &[usize] {
        self.inner.finalized_indexes()
    }

    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling<CSourceProvider, CHandlerProvider>(
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
        self.inner.run_regarbling(
            seeds,
            ciphertext_sources_provider,
            ciphertext_sink_provider,
            DEFAULT_CAPACITY,
            garbled_groth16::verify_compressed,
        )
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

// Implement SolderInput to allow creating derived instances from base instance with deltas
#[cfg(feature = "sp1-soldering")]
use crate::sp1_soldering::SolderInput;

#[cfg(feature = "sp1-soldering")]
impl SolderInput for garbled_groth16::EvaluatorCompressedInput {
    fn solder(
        &self,
        per_wire: &[(crate::S, crate::S)],
    ) -> garbled_groth16::EvaluatorCompressedInput {
        let mut it = per_wire.iter();

        let mut map_wire = |ew: &EvaluatedWire| -> EvaluatedWire {
            let (d0, d1) = *it.next().expect("delta length matches input wires");
            let delta = if ew.value { d1 } else { d0 };
            EvaluatedWire::new(ew.active_label ^ &delta, ew.value)
        };

        let map_fr =
            |fr: &garbled_groth16::EvaluatedFrWires,
             map_wire: &mut dyn FnMut(&EvaluatedWire) -> EvaluatedWire| {
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

        garbled_groth16::EvaluatorCompressedInput {
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

#[cfg(feature = "sp1-soldering")]
impl Evaluator<generic::Sha256LabelCommitHasher> {
    pub fn verify_soldering_against_commits(
        &mut self,
        proof: crate::sp1_soldering::SolderingProof,
    ) -> Result<crate::sp1_soldering::SolderedLabels, generic::SolderingCheckError> {
        self.inner.verify_soldering_against_commits(proof)
    }

    /// Evaluate all finalized instances using a single base set of input labels,
    /// reconstructing the rest from previously verified soldering deltas.
    ///
    /// Requirements:
    /// - Call `verify_soldering_against_commits` first; this stores the deltas.
    /// - `base_case.index` must equal the first finalized index (the base).
    /// - No additional constants are required; constants are derived from commits.
    #[allow(clippy::result_large_err)]
    pub fn run_evaluate_with_soldered_instances<
        CR: 'static + CiphertextSourceProvider + Send + Sync,
    >(
        &self,
        ciphertext_repo: &CR,
        base_case: EvaluatorCaseInput,
    ) -> Result<Vec<(usize, EvaluatedWire)>, ConsistencyError<generic::Sha256LabelCommitHasher>>
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
