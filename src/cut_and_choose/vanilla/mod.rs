//! Vanilla cut-and-choose API: plain garbler/evaluator without VSSS or soldering helpers.
//!
//! This is the base implementation that uses a two-phase commit protocol:
//! 1. `commit_phase_one` - commitments without nonce
//! 2. `commit_phase_two` - commitments with evaluator-provided nonce

mod evaluator;
mod garbler;
pub mod types;

#[cfg(feature = "test-utils")]
pub use evaluator::EvaluatorRawParts;
pub use evaluator::{ConsistencyError, Evaluator, EvaluatorCaseInput, Stage};
pub use garbler::Garbler;
#[cfg(feature = "test-utils")]
pub use garbler::GarblerRawParts;
pub use types::{
    ChosenInstances, CommitPhaseOne, CommitPhaseTwo, GarbledInstance, GarblerStage, OpenForInstance,
};

// Re-export common types from cut_and_choose
pub use crate::cut_and_choose::{
    AesLabelCommitHasher, CiphertextHandlerProvider, CiphertextSourceProvider, Commit, Commitment,
    Config, DefaultLabelCommitHasher, FileCiphertextHandler, FileCiphertextHandlerProvider,
    LabelCommit, LabelCommitHasher, Seed, Sha256LabelCommitHasher,
};

pub mod groth16;
