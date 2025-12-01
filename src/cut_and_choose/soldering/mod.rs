//! Soldering-focused cut-and-choose API.
//!
//! This module extends the vanilla cut-and-choose implementation with soldering helpers
//! for proving relationships between instances using SP1 proofs.

mod evaluator;
mod garbler;

pub use evaluator::{Evaluator, SolderingStage};
pub use garbler::SolderingGarblerExt;
pub type Garbler<I, GH = crate::AesCcrGateHasher> = crate::cut_and_choose::vanilla::Garbler<I, GH>;

// Re-export core types for convenience
pub use crate::cut_and_choose::vanilla::{
    ChosenInstances, CommitPhaseOne, CommitPhaseTwo, ConsistencyError, EvaluatorCaseInput,
    GarbledInstance, GarblerStage, OpenForInstance, Stage,
};
// Re-export common types from cut_and_choose
pub use crate::cut_and_choose::{
    AesLabelCommitHasher, CiphertextHandlerProvider, CiphertextSourceProvider, Commit, Commitment,
    Config, DefaultLabelCommitHasher, FileCiphertextHandler, FileCiphertextHandlerProvider,
    LabelCommit, LabelCommitHasher, Seed, Sha256LabelCommitHasher,
};

pub mod groth16;

use std::{error, fmt};

use crate::sp1_soldering::Sha256Commit;

/// Errors that can occur during soldering verification.
#[derive(Debug)]
pub enum SolderingCheckError {
    /// Unexpected size/layout of soldering data compared to local state
    ShapeMismatch(&'static str),
    /// Base instance per-wire commit mismatch
    BaseCommitMismatch {
        wire_index: usize,
        which: &'static str,
        expected: Sha256Commit,
        actual: Sha256Commit,
    },
    /// Base instance per-wire nonce commit mismatch
    BaseNonceCommitMismatch {
        wire_index: usize,
        which: &'static str,
        expected: Sha256Commit,
        actual: Sha256Commit,
    },
    /// Additional instance per-wire commit mismatch
    InstanceCommitMismatch {
        instance_index: usize,
        wire_index: usize,
        which: &'static str,
        expected: Sha256Commit,
        actual: Sha256Commit,
    },
    /// Failure during soldering verification
    SolderingFailed(String),
}

impl error::Error for SolderingCheckError {}

impl fmt::Display for SolderingCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShapeMismatch(msg) => write!(f, "Shape mismatch: {}", msg),
            Self::BaseCommitMismatch {
                wire_index,
                which,
                expected,
                actual,
            } => write!(
                f,
                "Base commit mismatch at wire {}, {}: expected {:?}, actual {:?}",
                wire_index, which, expected, actual
            ),
            Self::BaseNonceCommitMismatch {
                wire_index,
                which,
                expected,
                actual,
            } => write!(
                f,
                "Base nonce commit mismatch at wire {}, {}: expected {:?}, actual {:?}",
                wire_index, which, expected, actual
            ),
            Self::InstanceCommitMismatch {
                instance_index,
                wire_index,
                which,
                expected,
                actual,
            } => write!(
                f,
                "Instance {} commit mismatch at wire {}, {}: expected {:?}, actual {:?}",
                instance_index, wire_index, which, expected, actual
            ),
            Self::SolderingFailed(msg) => write!(f, "Soldering verification failed: {}", msg),
        }
    }
}
