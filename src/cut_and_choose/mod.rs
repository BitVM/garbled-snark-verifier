//! Cut-and-choose protocol primitives that implement the Setup and Evaluate
//! phases described in `docs/gsv_spec.md`. The submodules expose garbler and
//! evaluator roles plus utilities for ciphertext storage.
//!
//! # Module Structure
//!
//! - `vanilla` - Base cut-and-choose with two-phase commit protocol (and shared types)
//! - `soldering` - Extends vanilla with SP1 soldering proofs (requires `sp1-soldering` feature)
//! - `vsss` - Verifiable Secret Sharing Scheme variant (requires `vsss` feature)
use std::{
    fmt,
    ops::BitXor,
    sync::{Arc, OnceLock},
};

use rayon::{ThreadPool, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};

// Re-export the label commit hashers from hashers module
pub use crate::hashers::{
    AesLabelCommitHasher, Commit, DefaultLabelCommitHasher, LabelCommitHasher,
    Sha256LabelCommitHasher, commit_label_with,
};
use crate::{S, circuit::CircuitInput};

// Internal modules
mod ciphertext_repository;

// Protocol variants (vanilla is the base)
pub mod vanilla;

#[cfg(feature = "sp1-soldering")]
pub mod soldering;

#[cfg(feature = "vsss")]
pub mod vsss;

// Ciphertext handling (shared across all variants)
// Re-export vanilla types for backwards compatibility
pub use ciphertext_repository::{
    CiphertextHandlerProvider, CiphertextSourceProvider, FileCiphertextHandler,
    FileCiphertextHandlerProvider,
};
#[cfg(feature = "sp1-soldering")]
pub use soldering::SolderingCheckError;
pub use vanilla::{
    ChosenInstances, CommitPhaseOne, CommitPhaseTwo, ConsistencyError, EvaluatorCaseInput,
    GarbledInstance, GarblerStage, OpenForInstance, Stage,
};

pub type Seed = u64;

pub type CiphertextCommit = [u8; crate::ciphertext_hasher::HASH_OUTPUT_SIZE];

/// Type alias for commitment tuple (phase one, phase two)
pub type Commitment<GH, LH> = (Vec<CommitPhaseOne<GH, LH>>, Vec<CommitPhaseTwo<LH>>);

/// Per-wire label commitments used in both `Commit₁` and `Commit₂`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LabelCommit<H: Clone + Copy> {
    pub commit_false: H,
    pub commit_true: H,
}

impl<H: Clone + Copy> LabelCommit<H> {
    /// Hash both labels, optionally XOR-ing a nonce before hashing (spec Step 1.4).
    pub fn new<Hasher: LabelCommitHasher<Output = H>>(
        label_false: S,
        label_true: S,
        nonce: &Option<S>,
    ) -> Self {
        match nonce {
            Some(nonce) => Self {
                commit_false: commit_label_with::<Hasher>(label_false.bitxor(nonce)),
                commit_true: commit_label_with::<Hasher>(label_true.bitxor(nonce)),
            },
            None => Self {
                commit_false: commit_label_with::<Hasher>(label_false),
                commit_true: commit_label_with::<Hasher>(label_true),
            },
        }
    }

    pub fn commit_for_value(&self, bit: bool) -> H {
        if bit {
            self.commit_true
        } else {
            self.commit_false
        }
    }
}

impl<H: Clone + Copy + AsRef<[u8]>> fmt::Display for LabelCommit<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LabelCommit {{ false: 0x")?;
        write_commit_hex(f, self.commit_false.as_ref())?;
        write!(f, ", true: 0x")?;
        write_commit_hex(f, self.commit_true.as_ref())?;
        write!(f, " }}")
    }
}

pub fn commit_label(label: S) -> Commit {
    commit_label_with::<DefaultLabelCommitHasher>(label)
}

pub(crate) fn write_commit_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes.iter() {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}

/// Protocol configuration shared by Garbler and Evaluator.
///
/// Corresponds to the `(n, f, input)` tuple in `docs/gsv_spec.md`, where `n`
/// is the total number of garbled instances and `f` is the size of the
/// evaluation set selected during Step 2 (challenging).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config<I: CircuitInput> {
    pub total: usize,
    finalized_count: usize,
    input: I,
}

impl<I: CircuitInput> Config<I> {
    /// Create a new configuration with the total instance count, the number
    /// of finalized instances, and the compressed circuit input shared between
    /// garbler and evaluator.
    pub fn new(total: usize, finalized_count: usize, input: I) -> Self {
        Self {
            total,
            finalized_count,
            input,
        }
    }

    /// Total number of garbled circuits `n`.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Number of circuits `f` that will remain closed/finalized.
    pub fn finalized_count(&self) -> usize {
        self.finalized_count
    }

    /// Immutable access to the shared circuit input payload.
    pub fn input(&self) -> &I {
        &self.input
    }
}

static OPTIMIZED_POOL: OnceLock<Arc<ThreadPool>> = OnceLock::new();

/// Get the singleton optimized thread pool, creating it if necessary.
/// This is for internal use only - not exposed in the public API.
fn get_optimized_pool() -> &'static Arc<ThreadPool> {
    OPTIMIZED_POOL.get_or_init(|| Arc::new(build_pinned_pool()))
}

/// Build a thread pool with threads pinned to specific CPU cores.
/// This reduces thread migrations and can improve performance for CPU-intensive tasks.
fn build_pinned_pool() -> ThreadPool {
    ThreadPoolBuilder::new()
        .build()
        .expect("failed to create fallback thread pool")
}

#[cfg(test)]
mod tests;
