//! Cut-and-choose protocol primitives that implement the Setup and Evaluate
//! phases described in `docs/gsv_spec.md`. The submodules expose garbler and
//! evaluator roles plus utilities for ciphertext storage.
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

pub mod ciphertext_repository;
pub mod evaluator;
pub mod garbler;

pub use ciphertext_repository::*;
pub use evaluator::*;
pub use garbler::*;

pub mod groth16;

pub type Seed = u64;

pub type CiphertextCommit = [u8; 16];

/// Per-wire label commitments used in both `Commit₁` and `Commit₂`.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LabelCommit<H: Clone + Copy> {
    pub commit_label0: H,
    pub commit_label1: H,
}

impl<H: Clone + Copy> LabelCommit<H> {
    /// Hash both labels, optionally XOR-ing a nonce before hashing (spec Step 1.4).
    pub fn new<Hasher: LabelCommitHasher<Output = H>>(
        label0: S,
        label1: S,
        nonce: &Option<S>,
    ) -> Self {
        match nonce {
            Some(nonce) => Self {
                commit_label0: commit_label_with::<Hasher>(label0.bitxor(nonce)),
                commit_label1: commit_label_with::<Hasher>(label1.bitxor(nonce)),
            },
            None => Self {
                commit_label0: commit_label_with::<Hasher>(label0),
                commit_label1: commit_label_with::<Hasher>(label1),
            },
        }
    }

    pub fn commit_for_value(&self, bit: bool) -> H {
        if bit {
            self.commit_label1
        } else {
            self.commit_label0
        }
    }
}

impl<H: Clone + Copy + AsRef<[u8]>> fmt::Display for LabelCommit<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LabelCommit {{ label0: 0x")?;
        write_commit_hex(f, self.commit_label0.as_ref())?;
        write!(f, ", label1: 0x")?;
        write_commit_hex(f, self.commit_label1.as_ref())?;
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
    total: usize,
    to_finalize: usize,
    input: I,
}

impl<I: CircuitInput> Config<I> {
    /// Create a new configuration with the total instance count, the number
    /// of finalized instances, and the compressed circuit input shared between
    /// garbler and evaluator.
    pub fn new(total: usize, to_finalize: usize, input: I) -> Self {
        Self {
            total,
            to_finalize,
            input,
        }
    }

    /// Total number of garbled circuits `n`.
    pub fn total(&self) -> usize {
        self.total
    }

    /// Number of circuits `f` that will remain closed/finalized.
    pub fn to_finalize(&self) -> usize {
        self.to_finalize
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
    OPTIMIZED_POOL.get_or_init(|| {
        let n_threads = num_cpus::get_physical().max(1);
        Arc::new(build_pinned_pool(n_threads))
    })
}

/// Build a thread pool with threads pinned to specific CPU cores.
/// This reduces thread migrations and can improve performance for CPU-intensive tasks.
fn build_pinned_pool(n_threads: usize) -> ThreadPool {
    let chosen_cores = select_cores_for_affinity(n_threads);

    ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .start_handler(move |thread_idx| {
            // Try to pin this thread to its assigned core
            if let Some(core_id) = chosen_cores.get(thread_idx).cloned() {
                // Silently ignore affinity errors (may not be supported on all systems)
                let _ = core_affinity::set_for_current(core_id);
            }
        })
        .build()
        .unwrap_or_else(|_| {
            // Fallback to default thread pool if pinned pool creation fails
            ThreadPoolBuilder::new()
                .num_threads(n_threads)
                .build()
                .expect("failed to create fallback thread pool")
        })
}

/// Select CPU cores for thread affinity.
/// Strategy:
/// - If we have at least 2x cores as threads, use every other core (avoid hyperthreads)
/// - Otherwise, use the first N cores available
/// - Returns empty vector if core detection fails (affinity will be skipped)
fn select_cores_for_affinity(n: usize) -> Vec<core_affinity::CoreId> {
    match core_affinity::get_core_ids() {
        Some(cores) if cores.len() >= 2 * n => {
            // Skip hyperthreads by taking every other core
            cores.into_iter().step_by(2).take(n).collect()
        }
        Some(cores) => {
            // Use first N cores available
            cores.into_iter().take(n).collect()
        }
        None => {
            // Core detection failed - affinity will not be set
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests;
