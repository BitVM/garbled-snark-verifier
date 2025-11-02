use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use rayon::{ThreadPool, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};

use crate::{S, circuit::CircuitInput, hashers};

pub mod ciphertext_repository;
pub mod evaluator;
pub mod garbler;

pub use ciphertext_repository::{
    CiphertextHandlerProvider, CiphertextSourceProvider, FileCiphertextHandlerProvider,
};
pub use evaluator::*;
pub use garbler::*;

pub mod groth16;

pub type Seed = u64;

/// Default bound for automatically chosen multigarbling lanes
pub(crate) const DEFAULT_LANES: usize = 8;

pub type CiphertextCommit = [u8; 16];

pub trait LabelCommitHasher: fmt::Debug {
    type Output: Copy
        + fmt::Debug
        + Eq
        + Send
        + Sync
        + Serialize
        + for<'de> serde::Deserialize<'de>
        + AsRef<[u8]>;

    fn hash_label(label: S) -> Self::Output;
}

pub trait ModeBuilder<I: CircuitInput>: Send + Sync + Copy {
    fn build_single(
        &self,
        root: &mut crate::circuit::StreamingMode<
            crate::circuit::modes::GarbleMode<crate::AesNiHasher, crate::AESAccumulatingHash>,
        >,
        irepr: &I::WireRepr,
    ) -> crate::WireId;

    fn build_multi<const N: usize>(
        &self,
        root: &mut crate::circuit::StreamingMode<
            crate::circuit::modes::MultigarblingMode<
                crate::AesNiHasher,
                crate::AESAccumulatingHashBatch<N>,
                N,
            >,
        >,
        irepr: &I::WireRepr,
    ) -> crate::WireId;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AesLabelCommitHasher;

impl LabelCommitHasher for AesLabelCommitHasher {
    type Output = [u8; 16];

    fn hash_label(label: S) -> Self::Output {
        hashers::aes_ni::aes128_encrypt_block_static(label.to_bytes())
            .expect("AES backend should be available (HW or software)")
    }
}

pub type DefaultLabelCommitHasher = AesLabelCommitHasher;
pub type Commit = <DefaultLabelCommitHasher as LabelCommitHasher>::Output;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LabelCommit<H: Clone + Copy> {
    pub commit_label0: H,
    pub commit_label1: H,
}

impl<H: Clone + Copy> LabelCommit<H> {
    pub fn new<Hasher: LabelCommitHasher<Output = H>>(label0: S, label1: S) -> Self {
        Self {
            commit_label0: commit_label_with::<Hasher>(label0),
            commit_label1: commit_label_with::<Hasher>(label1),
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

pub fn commit_label_with<H: LabelCommitHasher>(label: S) -> H::Output {
    H::hash_label(label)
}

pub(crate) fn write_commit_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes.iter() {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}

/// Protocol configuration shared by Garbler/Evaluator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config<I: CircuitInput> {
    total: usize,
    to_finalize: usize,
    input: I,
}

impl<I: CircuitInput> Config<I> {
    pub fn new(total: usize, to_finalize: usize, input: I) -> Self {
        Self {
            total,
            to_finalize,
            input,
        }
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn to_finalize(&self) -> usize {
        self.to_finalize
    }

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

/// Heuristic to choose lanes N ∈ {1,2,4,8,16} up to `lanes`
/// - If instances <= threads: choose 1 (maximize per-instance parallelism)
/// - Else choose the largest N in {16,8,4,2} with N <= lanes s.t. ceil(instances/N) >= threads
/// - Else fall back to min(8, lanes)
pub(crate) fn pick_lanes(instances: usize, threads: usize, lanes: usize) -> usize {
    if instances <= threads {
        return 1;
    }
    for &n in [16usize, 8, 4, 2].iter() {
        if n <= lanes {
            let groups = instances.div_ceil(n);
            if groups >= threads {
                return n;
            }
        }
    }
    lanes.min(8)
}

#[cfg(test)]
mod tests;
