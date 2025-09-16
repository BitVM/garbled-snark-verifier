#![allow(dead_code)]

use std::path::Path;

use crossbeam::channel;
pub use generic::{Commit, Config, GarbledInstanceCommit, OpenForInstance, Seed};
use rand::Rng;

use crate::{EvaluatedWire, GarbledWire, S, cut_and_choose as generic, garbled_groth16};

/// Groth16-specific wrapper preserving the existing API while delegating
/// to the generic cut-and-choose implementation.
pub struct Garbler {
    inner: generic::Garbler<garbled_groth16::GarblerCompressedInput>,
}

impl Garbler {
    pub fn create(rng: impl Rng, config: Config<garbled_groth16::GarblerCompressedInput>) -> Self {
        let inner = generic::Garbler::create(rng, config, garbled_groth16::verify_compressed);
        Self { inner }
    }

    pub fn commit(&self) -> Vec<GarbledInstanceCommit> {
        self.inner.commit()
    }

    pub fn open_commit(
        &self,
        indexes_to_finalize: Vec<(usize, channel::Sender<(usize, S)>)>,
    ) -> Vec<OpenForInstance> {
        self.inner
            .open_commit(indexes_to_finalize, garbled_groth16::verify_compressed)
    }

    /// Return the constant labels for true/false as u128 words for a given instance.
    pub fn constants_for(&self, index: usize) -> (u128, u128) {
        self.inner.constants_for(index)
    }

    /// Return a clone of the input garbled labels for a given instance.
    pub fn input_labels_for(&self, index: usize) -> Vec<GarbledWire> {
        self.inner.input_labels_for(index)
    }
}

pub struct Evaluator {
    inner: generic::Evaluator<garbled_groth16::GarblerCompressedInput>,
}

impl Evaluator {
    // Generate `to_finalize` with `rng` based on data on `Config`
    pub fn create(
        rng: impl Rng,
        config: Config<garbled_groth16::GarblerCompressedInput>,
        commits: Vec<GarbledInstanceCommit>,
        receivers: Vec<channel::Receiver<(usize, S)>>,
    ) -> Self {
        let inner = generic::Evaluator::create(rng, config, commits, receivers);
        Self { inner }
    }

    pub fn get_indexes_to_finalize(&self) -> &[usize] {
        self.inner.get_indexes_to_finalize()
    }

    #[allow(clippy::result_unit_err)]
    pub fn run_regarbling(
        self,
        seeds: Vec<(usize, Seed)>,
        folder_for_ciphertexts: &Path,
    ) -> Result<(), ()> {
        // Pre-allocate 48GB for Groth16 circuit ciphertext files
        const GROTH16_CIPHERTEXT_SIZE: u64 = 48 * (1 << 30); // 48GB

        self.inner.run_regarbling(
            seeds,
            folder_for_ciphertexts,
            Some(GROTH16_CIPHERTEXT_SIZE),
            garbled_groth16::verify_compressed,
        )
    }
}

impl Evaluator {
    /// Evaluate all finalized instances from saved ciphertext files in `folder`.
    /// Returns `(index, EvaluatedWire)` pairs.
    pub fn evaluate_from_saved_all(
        cases: Vec<(
            usize,
            garbled_groth16::EvaluatorCompressedInput,
            (u128, u128),
        )>,
        capacity: usize,
        folder: &Path,
    ) -> Vec<(usize, EvaluatedWire)> {
        generic::Evaluator::<garbled_groth16::GarblerCompressedInput>::evaluate_from_saved_all(
            cases,
            capacity,
            folder,
            garbled_groth16::verify_compressed,
        )
    }
}
