//! Core types for the cut-and-choose protocol.
//!
//! These types are feature-agnostic and shared by all protocol variants.

use std::thread::JoinHandle;

use serde::{Deserialize, Serialize};

use crate::{
    GarbledWire, S,
    circuit::{CiphertextHandler, CircuitInput},
    cut_and_choose::{
        CiphertextCommit, DefaultLabelCommitHasher, LabelCommit, LabelCommitHasher,
        commit_label_with,
    },
    hashers::GateHasher,
};

/// A single garbled circuit instance produced during the Setup phase.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "GH: GateHasher")]
pub struct GarbledInstance<GH: GateHasher> {
    /// Constant to represent false wire constant
    pub false_wire_constant: GarbledWire,

    /// Constant to represent true wire constant
    pub true_wire_constant: GarbledWire,

    /// Output `WireId` in return order
    pub output_wire_values: GarbledWire,

    /// Values of the input Wires, which were fed to the circuit input
    pub input_wire_values: Vec<GarbledWire>,

    pub ciphertext_handler_result: CiphertextCommit,

    /// The seed for the gate hasher (used for regarbling/evaluation)
    pub gate_hasher_seed: GH::Seed,
}

impl<GH: GateHasher> GarbledInstance<GH> {
    /// Create a `GarbledInstance` from a `StreamingResult` and the gate hasher seed.
    pub fn from_streaming_result<
        I: CircuitInput,
        CTH: CiphertextHandler<Result = CiphertextCommit>,
    >(
        res: crate::circuit::StreamingResult<crate::GarbleMode<GH, CTH>, I, GarbledWire>,
        gate_hasher_seed: GH::Seed,
    ) -> Self {
        GarbledInstance {
            false_wire_constant: res.false_wire_constant,
            true_wire_constant: res.true_wire_constant,
            output_wire_values: res.output_value,
            input_wire_values: res.input_wire_values,
            ciphertext_handler_result: res.ciphertext_handler_result,
            gate_hasher_seed,
        }
    }
}

/// `Commit₁(i)` payload containing ciphertext hash, per-wire input commits,
/// output commits, and constant wire values (spec Step 1.2).
#[derive(Debug, Serialize, Deserialize, Eq)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub struct CommitPhaseOne<GH: GateHasher, LH: LabelCommitHasher = DefaultLabelCommitHasher> {
    ciphertext_hash: CiphertextCommit,
    input_commitments: Vec<LabelCommit<LH::Output>>,
    /// Commitment to the active output label when the circuit output is `true`.
    output_commit_true: LH::Output,
    /// Commitment to the active output label when the circuit output is `false`.
    output_commit_false: LH::Output,
    true_constant: u128,
    false_constant: u128,
    /// The gate hasher seed (needed for regarbling/evaluation).
    gate_hasher_seed: GH::Seed,
}

impl<GH: GateHasher, LH: LabelCommitHasher> Clone for CommitPhaseOne<GH, LH> {
    fn clone(&self) -> Self {
        Self {
            ciphertext_hash: self.ciphertext_hash,
            input_commitments: self.input_commitments.clone(),
            output_commit_false: self.output_commit_false,
            output_commit_true: self.output_commit_true,
            true_constant: self.true_constant,
            false_constant: self.false_constant,
            gate_hasher_seed: self.gate_hasher_seed.clone(),
        }
    }
}

impl<GH: GateHasher, LH: LabelCommitHasher> PartialEq for CommitPhaseOne<GH, LH>
where
    GH::Seed: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.ciphertext_hash == other.ciphertext_hash
            && self.input_commitments == other.input_commitments
            && self.output_commit_true == other.output_commit_true
            && self.output_commit_false == other.output_commit_false
            && self.true_constant == other.true_constant
            && self.false_constant == other.false_constant
            && self.gate_hasher_seed == other.gate_hasher_seed
    }
}

impl<GH: GateHasher, LH: LabelCommitHasher> CommitPhaseOne<GH, LH> {
    /// Create a new `CommitPhaseOne` directly from its components.
    pub fn new(
        ciphertext_hash: CiphertextCommit,
        input_commitments: Vec<LabelCommit<LH::Output>>,
        output_commit_true: LH::Output,
        output_commit_false: LH::Output,
        true_constant: u128,
        false_constant: u128,
        gate_hasher_seed: GH::Seed,
    ) -> Self {
        Self {
            ciphertext_hash,
            input_commitments,
            output_commit_true,
            output_commit_false,
            true_constant,
            false_constant,
            gate_hasher_seed,
        }
    }

    /// Recompute the `Commit₁` payload (without nonce injection) for a garbled instance.
    pub fn from_instance(instance: &GarbledInstance<GH>) -> Self {
        Self {
            ciphertext_hash: instance.ciphertext_handler_result,
            input_commitments: commit_input_wires::<LH>(&instance.input_wire_values, None),
            output_commit_true: commit_output_true::<LH>(&instance.output_wire_values),
            output_commit_false: commit_output_false::<LH>(&instance.output_wire_values),
            true_constant: instance.true_wire_constant.select(true).to_u128(),
            false_constant: instance.false_wire_constant.select(false).to_u128(),
            gate_hasher_seed: instance.gate_hasher_seed.clone(),
        }
    }

    pub fn ciphertext_hash(&self) -> CiphertextCommit {
        self.ciphertext_hash
    }

    pub fn input_commitments(&self) -> &[LabelCommit<LH::Output>] {
        &self.input_commitments
    }

    pub fn output_commit_true(&self) -> LH::Output {
        self.output_commit_true
    }

    pub fn output_commit_false(&self) -> LH::Output {
        self.output_commit_false
    }

    pub fn true_constant(&self) -> u128 {
        self.true_constant
    }

    pub fn false_constant(&self) -> u128 {
        self.false_constant
    }

    pub fn gate_hasher_seed(&self) -> &GH::Seed {
        &self.gate_hasher_seed
    }
}

/// `Commit₂(i)` payload containing nonce-blended per-wire input commitments
/// (spec Step 1.4).
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound = "H: LabelCommitHasher")]
pub struct CommitPhaseTwo<H: LabelCommitHasher = DefaultLabelCommitHasher> {
    input_commitments: Vec<LabelCommit<H::Output>>,
}

impl<H: LabelCommitHasher> Clone for CommitPhaseTwo<H> {
    fn clone(&self) -> Self {
        Self {
            input_commitments: self.input_commitments.clone(),
        }
    }
}

impl<H: LabelCommitHasher> CommitPhaseTwo<H> {
    /// Create a new `CommitPhaseTwo` directly from input commitments.
    pub fn new(input_commitments: Vec<LabelCommit<H::Output>>) -> Self {
        Self { input_commitments }
    }

    /// Recompute the `Commit₂` payload (with nonce injection) for a garbled instance.
    pub fn from_instance<GH: GateHasher>(instance: &GarbledInstance<GH>, nonce: S) -> Self {
        Self {
            input_commitments: commit_input_wires::<H>(&instance.input_wire_values, Some(nonce)),
        }
    }

    pub fn input_commitments(&self) -> &[LabelCommit<H::Output>] {
        &self.input_commitments
    }

    pub fn into_inner(self) -> Vec<LabelCommit<H::Output>> {
        self.input_commitments
    }
}

/// Result of opening a single instance.
pub enum OpenForInstance {
    /// Instance was opened - returns (index, seed)
    Open(usize, crate::cut_and_choose::Seed),
    /// Instance was kept closed/finalized
    Closed {
        index: usize,
        garbling_thread: JoinHandle<()>,
    },
}

/// Result of cut-and-choose challenge, partitioning instances into
/// those revealed for verification and those finalized for evaluation.
#[derive(Debug)]
pub struct ChosenInstances {
    /// Instances revealed for evaluator to verify by re-garbling
    pub revealed: Vec<(usize, crate::cut_and_choose::Seed)>,
    /// Instances finalized for actual circuit evaluation
    pub finalized: Vec<(usize, crate::cut_and_choose::Seed)>,
}

/// Garbler state machine stages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GarblerStage {
    Generating {
        seeds: Box<[crate::cut_and_choose::Seed]>,
    },
    PreparedForEval {
        finalized_indexes: Box<[usize]>,
    },
}

impl GarblerStage {
    pub(crate) fn next_stage(
        &mut self,
        finalized_indexes: Box<[usize]>,
    ) -> Box<[crate::cut_and_choose::Seed]> {
        assert!(matches!(self, Self::Generating { .. }));

        let mut n = GarblerStage::PreparedForEval { finalized_indexes };
        std::mem::swap(self, &mut n);

        match n {
            Self::Generating { seeds } => seeds,
            _ => unreachable!(),
        }
    }
}

// Helper functions for label commitments

pub(crate) fn commit_output_true<H: LabelCommitHasher>(wire: &GarbledWire) -> H::Output {
    commit_label_with::<H>(wire.label1)
}

pub(crate) fn commit_output_false<H: LabelCommitHasher>(wire: &GarbledWire) -> H::Output {
    commit_label_with::<H>(wire.label0)
}

pub(crate) fn commit_input_wires<H: LabelCommitHasher>(
    inputs: &[GarbledWire],
    nonce: Option<S>,
) -> Vec<LabelCommit<H::Output>> {
    inputs
        .iter()
        .map(|GarbledWire { label0, label1 }| {
            // label0 = false label, label1 = true label (from GarbledWire)
            LabelCommit::<H::Output>::new::<H>(*label0, *label1, &nonce)
        })
        .collect()
}

// Test utilities
#[cfg(feature = "test-utils")]
mod test_utils {
    use super::*;

    #[derive(Clone, Debug)]
    pub struct CommitPhaseOneRawParts<H: Clone + Copy> {
        pub ciphertext_hash: CiphertextCommit,
        pub input_commitments: Vec<LabelCommit<H>>,
        pub output_commit_true: H,
        pub output_commit_false: H,
        pub true_constant: u128,
        pub false_constant: u128,
    }

    impl<GH: GateHasher, LH: LabelCommitHasher> CommitPhaseOne<GH, LH> {
        /// Construct a commit payload directly from raw components for testing helpers.
        pub fn from_raw_parts(
            parts: CommitPhaseOneRawParts<LH::Output>,
            gate_hasher_seed: GH::Seed,
        ) -> Self {
            Self {
                ciphertext_hash: parts.ciphertext_hash,
                input_commitments: parts.input_commitments,
                output_commit_true: parts.output_commit_true,
                output_commit_false: parts.output_commit_false,
                true_constant: parts.true_constant,
                false_constant: parts.false_constant,
                gate_hasher_seed,
            }
        }

        pub fn into_raw_parts(self) -> (CommitPhaseOneRawParts<LH::Output>, GH::Seed) {
            (
                CommitPhaseOneRawParts {
                    ciphertext_hash: self.ciphertext_hash,
                    input_commitments: self.input_commitments,
                    output_commit_true: self.output_commit_true,
                    output_commit_false: self.output_commit_false,
                    true_constant: self.true_constant,
                    false_constant: self.false_constant,
                },
                self.gate_hasher_seed,
            )
        }
    }

    impl<H: LabelCommitHasher> CommitPhaseTwo<H> {
        pub fn from_raw_parts(input_commitments: Vec<LabelCommit<H::Output>>) -> Self {
            Self { input_commitments }
        }

        pub fn into_raw_parts(self) -> Vec<LabelCommit<H::Output>> {
            self.input_commitments
        }
    }
}

#[cfg(feature = "test-utils")]
#[allow(unused_imports)]
pub use test_utils::*;
