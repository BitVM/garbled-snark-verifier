//! Soldering extensions for the cut-and-choose garbler.
//!
//! Instead of wrapping the vanilla garbler, we extend it via a trait to keep
//! the API surface small while still adding soldering-specific helpers.

use serde::{Deserialize, Serialize};

use crate::{
    Blake3AccumulatingHash, GarbleMode,
    circuit::EncodeInput,
    cut_and_choose::{
        LabelCommit, LabelCommitHasher,
        vanilla::{
            Garbler as VanillaGarbler, GarblerStage,
            types::{commit_input_wires, commit_output_false, commit_output_true},
        },
    },
    hashers::GateHasher,
    sp1_soldering::SolderingProof,
};

/// Soldering-specific helpers that build on top of the vanilla garbler.
pub trait SolderingGarblerExt {
    /// Produces a soldering proof that binds instance inputs together.
    ///
    /// Requires `PreparedForEval` stage (after `open_commit`) and a set nonce
    /// from `commit_phase_two`.
    fn do_soldering(&self) -> SolderingProof;

    /// Input wire label commitments for the base instance (first finalized index).
    fn soldered_base_commitment<H: LabelCommitHasher>(&self)
    -> Option<Vec<LabelCommit<H::Output>>>;

    /// Output label commitments (false, true) for all finalized instances.
    fn finalized_output_label_commitment<H: LabelCommitHasher>(
        &self,
    ) -> Option<Vec<(H::Output, H::Output)>>;
}

impl<I, GH> SolderingGarblerExt for VanillaGarbler<I, GH>
where
    I: crate::circuit::CircuitInput
        + Clone
        + Send
        + Sync
        + EncodeInput<GarbleMode<GH, Blake3AccumulatingHash>>
        + Serialize
        + for<'de> Deserialize<'de>
        + 'static,
    <I as crate::circuit::CircuitInput>::WireRepr: Send,
    GH: GateHasher + 'static,
{
    fn do_soldering(&self) -> SolderingProof {
        let nonce = self
            .nonce()
            .expect("Nonce must be set before calling do_soldering");

        let GarblerStage::PreparedForEval { finalized_indexes } = self.stage() else {
            panic!("Garbler not ready for soldering")
        };

        let mut finalized_indexes = finalized_indexes.clone();
        finalized_indexes.sort();

        let inputs: Vec<_> = finalized_indexes
            .iter()
            .map(|idx| self.input_labels_for(*idx))
            .collect();

        crate::sp1_soldering::prove_soldering(inputs, nonce.to_u128())
    }

    fn soldered_base_commitment<H: LabelCommitHasher>(
        &self,
    ) -> Option<Vec<LabelCommit<H::Output>>> {
        let GarblerStage::PreparedForEval { finalized_indexes } = self.stage() else {
            return None;
        };

        let base_idx = *finalized_indexes.iter().min()?;
        let base_inputs = self.input_labels_for(base_idx);

        Some(commit_input_wires::<H>(&base_inputs, self.nonce()))
    }

    fn finalized_output_label_commitment<H: LabelCommitHasher>(
        &self,
    ) -> Option<Vec<(H::Output, H::Output)>> {
        let GarblerStage::PreparedForEval { finalized_indexes } = self.stage() else {
            return None;
        };

        let mut sorted_indexes = finalized_indexes.to_vec();
        sorted_indexes.sort();

        Some(
            sorted_indexes
                .iter()
                .filter_map(|&idx| {
                    self.output_wire(idx).map(|wire| {
                        (
                            commit_output_false::<H>(wire),
                            commit_output_true::<H>(wire),
                        )
                    })
                })
                .collect(),
        )
    }
}
