use std::thread::JoinHandle;

use ark_ff::UniformRand;
use ark_secp256k1::{Fr, Projective};
use crossbeam::channel;
use itertools::Itertools;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::{
    adaptor::{SignatureBytes, WideAdaptorInfo},
    core::{PolynomialCommits, ShareCommits, lagrange_interpolate_whole_polynomial},
    garbler::InstanceWideLabelLookup,
    types::{Canonical, transpose},
    wide_garbling::GarbledWideLabelTable,
};
use crate::{
    EvaluatedWire, S, WireId,
    circuit::{CiphertextHandler, CircuitMode, EncodeInput, EvaluateMode, ciphertext_source},
    cut_and_choose::{CommitPhaseOne, LabelCommitHasher, Seed},
    hashers::{DefaultLabelCommitHasher, GateHasher},
};

/// Messages emitted by the Garbler during Setup (spec Steps 1–4).
pub enum SetupBroadcast<GH: GateHasher, LH: LabelCommitHasher> {
    Commit(VsssCommit<GH, LH>),
    OpenInstances(Vec<OpenVsssInstance>, Vec<(usize, InstanceWideLabelLookup)>),
    Assert(Vec<SignatureBytes>),
}

/// Messages emitted by the Evaluator during Setup.
pub enum SetupResponse<CTH: 'static + Send + CiphertextHandler> {
    /// Step 2 — finalization challenge specifying the evaluation set plus ciphertext handlers.
    FinalizeChallenge(Challenge<CTH>),
}

pub struct Challenge<CTH: 'static + Send + CiphertextHandler> {
    pub finalized: Vec<FinalizeChallenge<CTH>>,
    pub adaptor_sigs: Vec<WideAdaptorInfo>,
    pub assert_index: usize,
}

impl<CTH: 'static + Send + CiphertextHandler> Challenge<CTH> {
    pub fn compute_signatures<GH, T>(
        &self,
        wide_labels: &[Fr],
        val: &T,
        seed: GH::Seed,
    ) -> Vec<SignatureBytes>
    where
        GH: GateHasher,
        T: EncodeInput<EvaluateMode<GH, ciphertext_source::DummySource>>,
    {
        let wire_values = encode_input::<GH, T>(val, seed);

        wide_labels
            .chunks(256)
            .zip(wire_values.chunks(8))
            .map(|(wide_labels, bit_vals)| {
                let wide_label_idx = bit_vals.iter().fold(0, |acc, &val| acc * 2 + val as u8);
                wide_labels[wide_label_idx as usize]
            })
            .zip_eq(self.adaptor_sigs.iter())
            .map(|(wide_label, adaptor_sig)| adaptor_sig.garbler_signature(&wide_label))
            .collect::<Result<Vec<_>, _>>()
            .expect("adaptor sigs should be valid")
    }
}

#[derive(Clone)]
pub struct FinalizeChallenge<CTH: 'static + Send + CiphertextHandler> {
    pub index: usize,
    pub ciphertext_handler: CTH,
}

pub struct VsssStreamReceivers {
    pub index: usize,
    pub ciphertext_receiver: channel::Receiver<S>,
}

impl crate::cut_and_choose::CiphertextSourceProvider for Vec<VsssStreamReceivers> {
    type Source = channel::Receiver<S>;
    type Error = ();

    fn source_for(&self, index: usize) -> Result<Self::Source, Self::Error> {
        self.iter()
            .find_map(|x| x.index.eq(&index).then_some(x.ciphertext_receiver.clone()))
            .ok_or(())
    }
}

// A hacky way to get the binary representation of an input
pub fn encode_input<GH, T>(val: &T, seed: GH::Seed) -> Vec<bool>
where
    GH: GateHasher,
    T: EncodeInput<EvaluateMode<GH, ciphertext_source::DummySource>>,
{
    let gate_hasher = GH::from_seed(seed);
    let mut dummy_evaluate_mode = EvaluateMode::<GH, ciphertext_source::DummySource>::new(
        gate_hasher,
        0,
        S::ZERO,
        S::ZERO,
        ciphertext_source::DummySource,
    );

    let mut x = WireId::MIN.0;
    let allocated = val.allocate(|| {
        dummy_evaluate_mode.allocate_wire(1);

        let ret = WireId(x);
        x += 1;
        ret
    });
    val.encode(&allocated, &mut dummy_evaluate_mode);
    // (WireId::MIN.0..x).for_each(|_| dummy_evaluate_mode.allocate_wire(1));
    (WireId::MIN.0..x)
        .map(|i| {
            dummy_evaluate_mode
                .lookup_wire(WireId(i))
                .expect("wire should have value")
                .value
        })
        .collect_vec()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "GH: GateHasher, LH: LabelCommitHasher")]
pub struct VsssCommit<GH: GateHasher, LH: LabelCommitHasher = DefaultLabelCommitHasher> {
    pub circuit_commits: Vec<CommitPhaseOne<GH, LH>>,
    pub share_commits: Vec<ShareCommits<Canonical<Projective>>>,
    pub polynomial_commits: Vec<PolynomialCommits<Canonical<Projective>>>,
    pub garbling_table_commits: Vec<[u8; 32]>,
}

pub struct OpenVsssInstance {
    pub index: usize,
    pub seed: Seed,
    pub shares: Vec<Canonical<Fr>>,
}

pub struct FinalizedVsssInstance {
    pub index: usize,
    pub wide_label_lookup: Vec<GarbledWideLabelTable>,
    pub garbling_thread: JoinHandle<()>,
}

pub struct EvaluatorAdaptorSigs {
    pub assert_index: usize,
    pub secret: Fr,
    pub adaptor_sigs: Vec<WideAdaptorInfo>,
}

impl EvaluatorAdaptorSigs {
    pub fn new(
        rng: &mut impl Rng,
        finalized_indices: &[usize],
        garbler_commits: &[ShareCommits<Canonical<Projective>>],
        sighashes: &[Vec<u8>],
    ) -> Self {
        // choose an index that is to be used for the assert
        let assert_index = finalized_indices[rng.gen_range(0..finalized_indices.len())];

        let secret = Fr::rand(rng);
        let adaptor_sigs = garbler_commits
            .chunks(256)
            .zip_eq(sighashes)
            .map(|(chunk, sighash)| {
                let commits = chunk
                    .iter()
                    .map(|commits| commits.0[assert_index].0)
                    .collect_vec();
                WideAdaptorInfo::new(&secret, &commits, sighash, rng)
            })
            .collect();

        Self {
            assert_index,
            secret,
            adaptor_sigs,
        }
    }

    fn extract_wide_labels(&self, signatures: &[SignatureBytes]) -> Vec<Fr> {
        self.adaptor_sigs
            .iter()
            .zip_eq(signatures)
            .map(|(adaptor_sig, signature)| {
                adaptor_sig
                    .extract_secret(signature)
                    .expect("adaptor sigs should be valid")
            })
            .collect_vec()
    }

    pub fn evaluated_wires(
        &self,
        signatures: &[SignatureBytes],
        wide_label_lookups: &[(usize, InstanceWideLabelLookup)],
        open_instance_data: &[OpenVsssInstance],
        total_instance_count: usize,
    ) -> Vec<(usize, Vec<EvaluatedWire>)> {
        let wide_labels = self.extract_wide_labels(signatures);

        let value_indices = {
            let wide_label_lookup = &wide_label_lookups
                .iter()
                .find(|x| x.0 == self.assert_index)
                .unwrap()
                .1;
            wide_labels
                .iter()
                .zip(wide_label_lookup.iter())
                .map(|(wide_label, wide_label_lookup)| wide_label_lookup.lookup_index(wide_label))
                .collect_vec()
        };

        let known_labels = open_instance_data
            .iter()
            .map(|x| {
                (
                    x.index, // instance index
                    x.shares
                        .chunks(256)
                        .zip(value_indices.iter())
                        .map(|(share, index)| share[*index].0) // out of the 256 possible values, use the selected one
                        .collect_vec(),
                )
            })
            .chain(std::iter::once((self.assert_index, wide_labels.clone())))
            .collect_vec();

        let missing_indices = (0..total_instance_count)
            .filter(|&i| !known_labels.iter().any(|(j, _)| j == &i))
            .collect_vec();

        let num_labels = known_labels[0].1.len();
        let mut interpolated_labels = vec![];

        for i in 0..num_labels {
            let known = known_labels
                .iter()
                .map(|(j, shares)| (*j, shares[i]))
                .collect_vec();
            let missing = lagrange_interpolate_whole_polynomial(&known, &missing_indices);
            interpolated_labels.push(missing);
        }

        let interpolated_labels = transpose(&interpolated_labels);

        missing_indices
            .into_iter()
            .zip(interpolated_labels)
            .chain(std::iter::once((self.assert_index, wide_labels.clone())))
            .map(|(index, labels)| {
                let wide_label_lookup =
                    &wide_label_lookups.iter().find(|x| x.0 == index).unwrap().1;

                let wires = labels
                    .iter()
                    .zip(wide_label_lookup.iter())
                    .flat_map(|(wide_label, wide_label_lookup)| {
                        wide_label_lookup.lookup_evaluated_wires(wide_label)
                    })
                    .collect_vec();
                (index, wires)
            })
            .collect_vec()
    }
}
