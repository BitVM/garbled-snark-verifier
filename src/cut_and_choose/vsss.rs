use std::thread::JoinHandle;

use ark_secp256k1::{Fr, Projective};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crossbeam::channel;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    AesNiHasher, CommitPhaseOne, LabelCommitHasher, S, WireId,
    cac::vsss::{PolynomialCommits, ShareCommits},
    circuit::{CiphertextHandler, CircuitMode, EncodeInput, EvaluateMode, ciphertext_source},
    cut_and_choose::{GarbledWideLabelTable, InstanceWideLabelLookup, Seed},
    hashers::DefaultLabelCommitHasher,
};

/// Messages emitted by the Garbler during Setup (spec Steps 1–4).
pub enum SetupBroadcast<HHasher: LabelCommitHasher> {
    Commit(VsssCommit<HHasher>),
    OpenInstances(Vec<OpenVsssInstance>, Vec<(usize, InstanceWideLabelLookup)>),
    Assert(usize, Vec<Canonical<Fr>>),
}

/// Messages emitted by the Evaluator during Setup.
pub enum SetupResponse<CTH: 'static + Send + CiphertextHandler> {
    /// Step 2 — finalization challenge specifying the evaluation set plus ciphertext handlers.
    FinalizeChallenge(Vec<FinalizeChallenge<CTH>>),
}

pub struct FinalizeChallenge<CTH: 'static + Send + CiphertextHandler> {
    pub index: usize,
    pub ciphertext_handler: CTH,
}

pub struct VsssStreamReceivers {
    pub index: usize,
    pub ciphertext_receiver: channel::Receiver<S>,
}

// A hacky way to get the binary representation of an input
pub fn encode_input<T>(val: &T) -> Vec<bool>
where
    T: EncodeInput<EvaluateMode<AesNiHasher, ciphertext_source::DummySource>>,
{
    // EvaluateMode<AesNiHasher, SRC>{}
    let mut dummy_evaluate_mode = EvaluateMode::<AesNiHasher, ciphertext_source::DummySource>::new(
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

pub fn transpose<T: Clone>(m: &[Vec<T>]) -> Vec<Vec<T>> {
    (0..m[0].len())
        .map(|i| m.iter().map(|row| row[i].clone()).collect())
        .collect()
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct Canonical<T: CanonicalDeserialize + CanonicalSerialize>(pub T);

impl<T: CanonicalSerialize + CanonicalDeserialize> Serialize for Canonical<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de, T: CanonicalSerialize + CanonicalDeserialize> Deserialize<'de> for Canonical<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;

        Ok(Canonical(
            T::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)?,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound = "H: LabelCommitHasher")]
pub struct VsssCommit<H: LabelCommitHasher = DefaultLabelCommitHasher> {
    pub circuit_commits: Vec<CommitPhaseOne<H>>,
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
