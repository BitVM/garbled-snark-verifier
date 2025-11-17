use bincode::{Decode, Encode};

pub type Wire = (u128, u128);
pub type InstancesWires = Vec<Wire>;
pub type Sha256Commit = [u8; 32];

#[derive(Encode, Decode, Debug, PartialEq)]
pub struct WiresInput {
    pub instances_wires: Vec<InstancesWires>,
    pub nonce: u128,
}

#[derive(Encode, Decode, Debug, PartialEq)]
pub struct SolderedLabelsData {
    pub deltas: Vec<Vec<(u128, u128)>>,
    pub base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    pub base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    pub nonce: u128,
    pub commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
}
