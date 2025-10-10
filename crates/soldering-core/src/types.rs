use rkyv::{Archive, Deserialize, Serialize};

pub type Wire = (u128, u128);
pub type InstancesWires = Vec<Wire>;
pub type Sha256Commit = [u8; 32];

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[rkyv(derive(Debug))]
pub struct WiresInput {
    pub instances_wires: Vec<InstancesWires>,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
pub struct SolderedLabelsData {
    pub deltas: Vec<Vec<(u128, u128)>>,
    pub base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    pub commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
}
