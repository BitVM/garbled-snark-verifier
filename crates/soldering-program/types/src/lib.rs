use serde::*;
use serde_big_array::BigArray;

pub const INPUT_WIRE_COUNT: usize = 1093;
pub const INSTANCE_COUNT: usize = 7;

pub type Label = [u8; 16];
pub type Commit = [u8; 32];
pub type ShaDigest = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Wire {
    pub label0: Label,
    pub label1: Label,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InstanceWires {
    #[serde(with = "BigArray")]
    pub labels: [Wire; INPUT_WIRE_COUNT],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivateParams {
    pub labels: [InstanceWires; INSTANCE_COUNT],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Input {
    pub public_param: PublicParams,
    pub private_param: PrivateParams,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicParams {
    pub selection: [bool; INSTANCE_COUNT],
    pub commitments: [Commit; INSTANCE_COUNT],
    #[serde(with = "BigArray")]
    pub sha0: [ShaDigest; INPUT_WIRE_COUNT],
    #[serde(with = "BigArray")]
    pub sha1: [ShaDigest; INPUT_WIRE_COUNT],
    #[serde(with = "BigArray")]
    pub deltas0: [WireLabels; INSTANCE_COUNT],
    #[serde(with = "BigArray")]
    pub deltas1: [WireLabels; INSTANCE_COUNT],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireLabels(
    #[serde(with = "BigArray")] pub [Label; INPUT_WIRE_COUNT]
);

