use serde::{ser::SerializeSeq, *};

// Serde helpers for Box<[T; N]> arrays of any size.
pub(crate) mod boxed_array {
    use super::*;

    pub fn serialize<S, T, const N: usize>(arr: &[T; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        let mut seq = serializer.serialize_seq(Some(N))?;
        for item in arr.iter() {
            seq.serialize_element(item)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D, T, const N: usize>(deserializer: D) -> Result<Box<[T; N]>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        let v: Vec<T> = Vec::deserialize(deserializer)?;
        if v.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected array of length {}, got {}",
                N,
                v.len()
            )));
        }
        // SAFETY: length is checked to be exactly N above.
        let boxed_slice: Box<[T]> = v.into_boxed_slice();
        let boxed_array = boxed_slice.try_into().map_err(|boxed: Box<[T]>| {
            serde::de::Error::custom(format!(
                "failed to convert boxed slice of length {} to boxed array of length {}",
                boxed.len(),
                N
            ))
        })?;
        Ok(boxed_array)
    }
}

pub const INPUT_WIRE_COUNT: usize = 1093;
pub const SOLDERED_INSTANCE: usize = 6;

pub type Label = u128;
pub type Commit = [u8; 32];
pub type ShaDigest = [u8; 32];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Wire {
    pub label0: Label,
    pub label1: Label,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InstanceWires<const INPUT_WIRE_COUNT: usize> {
    #[serde(with = "boxed_array")]
    pub labels: Box<[Wire; INPUT_WIRE_COUNT]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PrivateParams<const INPUT_WIRE_COUNT: usize, const SOLDERED_INSTANCE: usize> {
    pub core_instance: InstanceWires<INPUT_WIRE_COUNT>,
    #[serde(with = "boxed_array")]
    pub additional_instances: Box<[InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PublicParams<const INPUT_WIRE_COUNT: usize, const SOLDERED_INSTANCE: usize> {
    #[serde(with = "boxed_array")]
    pub core_commitment: Box<[[ShaDigest; 2]; INPUT_WIRE_COUNT]>,
    #[serde(with = "boxed_array")]
    pub commitments: Box<[Commit; SOLDERED_INSTANCE]>,
    #[serde(with = "boxed_array")]
    pub deltas0: Box<[WireLabels<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE]>,
    #[serde(with = "boxed_array")]
    pub deltas1: Box<[WireLabels<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE]>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Input<const INPUT_WIRE_COUNT: usize, const SOLDERED_INSTANCE: usize> {
    pub public_param: PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
    pub private_param: PrivateParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct WireLabels<const INPUT_WIRE_COUNT: usize>(
    #[serde(with = "boxed_array")] pub Box<[Label; INPUT_WIRE_COUNT]>,
);

pub type DefaultInstanceWires = InstanceWires<INPUT_WIRE_COUNT>;
pub type DefaultPrivateParams = PrivateParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>;
pub type DefaultPublicParams = PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>;
pub type DefaultInput = Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>;
